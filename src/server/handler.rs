use base64::Engine;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::CONTENT_LENGTH;
use hyper::{Method, Request, Response, StatusCode};
use rusqlite::params;
use std::fmt::Write;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::{AccessType, Config, SMALL_SIZE};
use crate::error::{Error, ResponseFuture, Result};
use crate::state::State;

/// Print an error to the terminal and return a future describing the error
fn handle_error<E: std::fmt::Debug>(
    file: &str,
    line: u32,
    code: StatusCode,
    message: &'static str,
    e: E,
) -> ResponseFuture {
    //if code != StatusCode::NOT_FOUND {
    error!("{}:{}: {} {} error {:?}", file, line, message, code, e);
    //}
    Ok(Response::builder()
        .status(code)
        .body(Full::from(message))
        .unwrap())
}

/// Print an error to the terminal and return a body describing the error
macro_rules! handle_error {
    ($code:expr, $message:expr, $e:expr) => {
        handle_error(file!(), line!(), $code, $message, $e)
    };
}

macro_rules! tryfut {
    ($r:expr, $code:expr, $err:expr $(,)?) => {
        match $r {
            Ok(v) => v,
            Err(e) => return handle_error!($code, $err, e),
        }
    };
}

/// Construct a http ok response
fn ok_message(message: Option<String>) -> ResponseFuture {
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(match message {
            Some(message) => Full::from(message),
            None => Full::from(""),
        })
        .unwrap())
}

/// Construct an unauthorize http response
fn unauthorized_message() -> ResponseFuture {
    Ok(Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(
            "WWW-Authenticate",
            "Basic realm=\"mbackup\", charset=\"UTF-8\"",
        )
        .body(Full::from(""))
        .unwrap())
}

/// Check if the user has an access lever greater than or equal to level
/// If he does None is returned
/// Otherwise Some(unauthorized_message()) is returned
fn check_auth<'a>(
    req: &Request<Incoming>,
    state: &'a State,
    level: AccessType,
) -> std::result::Result<&'a crate::config::User, ResponseFuture> {
    let auth = match req.headers().get("Authorization") {
        Some(data) => data,
        None => return Err(unauthorized_message()),
    };

    let auth = match auth.to_str() {
        Ok(data) => data,
        Err(_) => return Err(unauthorized_message()),
    };

    for user in state.config.users.iter() {
        if format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", user.name, user.password))
        ) != auth
        {
            continue;
        }
        if level != AccessType::Get && user.max_root_age.is_some() {
            // Do not allow users with max age to do none get requests
            return Err(unauthorized_message());
        }
        if user.access_level >= level {
            return Ok(user);
        }
    }

    Err(unauthorized_message())
}

/// Validate that a string is a valid hex encoding of a 256bit hash
fn check_hash(name: &str) -> Result<()> {
    if name.len() != 64 {
        return Err(Error::Server("wrong hash length"));
    }
    for c in name.chars() {
        if c.is_ascii_digit() {
            continue;
        }
        if ('a'..='f').contains(&c) {
            continue;
        }
        return Err(Error::Server("hash character not lowercase hex"));
    }
    Ok(())
}

fn chunk_path(data_dir: &str, bucket: &str, chunk: &str) -> String {
    format!(
        "{}/data/{}/{}/{}",
        data_dir,
        &bucket,
        &chunk[..2],
        &chunk[2..]
    )
}

/// Put a chunk into the chunk archive
async fn handle_put_chunk(
    bucket: String,
    chunk: String,
    req: Request<Incoming>,
    state: Arc<State>,
) -> ResponseFuture {
    if let Err(res) = check_auth(&req, &state, AccessType::Put) {
        warn!("Unauthorized access for put chunk {}/{}", bucket, chunk);
        return res;
    }

    tryfut!(
        check_hash(bucket.as_ref()),
        StatusCode::BAD_REQUEST,
        "Bad bucket"
    );
    tryfut!(
        check_hash(chunk.as_ref()),
        StatusCode::BAD_REQUEST,
        "Bad chunk"
    );

    // Check if the chunk is already there.
    if tryfut!(
        do_check_chunk_exists(&mut state.conn.lock().unwrap(), &bucket, &chunk),
        StatusCode::INTERNAL_SERVER_ERROR,
        "do_check_chunk_exists failed"
    ) {
        state.stat.put_chunk_already_there.inc();
        return handle_error!(StatusCode::CONFLICT, "Already there", "");
    }

    let mut v = Vec::new();
    let mut body = req.into_body();
    while let Some(chunk) = body.frame().await {
        let chunk = match chunk?.into_data() {
            Ok(v) => v,
            Err(_) => continue,
        };
        v.extend_from_slice(&chunk);
        if v.len() > 1024 * 1024 * 1024 {
            return handle_error!(StatusCode::BAD_REQUEST, "Content too large", "");
        }
    }

    let len = v.len();
    state.stat.put_chunk_bytes.add(len);

    // Small content is stored directly in the DB
    if len < SMALL_SIZE {
        state.stat.put_chunk_small.inc();
        let conn = state.conn.lock().unwrap();
        tryfut!(
            conn.execute(
                "INSERT INTO chunks (bucket, hash, size, time, has_content) VALUES (?, ?, ?, strftime('%s', 'now'), TRUE)",
                params![&bucket, &chunk, v.len() as i64],
            ),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Insert failed",
        );
        let id = conn.last_insert_rowid();
        tryfut!(
            conn.execute(
                "INSERT INTO chunk_content (chunk_id, content) VALUES (?, ?)",
                params![id, &v],
            ),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Insert failed",
        );
    } else {
        state.stat.put_chunk_large.inc();
        // Large content is stored on disk. We first store the data in a temp upload folder
        // and then atomically rename into its right location
        tryfut!(
            std::fs::create_dir_all(format!("{}/data/upload/{}", state.config.data_dir, &bucket)),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Could not create upload folder"
        );
        let temp_path = format!(
            "{}/data/upload/{}/{}_{}",
            state.config.data_dir,
            bucket,
            chunk,
            rand::random::<u64>()
        );
        tryfut!(
            std::fs::write(&temp_path, v),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Write failed"
        );
        tryfut!(
            std::fs::create_dir_all(format!(
                "{}/data/{}/{}",
                state.config.data_dir,
                &bucket,
                &chunk[..2]
            )),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Could not create bucket folder"
        );
        {
            let conn = state.conn.lock().unwrap();
            tryfut!(conn.execute("INSERT INTO chunks (bucket, hash, size, time, has_content) VALUES (?, ?, ?, strftime('%s', 'now'), FALSE)",
                params![&bucket, &chunk, len as i64]),
                StatusCode::INTERNAL_SERVER_ERROR, "Insert failed");
        }
        tryfut!(
            std::fs::rename(
                &temp_path,
                chunk_path(&state.config.data_dir, &bucket, &chunk)
            ),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Move failed"
        );
    }
    info!("{}:{}: put chunk {} success", file!(), line!(), chunk);

    ok_message(None)
}

fn do_check_chunk_exists(
    conn: &mut rusqlite::Connection,
    bucket: &str,
    chunk: &str,
) -> Result<bool> {
    let mut stmt = conn.prepare("SELECT id FROM chunks WHERE bucket=? AND hash=?")?;
    let mut rows = stmt.query(params![bucket, chunk])?;
    Ok(rows.next()?.is_some())
}

/// Get a chunk from the archive
async fn handle_get_chunk(
    bucket: String,
    chunk: String,
    req: Request<Incoming>,
    state: Arc<State>,
    head: bool,
) -> ResponseFuture {
    if let Err(res) = check_auth(
        &req,
        &state,
        if head {
            AccessType::Put
        } else {
            AccessType::Get
        },
    ) {
        warn!("Unauthorized access for get chunk {}/{}", bucket, chunk);
        return res;
    }

    tryfut!(
        check_hash(bucket.as_ref()),
        StatusCode::BAD_REQUEST,
        "Bad bucket"
    );
    tryfut!(
        check_hash(chunk.as_ref()),
        StatusCode::BAD_REQUEST,
        "Bad chunk"
    );

    let (content, size) = match tryfut!(
        do_get_chunk(&mut state.conn.lock().unwrap(), &bucket, &chunk, head),
        StatusCode::INTERNAL_SERVER_ERROR,
        "Database error"
    ) {
        Some(x) => x,
        None => {
            if head {
                state.stat.get_chunk_head_missing.inc();
            } else {
                state.stat.get_chunk_missing.inc();
            }
            return handle_error!(StatusCode::NOT_FOUND, "Not found", chunk);
        }
    };

    if head {
        state.stat.get_chunk_head_found.inc();
        info!("{}:{}: head chunk {} success", file!(), line!(), chunk);
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_LENGTH, size)
            .body(Full::from(""))
            .unwrap());
    }
    let content = match content {
        Some(content) => {
            state.stat.get_chunk_small.inc();
            content
        }
        None => {
            state.stat.get_chunk_large.inc();
            let path = chunk_path(&state.config.data_dir, &bucket, &chunk);
            match std::fs::read(path) {
                //TODO use tokio for async fileread
                Ok(data) => data,
                Err(e) => {
                    return handle_error!(StatusCode::INTERNAL_SERVER_ERROR, "Chunk missing", e)
                }
            }
        }
    };
    state.stat.get_chunk_bytes.add(size as usize);
    info!("{}:{}: get chunk {} success", file!(), line!(), chunk);
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_LENGTH, size)
        .body(Full::from(content))
        .unwrap())
}

fn do_get_chunk(
    conn: &mut rusqlite::Connection,
    bucket: &str,
    chunk: &str,
    head: bool,
) -> Result<Option<(Option<Vec<u8>>, i64)>> {
    let mut stmt =
        conn.prepare("SELECT id, has_content, size FROM chunks WHERE bucket=? AND hash=?")?;

    let mut rows = stmt.query(params![bucket, chunk])?;
    let (_id, content, size) = match rows.next()? {
        Some(row) => {
            let id: i64 = row.get(0)?;
            // TODO(rav): Make has_content NOT NULL in the database
            let has_content: Option<bool> = row.get(1)?;
            let has_content = has_content == Some(true);
            let size: i64 = row.get(2)?;
            if !head && has_content {
                let mut stmt =
                    conn.prepare("SELECT content FROM chunk_content WHERE chunk_id = ?")?;
                let mut rows = stmt.query(params![id])?;
                match rows.next()? {
                    Some(v) => (id, v.get(0)?, size),
                    None => {
                        return Ok(None);
                    }
                }
            } else {
                (id, None, size)
            }
        }
        None => {
            return Ok(None);
        }
    };
    Ok(Some((content, size)))
}

fn do_delete_chunks(
    conn: &mut rusqlite::Connection,
    bucket: String,
    chunks: &[&str],
    config: &Config,
) -> Result<usize> {
    if chunks.is_empty() {
        return Ok(0);
    }

    let mut params: Vec<&str> = vec![&bucket];
    for chunk in chunks {
        params.push(chunk)
    }
    let mut stmt = conn.prepare(&format!(
        "SELECT id, hash, has_content FROM chunks WHERE bucket=? AND hash IN (?{})",
        ", ?".repeat(chunks.len() - 1)
    ))?;

    let mut internal_chunks = Vec::new();
    for row in stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?))
    })? {
        // TODO(rav): Make has_content NOT NULL in the database
        let (id, chunk, has_content): (usize, String, Option<bool>) = row?;
        let has_content = has_content == Some(true);
        if has_content {
            internal_chunks.push(id);
        } else {
            let path = chunk_path(&config.data_dir, &bucket, &chunk);
            match std::fs::remove_file(path) {
                Ok(_) => (),
                Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Err(_) => return Err(Error::Server("Delete failed")),
            }
        }
    }

    if !internal_chunks.is_empty() {
        conn.execute(
            &format!(
                "DELETE FROM chunk_content WHERE chunk_id IN (?{})",
                ", ?".repeat(internal_chunks.len() - 1)
            ),
            rusqlite::params_from_iter(internal_chunks.iter()),
        )?;
    }

    let count = conn.execute(
        &format!(
            "DELETE FROM chunks WHERE bucket=? AND hash IN (?{})",
            ", ?".repeat(chunks.len() - 1)
        ),
        rusqlite::params_from_iter(params.iter()),
    )?;

    conn.execute(
        "REPLACE INTO deletes VALUES (?, strftime('%s', 'now'))",
        params![bucket],
    )?;
    Ok(count)
}

async fn handle_delete_chunk(
    bucket: String,
    chunk: String,
    req: Request<Incoming>,
    state: Arc<State>,
) -> ResponseFuture {
    if let Err(res) = check_auth(&req, &state, AccessType::Delete) {
        warn!("Unauthorized access for delete chunk {}/{}", bucket, chunk);
        return res;
    }
    state.stat.delete_chunk_count.inc();

    tryfut!(
        check_hash(bucket.as_ref()),
        StatusCode::BAD_REQUEST,
        "Bad bucket"
    );
    tryfut!(
        check_hash(chunk.as_ref()),
        StatusCode::BAD_REQUEST,
        "Bad chunk"
    );
    let chu: &str = &chunk;

    let count = tryfut!(
        do_delete_chunks(
            &mut state.conn.lock().unwrap(),
            bucket,
            std::slice::from_ref(&chu),
            &state.config
        ),
        StatusCode::INTERNAL_SERVER_ERROR,
        "do_delete_chunks failed"
    );
    state.stat.chunks_deleted.add(count);
    if count != 1 {
        return handle_error!(StatusCode::NOT_FOUND, "Missing chunk", "");
    }
    ok_message(None)
}

async fn handle_delete_chunks(
    bucket: String,
    req: Request<Incoming>,
    state: Arc<State>,
) -> ResponseFuture {
    if let Err(res) = check_auth(&req, &state, AccessType::Delete) {
        warn!("Unauthorized access for delete chunks {}", bucket);
        return res;
    }
    state.stat.delete_chunks_count.inc();

    tryfut!(
        check_hash(bucket.as_ref()),
        StatusCode::BAD_REQUEST,
        "Bad bucket"
    );

    let mut v = Vec::new();
    let mut body = req.into_body();

    while let Some(frame) = body.frame().await {
        let chunk = match frame?.into_data() {
            Ok(v) => v,
            Err(_) => continue,
        };
        v.extend_from_slice(&chunk);
        if v.len() >= 1024 * 1024 * 256 {
            return handle_error!(StatusCode::BAD_REQUEST, "Too much data", "");
        }
    }

    let s = tryfut!(String::from_utf8(v), StatusCode::BAD_REQUEST, "Bad chunks");
    let chunks: Vec<&str> = s.split('\0').collect();
    for chunk in chunks.iter() {
        tryfut!(check_hash(chunk), StatusCode::BAD_REQUEST, "Bad bucket");
    }
    let count = tryfut!(
        do_delete_chunks(
            &mut state.conn.lock().unwrap(),
            bucket,
            &chunks,
            &state.config
        ),
        StatusCode::INTERNAL_SERVER_ERROR,
        "do_delete_chunks failed"
    );
    state.stat.chunks_deleted.add(count);
    if count != chunks.len() {
        return handle_error!(StatusCode::NOT_FOUND, "Missing chunk", "");
    }
    ok_message(None)
}

async fn handle_list_chunks(
    bucket: String,
    req: Request<Incoming>,
    state: Arc<State>,
) -> ResponseFuture {
    let validate = req.uri().query().map_or(false, |q| q.contains("validate"));

    match check_auth(
        &req,
        &state,
        if validate {
            AccessType::Get
        } else {
            AccessType::Put
        },
    ) {
        Err(res) => {
            warn!("Unauthorized access for list chunks {}", bucket);
            return res;
        }
        Ok(u) if u.access_level == AccessType::Get && u.max_root_age.is_some() => {
            warn!("Get user cannot access chunk list if max age is specified");
            return unauthorized_message();
        }
        Ok(_) => (),
    }

    tryfut!(
        check_hash(bucket.as_ref()),
        StatusCode::BAD_REQUEST,
        "Bad bucket"
    );

    state.stat.list_chunks_count.inc();

    let ans = tryfut!(
        do_list_chunks(
            &mut state.conn.lock().unwrap(),
            &state.config,
            &bucket,
            validate
        ),
        StatusCode::INTERNAL_SERVER_ERROR,
        "do_list_chunks failed"
    );
    state.stat.list_chunks_entries.inc();
    ok_message(Some(ans))
}

fn do_list_chunks(
    conn: &mut rusqlite::Connection,
    config: &Config,
    bucket: &str,
    validate: bool,
) -> Result<String> {
    let mut ans = "".to_string();
    // TODO(rav): For some reason, it is taking much longer with a WHERE clause,
    // than it takes to do a full scan and a manual filter.
    // let mut stmt = conn.prepare("SELECT hash, size, has_content FROM chunks WHERE bucket=?")?;
    // let rows = stmt.query_map(params![bucket], |row| {
    //     Ok(Some((row.get(0)?, row.get(1)?, row.get(2)?)))
    // })?;
    let mut stmt = conn.prepare("SELECT hash, size, has_content, bucket FROM chunks")?;
    let rows = stmt.query_map(params![], |row| {
        let b: String = row.get(3)?;
        if b == bucket {
            Ok(Some((row.get(0)?, row.get(1)?, row.get(2)?)))
        } else {
            Ok(None)
        }
    })?;

    for row in rows {
        // TODO(rav): Make has_content NOT NULL in the database
        let (chunk, size, has_content): (String, i64, Option<bool>) = match row? {
            Some(row) => row,
            None => continue,
        };
        let has_content = has_content == Some(true);
        if validate {
            let content_size = if has_content {
                // TODO(rav): Join with content table
                size
            } else {
                let path = chunk_path(&config.data_dir, bucket, &chunk);
                match std::fs::metadata(path) {
                    Ok(md) => md.len() as i64,
                    Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => -1,
                    Err(_) => return Err(Error::Server("Unable to access metadata")),
                }
            };
            writeln!(ans, "{chunk} {size} {content_size}").unwrap();
        } else {
            writeln!(ans, "{chunk} {size}").unwrap();
        }
    }
    Ok(ans)
}

async fn handle_get_status(
    bucket: String,
    req: Request<Incoming>,
    state: Arc<State>,
) -> ResponseFuture {
    if let Err(res) = check_auth(&req, &state, AccessType::Put) {
        warn!("Unauthorized access for get status {}", bucket);
        return res;
    }
    tryfut!(
        check_hash(bucket.as_ref()),
        StatusCode::BAD_REQUEST,
        "Bad bucket"
    );

    state.stat.get_status_count.inc();

    let time = tryfut!(
        do_get_status(&mut state.conn.lock().unwrap(), &bucket),
        StatusCode::INTERNAL_SERVER_ERROR,
        "Database error",
    );
    ok_message(Some(format!("{time}")))
}

fn do_get_status(conn: &mut rusqlite::Connection, bucket: &str) -> Result<i64> {
    let mut stmt = conn.prepare("SELECT time FROM deletes WHERE bucket=?")?;
    let mut rows = stmt.query(params![bucket])?;
    match rows.next()? {
        Some(row) => Ok(row.get(0)?),
        None => Ok(0),
    }
}

async fn handle_get_roots(
    bucket: String,
    req: Request<Incoming>,
    state: Arc<State>,
) -> ResponseFuture {
    let earliest_root = match check_auth(&req, &state, AccessType::Get) {
        Err(res) => {
            warn!("Unauthorized access for get roots {}", bucket);
            return res;
        }
        Ok(u) => u.max_root_age.map(|v| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                - v * 60 * 60 * 24
        }),
    };
    tryfut!(
        check_hash(bucket.as_ref()),
        StatusCode::BAD_REQUEST,
        "Bad bucket"
    );

    state.stat.get_roots_count.inc();
    // LIMIT response to only new roots
    ok_message(Some(tryfut!(
        do_get_roots(&mut state.conn.lock().unwrap(), &bucket, earliest_root),
        StatusCode::INTERNAL_SERVER_ERROR,
        "do_get_roots failed"
    )))
}

fn do_get_roots(
    conn: &mut rusqlite::Connection,
    bucket: &str,
    earliest_root: Option<u64>,
) -> Result<String> {
    let mut stmt =
        conn.prepare("SELECT id, host, time, hash FROM roots WHERE bucket=? AND time >=?")?;

    let mut ans = "".to_string();
    for t in stmt.query_map(params![bucket, earliest_root.unwrap_or(0)], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
    })? {
        let t = t?;
        let id: i64 = t.0;
        let host: String = t.1;
        let time: i64 = t.2;
        let hash: String = t.3;
        if !ans.is_empty() {
            ans.push('\0');
            ans.push('\0');
        }
        ans.push_str(&format!("{id}\0{host}\0{time}\0{hash}"));
    }
    Ok(ans)
}

async fn handle_put_root(
    bucket: String,
    host: String,
    req: Request<Incoming>,
    state: Arc<State>,
) -> ResponseFuture {
    if let Err(res) = check_auth(&req, &state, AccessType::Put) {
        warn!("Unauthorized access for put root {}", bucket);
        return res;
    }

    tryfut!(
        check_hash(bucket.as_ref()),
        StatusCode::BAD_REQUEST,
        "Bad bucket"
    );

    if host.contains('\0') {
        return handle_error!(StatusCode::BAD_REQUEST, "Bad host name", "");
    }

    state.stat.put_root_count.inc();

    let mut body = req.into_body();
    let mut v = Vec::new();
    while let Some(chunk) = body.frame().await {
        let chunk = match chunk?.into_data() {
            Ok(v) => v,
            Err(_) => continue,
        };
        v.extend_from_slice(&chunk);
        if v.len() > 1024 * 1024 * 10 {
            return handle_error!(StatusCode::BAD_REQUEST, "Content too long", "");
        }
    }

    let s = tryfut!(String::from_utf8(v), StatusCode::BAD_REQUEST, "Bad bucket");
    tryfut!(
        check_hash(s.as_ref()),
        StatusCode::BAD_REQUEST,
        "Bad bucket"
    );

    {
        let conn = state.conn.lock().unwrap();
        tryfut!(
                conn.execute(
                    "INSERT INTO roots (bucket, host, time, hash) VALUES (?, ?, strftime('%s', 'now'), ?)",
                    params![&bucket, &host, &s],
                ),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Insert failed",
            );
    }
    ok_message(None)
}

async fn handle_delete_root(
    bucket: String,
    root: String,
    req: Request<Incoming>,
    state: Arc<State>,
) -> ResponseFuture {
    if let Err(res) = check_auth(&req, &state, AccessType::Delete) {
        warn!("Unauthorized access for delete root {}", bucket);
        return res;
    }
    tryfut!(
        check_hash(bucket.as_ref()),
        StatusCode::BAD_REQUEST,
        "Bad bucket"
    );

    state.stat.delete_root_count.inc();

    let res = state.conn.lock().unwrap().execute(
        "DELETE FROM roots WHERE bucket=? AND id=?",
        params![bucket, root],
    );
    match res {
        Err(e) => handle_error!(StatusCode::INTERNAL_SERVER_ERROR, "Query failed", e),
        Ok(0) => handle_error!(StatusCode::NOT_FOUND, "Not found", ""),
        Ok(_) => ok_message(None),
    }
}

async fn handle_get_metrics(req: Request<Incoming>, state: Arc<State>) -> ResponseFuture {
    if let Some(token) = &state.config.metrics_token {
        if req.uri().query() != Some(token.as_str()) {
            return handle_error!(StatusCode::FORBIDDEN, "Forbidden", "Missing metrics token");
        }
    }

    let mut ans = String::new();
    let s = &state.stat;
    for (counter, name) in [
        (&s.put_chunk_already_there, "put_chunk_already_there_total"),
        (&s.put_chunk_small, "put_chunk_small_total"),
        (&s.put_chunk_large, "put_chunk_large_total"),
        (&s.put_chunk_bytes, "put_chunk_bytes_bytes"),
        (&s.get_chunk_head_missing, "get_chunk_head_missing_total"),
        (&s.get_chunk_head_found, "get_chunk_head_found_total"),
        (&s.get_chunk_missing, "get_chunk_missing_total"),
        (&s.get_chunk_small, "get_chunk_small_total"),
        (&s.get_chunk_large, "get_chunk_large_total"),
        (&s.get_chunk_bytes, "get_chunk_bytes_bytes"),
        (&s.delete_root_count, "delete_root_count_total"),
        (&s.put_root_count, "put_root_count_total"),
        (&s.get_roots_count, "get_roots_count_total"),
        (&s.get_status_count, "get_status_count_total"),
        (&s.list_chunks_count, "list_chunks_count_total"),
        (&s.list_chunks_entries, "list_chunks_entries_total"),
        (&s.delete_chunks_count, "delete_chunks_count_total"),
        (&s.chunks_deleted, "chunks_deleted_total"),
        (&s.delete_chunk_count, "delete_chunk_count_total"),
    ]
    .iter()
    {
        writeln!(
            ans,
            "# TYPE merkelbackup_{} counter\nmerkelbackup_{} {}\n",
            name,
            name,
            counter.read()
        )
        .unwrap();
    }

    writeln!(ans, "# TYPE merkelbackup_rows_count gauge",).unwrap();

    // Note that SELECT COUNT(...) always does a full table scan in SQLite3
    // so we use the max id instead, which is faster. See also:
    // https://stackoverflow.com/q/8988915/sqlite-count-slow-on-big-tables
    let roots_max_id: i64 = tryfut!(
        state
            .conn
            .lock()
            .unwrap()
            .query_row("SELECT MAX(`id`) FROM roots LIMIT 1", [], |row| row.get(0),),
        StatusCode::INTERNAL_SERVER_ERROR,
        "Select failed"
    );
    let chunks_max_id: i64 = tryfut!(
        state
            .conn
            .lock()
            .unwrap()
            .query_row("SELECT MAX(`id`) FROM chunks LIMIT 1", [], |row| row.get(0),),
        StatusCode::INTERNAL_SERVER_ERROR,
        "Select failed"
    );
    // `deletes` has no id column, but it's a tiny table,
    // so use a full table scan with COUNT(*).
    let deletes_count: i64 = tryfut!(
        state
            .conn
            .lock()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM deletes LIMIT 1", [], |row| row.get(0),),
        StatusCode::INTERNAL_SERVER_ERROR,
        "Select failed"
    );

    write!(
        ans,
        "merkelbackup_rows_count{{merkelbackup_table=\"roots\"}} {roots_max_id}\n\
        merkelbackup_rows_count{{merkelbackup_table=\"chunks\"}} {chunks_max_id}\n\
        merkelbackup_rows_count{{merkelbackup_table=\"deletes\"}} {deletes_count}\n\n",
    )
    .unwrap();

    for (name, time) in [
        ("start", &s.start_time),
        ("current", &std::time::SystemTime::now()),
    ]
    .iter()
    {
        write!(
            ans,
            "# TYPE merkelbackup_{}_time_seconds counter\nmerkelbackup_{}_time_seconds {}\n\n",
            name,
            name,
            time.duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs_f64()
        )
        .unwrap();
    }

    ok_message(Some(ans))
}

async fn handle_get_mirror(_req: Request<Incoming>, state: Arc<State>) -> ResponseFuture {
    let mut bit: u8 = 1;
    let mut val: u8 = 0;
    let mut nid: i64 = 0;
    let mut ans = String::new();

    let conn = state.conn.lock().unwrap();
    let mut stmt = conn.prepare("SELECT id FROM chunks ORDER BY id").unwrap();

    for row in stmt.query_map([], |row| row.get(0)).unwrap() {
        let id: i64 = row.expect("Unable to read db row");
        while nid <= id {
            if bit == 127 {
                ans.push((48 + val) as char);
                bit = 0;
                val = 0;
            }
            if id == nid {
                val += bit
            }
            bit *= 2;
            nid += 1;
        }
    }
    if val != 0 {
        ans.push((48 + val) as char);
    }

    ok_message(None)
}

pub async fn backup_serve(req: Request<Incoming>, state: Arc<State>) -> ResponseFuture {
    let path: Vec<String> = req
        .uri()
        .path()
        .split('/')
        .map(std::string::ToString::to_string)
        .collect();
    if req.method() == Method::GET && path.len() == 3 && path[1] == "status" {
        handle_get_status(path[2].clone(), req, state).await
    } else if req.method() == Method::GET && path.len() == 4 && path[1] == "chunks" {
        handle_get_chunk(path[2].clone(), path[3].clone(), req, state, false).await
    } else if req.method() == Method::PUT && path.len() == 4 && path[1] == "chunks" {
        handle_put_chunk(path[2].clone(), path[3].clone(), req, state).await
    } else if req.method() == Method::DELETE && path.len() == 3 && path[1] == "chunks" {
        handle_delete_chunks(path[2].clone(), req, state).await
    } else if req.method() == Method::DELETE && path.len() == 4 && path[1] == "chunks" {
        handle_delete_chunk(path[2].clone(), path[3].clone(), req, state).await
    } else if req.method() == Method::HEAD && path.len() == 4 && path[1] == "chunks" {
        handle_get_chunk(path[2].clone(), path[3].clone(), req, state, true).await
    } else if req.method() == Method::GET && path.len() == 3 && path[1] == "chunks" {
        handle_list_chunks(path[2].clone(), req, state).await
    } else if req.method() == Method::GET && path.len() == 3 && path[1] == "roots" {
        handle_get_roots(path[2].clone(), req, state).await
    } else if req.method() == Method::PUT && path.len() == 4 && path[1] == "roots" {
        handle_put_root(path[2].clone(), path[3].clone(), req, state).await
    } else if req.method() == Method::DELETE && path.len() == 4 && path[1] == "roots" {
        handle_delete_root(path[2].clone(), path[3].clone(), req, state).await
    } else if req.method() == Method::GET && path.len() == 2 && path[1] == "metrics" {
        handle_get_metrics(req, state).await
    } else if req.method() == Method::GET && path.len() == 2 && path[1] == "mirror" {
        handle_get_mirror(req, state).await
    } else {
        handle_error!(StatusCode::NOT_FOUND, "Not found", req.uri())
    }
}
