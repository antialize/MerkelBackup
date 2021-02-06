use hyper::header::CONTENT_LENGTH;
use hyper::{Body, Method, Request, Response, StatusCode};
use rusqlite::{params, NO_PARAMS};
use std::sync::Arc;

use crate::config::{AccessType, SMALL_SIZE};
use crate::error::{Error, ResponseFuture};
use crate::state::State;
use hyper::body::HttpBody;

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
        .body(Body::from(message))
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
            Some(message) => Body::from(message),
            None => Body::from(""),
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
        .body(Body::from(""))
        .unwrap())
}

/// Check if the user has an access lever greater than or equal to level
/// If he does None is returned
/// Otherwise Some(unauthorized_message()) is returned
fn check_auth(req: &Request<Body>, state: Arc<State>, level: AccessType) -> Option<ResponseFuture> {
    let auth = match req.headers().get("Authorization") {
        Some(data) => data,
        None => return Some(unauthorized_message()),
    };

    let auth = match auth.to_str() {
        Ok(data) => data,
        Err(_) => return Some(unauthorized_message()),
    };

    for user in state.config.users.iter() {
        if format!(
            "Basic {}",
            base64::encode(&format!("{}:{}", user.name, user.password))
        ) != auth
        {
            continue;
        }
        if user.access_level >= level {
            return None;
        }
    }

    Some(unauthorized_message())
}

/// Validate that a string is a valid hex encoding of a 256bit hash
fn check_hash(name: &str) -> std::result::Result<(), Error> {
    if name.len() != 64 {
        return Err(Error::Server("wrong hash length"));
    }
    for c in name.chars() {
        if '0' <= c && c <= '9' {
            continue;
        }
        if 'a' <= c && c <= 'f' {
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
    req: Request<Body>,
    state: Arc<State>,
) -> ResponseFuture {
    if let Some(res) = check_auth(&req, state.clone(), AccessType::Put) {
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
    {
        let conn = state.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT id FROM chunks WHERE bucket=? AND hash=?")
            .unwrap();

        let mut rows = stmt.query(params![bucket, chunk]).unwrap();
        if rows.next().expect("Unable to read db row").is_some() {
            state.stat.put_chunk_already_there.inc();
            return handle_error!(StatusCode::CONFLICT, "Already there", "");
        }
    }

    let mut v = Vec::new();
    let mut body = req.into_body();
    while let Some(chunk) = body.data().await {
        v.extend_from_slice(&chunk?);
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
                "INSERT INTO chunks (bucket, hash, size, time, content) VALUES (?, ?, ?, strftime('%s', 'now'), ?)",
                params![&bucket, &chunk, v.len() as i64, &v],
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
            tryfut!(conn.execute("INSERT INTO chunks (bucket, hash, size, time) VALUES (?, ?, ?, strftime('%s', 'now'))",
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

/// Get a chunk from the archive
async fn handle_get_chunk(
    bucket: String,
    chunk: String,
    req: Request<Body>,
    state: Arc<State>,
    head: bool,
) -> ResponseFuture {
    if let Some(res) = check_auth(
        &req,
        state.clone(),
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

    let (content, size) = {
        let conn = state.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT id, content, size FROM chunks WHERE bucket=? AND hash=?")
            .unwrap();

        let mut rows = stmt.query(params![bucket, chunk]).unwrap();
        let (_id, content, size) = match rows.next().expect("Unable to read db row") {
            Some(row) => {
                let id: i64 = row.get(0).unwrap();
                let content: Option<Vec<u8>> = row.get(1).unwrap();
                let size: i64 = row.get(2).unwrap();
                (id, content, size)
            }
            None => {
                if head {
                    state.stat.get_chunk_head_missing.inc();
                } else {
                    state.stat.get_chunk_missing.inc();
                }
                return handle_error!(StatusCode::NOT_FOUND, "Not found", chunk);
            }
        };
        (content, size)
    };

    if head {
        state.stat.get_chunk_head_found.inc();
        info!("{}:{}: head chunk {} success", file!(), line!(), chunk);
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_LENGTH, size)
            .body(Body::from(""))
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
        .body(Body::from(content))
        .unwrap())
}

async fn do_delete_chunks(bucket: String, chunks: &[&str], state: Arc<State>) -> ResponseFuture {
    if chunks.is_empty() {
        return ok_message(None);
    }

    let mut params: Vec<&str> = vec![&bucket];
    for chunk in chunks {
        params.push(chunk)
    }
    let count = {
        let conn = state.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(&format!(
                "SELECT hash, content IS NULL FROM chunks WHERE bucket=? AND hash IN (?{})",
                ", ?".repeat(chunks.len() - 1)
            ))
            .unwrap();

        for row in stmt
            .query_map(&params, |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
        {
            let (chunk, external): (String, bool) = row.expect("Unable to read db row");
            if external {
                let path = chunk_path(&state.config.data_dir, &bucket, &chunk);
                tryfut!(
                    match std::fs::remove_file(path) {
                        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                        v => v,
                    },
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Delete failed",
                );
            }
        }

        let count = tryfut!(
            conn.execute(
                &format!(
                    "DELETE FROM chunks WHERE bucket=? AND hash IN (?{})",
                    ", ?".repeat(chunks.len() - 1)
                ),
                &params,
            ),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Query failed",
        );

        tryfut!(
            conn.execute(
                "REPLACE INTO deletes VALUES (?, strftime('%s', 'now'))",
                params![bucket],
            ),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Query failed",
        );
        count
    };
    state.stat.chunks_deleted.add(count);
    if count != chunks.len() {
        return handle_error!(StatusCode::NOT_FOUND, "Missing chunk", "");
    }
    ok_message(None)
}

async fn handle_delete_chunk(
    bucket: String,
    chunk: String,
    req: Request<Body>,
    state: Arc<State>,
) -> ResponseFuture {
    if let Some(res) = check_auth(&req, state.clone(), AccessType::Delete) {
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

    do_delete_chunks(bucket, std::slice::from_ref(&chu), state).await
}

async fn handle_delete_chunks(
    bucket: String,
    req: Request<Body>,
    state: Arc<State>,
) -> ResponseFuture {
    if let Some(res) = check_auth(&req, state.clone(), AccessType::Delete) {
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

    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
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
    do_delete_chunks(bucket, &chunks, state).await
}

async fn handle_list_chunks(
    bucket: String,
    req: Request<Body>,
    state: Arc<State>,
) -> ResponseFuture {
    let full = req.uri().query().map_or(false, |q| q.contains("validate"));

    if let Some(res) = check_auth(
        &req,
        state.clone(),
        if full {
            AccessType::Get
        } else {
            AccessType::Put
        },
    ) {
        warn!("Unauthorized access for list chunks {}", bucket);
        return res;
    }

    tryfut!(
        check_hash(bucket.as_ref()),
        StatusCode::BAD_REQUEST,
        "Bad bucket"
    );

    state.stat.list_chunks_count.inc();

    let ans = {
        let mut ans = "".to_string();
        let conn = state.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT hash, size, length(content) FROM chunks WHERE bucket=?")
            .unwrap();

        for row in stmt
            .query_map(params![bucket], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .unwrap()
        {
            let (chunk, size, content_size): (String, i64, Option<i64>) = row.unwrap();
            if full {
                let content_size = match content_size {
                    Some(v) => v,
                    None => {
                        let path = chunk_path(&state.config.data_dir, &bucket, &chunk);
                        match std::fs::metadata(path) {
                            Ok(md) => md.len() as i64,
                            Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => -1,
                            Err(e) => {
                                return handle_error!(
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    "Unable to access metadata",
                                    e
                                )
                            }
                        }
                    }
                };
                ans.push_str(&format!("{} {} {}\n", chunk, size, content_size));
            } else {
                ans.push_str(&format!("{} {}\n", chunk, size));
            }
            state.stat.list_chunks_entries.inc();
        }
        ans
    };
    ok_message(Some(ans))
}

async fn handle_get_status(
    bucket: String,
    req: Request<Body>,
    state: Arc<State>,
) -> ResponseFuture {
    if let Some(res) = check_auth(&req, state.clone(), AccessType::Put) {
        warn!("Unauthorized access for get status {}", bucket);
        return res;
    }
    tryfut!(
        check_hash(bucket.as_ref()),
        StatusCode::BAD_REQUEST,
        "Bad bucket"
    );

    state.stat.get_status_count.inc();

    let conn = state.conn.lock().unwrap();
    let mut stmt = conn
        .prepare("SELECT time FROM deletes WHERE bucket=?")
        .unwrap();

    let mut rows = stmt.query(params![bucket]).unwrap();
    let time: i64 = match rows.next().expect("Unable to read db row") {
        Some(row) => row.get(0).expect("Unable to get number"),
        None => 0,
    };
    ok_message(Some(format!("{}", time)))
}

async fn handle_get_roots(bucket: String, req: Request<Body>, state: Arc<State>) -> ResponseFuture {
    if let Some(res) = check_auth(&req, state.clone(), AccessType::Get) {
        warn!("Unauthorized access for get roots {}", bucket);
        return res;
    }
    tryfut!(
        check_hash(bucket.as_ref()),
        StatusCode::BAD_REQUEST,
        "Bad bucket"
    );

    state.stat.get_roots_count.inc();

    let ans = {
        let conn = state.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT id, host, time, hash FROM roots WHERE bucket=?")
            .unwrap();

        let mut ans = "".to_string();
        for t in stmt
            .query_map(params![bucket], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .unwrap()
        {
            let t = t.unwrap();
            let id: i64 = t.0;
            let host: String = t.1;
            let time: i64 = t.2;
            let hash: String = t.3;
            if !ans.is_empty() {
                ans.push('\0');
                ans.push('\0');
            }
            ans.push_str(&format!("{}\0{}\0{}\0{}", id, host, time, hash));
        }
        ans
    };
    ok_message(Some(ans))
}

async fn handle_put_root(
    bucket: String,
    host: String,
    req: Request<Body>,
    state: Arc<State>,
) -> ResponseFuture {
    if let Some(res) = check_auth(&req, state.clone(), AccessType::Put) {
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
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
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
    req: Request<Body>,
    state: Arc<State>,
) -> ResponseFuture {
    if let Some(res) = check_auth(&req, state.clone(), AccessType::Delete) {
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

async fn handle_get_metrics(req: Request<Body>, state: Arc<State>) -> ResponseFuture {
    use std::fmt::Write;
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
        write!(
            ans,
            "# TYPE merkelbackup_{} counter\nmerkelbackup_{} {}\n\n",
            name,
            name,
            counter.read()
        )
        .unwrap();
    }

    write!(ans, "# TYPE merkelbackup_rows_count gauge\n",).unwrap();

    for table in ["roots", "chunks", "deletes"].iter() {
        let cnt: i64 = tryfut!(
            state.conn.lock().unwrap().query_row(
                format!("SELECT COUNT(*) FROM {}", table).as_str(),
                NO_PARAMS,
                |row| row.get(0),
            ),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Select failed"
        );

        write!(
            ans,
            "merkelbackup_rows_count{{merkelbackup_table=\"{}\"}} {}\n",
            table, cnt
        )
        .unwrap();
    }
    ans.push('\n');

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

async fn handle_get_mirror(_req: Request<Body>, state: Arc<State>) -> ResponseFuture {
    let mut bit: u8 = 1;
    let mut val: u8 = 0;
    let mut nid: i64 = 0;
    let mut ans = String::new();

    let conn = state.conn.lock().unwrap();
    let mut stmt = conn.prepare("SELECT id FROM chunks ORDER BY id").unwrap();

    for row in stmt.query_map(NO_PARAMS, |row| Ok(row.get(0)?)).unwrap() {
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

pub async fn backup_serve(req: Request<Body>, state: Arc<State>) -> ResponseFuture {
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
