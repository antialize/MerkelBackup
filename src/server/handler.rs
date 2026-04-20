use base64::Engine;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::CONTENT_LENGTH;
use hyper::{Method, Request, Response, StatusCode};
use rand::TryRng;
use rand::rngs::SysRng;
use rusqlite::params;
use std::fmt::Write;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

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
    error!("{file}:{line}: {message} {code} error {e:?}");
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
#[allow(clippy::result_large_err)]
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
        let expected = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", user.name, user.password))
        );
        if !bool::from(expected.as_bytes().ct_eq(auth.as_bytes())) {
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

/// Write a large chunk to disk via a temp file + atomic rename and record it in the DB.
/// Uses INSERT OR IGNORE so callers that have already verified non-existence and callers
/// that haven't are both safe. Returns true if a new row was inserted.
fn store_chunk_on_disk(
    conn: &mut rusqlite::Connection,
    config: &Config,
    bucket: &str,
    hash: &str,
    data: &[u8],
) -> Result<bool> {
    std::fs::create_dir_all(format!("{}/data/upload/{}", config.data_dir, bucket))
        .map_err(|_| Error::Server("Could not create upload folder"))?;
    let temp_path = format!(
        "{}/data/upload/{}/{}_{}",
        config.data_dir,
        bucket,
        hash,
        SysRng.try_next_u64()?
    );
    std::fs::write(&temp_path, data).map_err(|_| Error::Server("Write failed"))?;
    std::fs::create_dir_all(format!(
        "{}/data/{}/{}",
        config.data_dir,
        bucket,
        &hash[..2]
    ))
    .map_err(|_| Error::Server("Could not create bucket folder"))?;
    let inserted = conn.execute(
        "INSERT OR IGNORE INTO chunks (bucket, hash, size, time, has_content) \
         VALUES (?, ?, ?, strftime('%s', 'now'), FALSE)",
        params![bucket, hash, data.len() as i64],
    )?;
    if inserted > 0 {
        if std::fs::rename(&temp_path, chunk_path(&config.data_dir, bucket, hash)).is_err() {
            let _ = std::fs::remove_file(&temp_path);
            return Err(Error::Server("Move failed"));
        }
    } else {
        let _ = std::fs::remove_file(&temp_path);
    }
    Ok(inserted > 0)
}

/// Put a chunk into the chunk archive
async fn handle_put_chunk(
    bucket: String,
    chunk: String,
    req: Request<Incoming>,
    state: Arc<State>,
) -> ResponseFuture {
    if let Err(res) = check_auth(&req, &state, AccessType::Put) {
        warn!("Unauthorized access for put chunk {bucket}/{chunk}");
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
    let state2 = Arc::clone(&state);
    let bucket2 = bucket.clone();
    let chunk2 = chunk.clone();
    if tryfut!(
        tokio::task::spawn_blocking(move || {
            do_check_chunk_exists(&mut state2.conn.lock().unwrap(), &bucket2, &chunk2)
        })
        .await
        .map_err(|_| crate::error::Error::Server("blocking task panicked"))
        .and_then(|r| r),
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
        let state2 = Arc::clone(&state);
        let bucket2 = bucket.clone();
        let chunk2 = chunk.clone();
        tryfut!(
            tokio::task::spawn_blocking(move || -> crate::error::Result<()> {
                let mut conn = state2.conn.lock().unwrap();
                let tx = conn.transaction()?;
                tx.execute(
                    "INSERT INTO chunks (bucket, hash, size, time, has_content) VALUES (?, ?, ?, strftime('%s', 'now'), TRUE)",
                    params![&bucket2, &chunk2, v.len() as i64],
                )?;
                let id = tx.last_insert_rowid();
                tx.execute(
                    "INSERT INTO chunk_content (chunk_id, content) VALUES (?, ?)",
                    params![id, &v],
                )?;
                tx.commit()?;
                Ok(())
            })
            .await
            .map_err(|_| crate::error::Error::Server("blocking task panicked"))
            .and_then(|r| r),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Insert failed",
        );
    } else {
        state.stat.put_chunk_large.inc();
        let state2 = Arc::clone(&state);
        let bucket2 = bucket.clone();
        let chunk2 = chunk.clone();
        tryfut!(
            tokio::task::spawn_blocking(move || {
                store_chunk_on_disk(
                    &mut state2.conn.lock().unwrap(),
                    &state2.config,
                    &bucket2,
                    &chunk2,
                    &v,
                )
            })
            .await
            .map_err(|_| crate::error::Error::Server("blocking task panicked"))
            .and_then(|r| r),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Store chunk on disk failed"
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
        warn!("Unauthorized access for get chunk {bucket}/{chunk}");
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

    let pool = Arc::clone(&state.read_pool);
    let bucket2 = bucket.clone();
    let chunk2 = chunk.clone();
    let (content, size) = match tryfut!(
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.acquire();
            do_get_chunk(&mut conn, &bucket2, &chunk2, head)
        })
        .await
        .map_err(|_| crate::error::Error::Server("blocking task panicked"))
        .and_then(|r| r),
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
                    return handle_error!(StatusCode::INTERNAL_SERVER_ERROR, "Chunk missing", e);
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
    bucket: &str,
    chunks: &[&str],
    config: &Config,
) -> Result<usize> {
    if chunks.is_empty() {
        return Ok(0);
    }

    let mut params: Vec<&str> = vec![bucket];
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
            let path = chunk_path(&config.data_dir, bucket, &chunk);
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

/// Batch-upload multiple chunks in a single request.
/// Body format (repeated until EOF):
///   [64 ASCII hex hash]['\0'][4-byte LE u32 encrypted-data-len][encrypted-data]
/// Storage follows the same SMALL_SIZE rule as individual PUT: small chunks go into
/// the SQLite chunk_content table, large chunks are written to disk.
/// Chunks that already exist are silently skipped.
/// Response body: decimal count of newly inserted chunks.
async fn handle_put_chunks(
    bucket: String,
    req: Request<Incoming>,
    state: Arc<State>,
) -> ResponseFuture {
    if let Err(res) = check_auth(&req, &state, AccessType::Put) {
        warn!("Unauthorized access for batch put chunks {bucket}");
        return res;
    }
    tryfut!(
        check_hash(bucket.as_ref()),
        StatusCode::BAD_REQUEST,
        "Bad bucket"
    );

    let mut v = Vec::new();
    let mut body = req.into_body();
    while let Some(frame) = body.frame().await {
        let chunk = match frame?.into_data() {
            Ok(d) => d,
            Err(_) => continue,
        };
        v.extend_from_slice(&chunk);
        if v.len() > 64 * 1024 * 1024 {
            return handle_error!(StatusCode::BAD_REQUEST, "Too much data", "");
        }
    }

    let v_len = v.len();
    let state2 = Arc::clone(&state);
    let bucket2 = bucket.clone();
    let (already_there, small_inserted, large_inserted) = tryfut!(
        tokio::task::spawn_blocking(move || {
            do_put_chunks(
                &mut state2.conn.lock().unwrap(),
                &state2.config,
                &bucket2,
                &v,
            )
        })
        .await
        .map_err(|_| crate::error::Error::Server("blocking task panicked"))
        .and_then(|r| r),
        StatusCode::INTERNAL_SERVER_ERROR,
        "do_put_chunks failed"
    );
    state.stat.put_chunks_count.inc();
    state.stat.put_chunk_bytes.add(v_len);
    state.stat.put_chunk_already_there.add(already_there);
    state.stat.put_chunk_small.add(small_inserted);
    state.stat.put_chunk_large.add(large_inserted);
    let total_inserted = small_inserted + large_inserted;
    info!(
        "{}:{}: put chunks {} inserted {} chunks ({} small, {} large, {} already there)",
        file!(),
        line!(),
        bucket,
        total_inserted,
        small_inserted,
        large_inserted,
        already_there
    );
    ok_message(Some(format!("{total_inserted}")))
}

fn do_put_chunks(
    conn: &mut rusqlite::Connection,
    config: &Config,
    bucket: &str,
    data: &[u8],
) -> Result<(usize, usize, usize)> {
    // First pass: parse all records and validate, collecting what needs inserting.
    struct ChunkRecord<'d> {
        hash: String,
        size: usize,
        data: &'d [u8],
    }
    let mut records: Vec<ChunkRecord> = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        let header = rest
            .split_off(..64 + 1 + 4)
            .ok_or_else(|| Error::Server("Truncated batch record"))?;
        let hash_str =
            std::str::from_utf8(&header[..64]).map_err(|_| Error::Server("Bad hash encoding"))?;
        check_hash(hash_str)?;
        if header[64] != b'\0' {
            return Err(Error::Server("Missing record separator"));
        }
        let chunk_size = u32::from_le_bytes(header[65..69].try_into().unwrap()) as usize;
        let data = rest
            .split_off(..chunk_size)
            .ok_or_else(|| Error::Server("Truncated chunk data"))?;
        records.push(ChunkRecord {
            hash: hash_str.to_string(),
            size: chunk_size,
            data,
        });
    }

    // Second pass: insert.  Small chunks go into the DB in one transaction.
    // Large chunks are written to disk then recorded individually (matching
    // handle_put_chunk's write-then-rename approach).
    let mut small: Vec<&ChunkRecord> = Vec::new();
    let mut large: Vec<&ChunkRecord> = Vec::new();
    {
        let mut exists_stmt = conn.prepare("SELECT id FROM chunks WHERE bucket=? AND hash=?")?;
        for rec in &records {
            // Check existence once so we can skip both DB and disk work.
            let exists = exists_stmt
                .query(params![bucket, rec.hash])?
                .next()?
                .is_some();
            if !exists {
                if rec.size < SMALL_SIZE {
                    small.push(rec);
                } else {
                    large.push(rec);
                }
            }
        }
        // `exists_stmt` dropped here, releasing the borrow on `conn`.
    }

    let mut small_inserted = 0;
    let mut large_inserted = 0;

    // Batch-insert all small chunks in one transaction.
    if !small.is_empty() {
        let tx = conn.transaction()?;
        for rec in &small {
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO chunks (bucket, hash, size, time, has_content) \
                 VALUES (?, ?, ?, strftime('%s', 'now'), TRUE)",
                params![bucket, rec.hash, rec.size as i64],
            )?;
            if inserted > 0 {
                let id = tx.last_insert_rowid();
                tx.execute(
                    "INSERT OR IGNORE INTO chunk_content (chunk_id, content) VALUES (?, ?)",
                    params![id, rec.data],
                )?;
                small_inserted += 1;
            }
        }
        tx.commit()?;
    }

    // Insert large chunks via temp-file + rename.
    for rec in &large {
        if store_chunk_on_disk(conn, config, bucket, &rec.hash, rec.data)? {
            large_inserted += 1;
        }
    }

    let already_there = records.len() - small_inserted - large_inserted;
    Ok((already_there, small_inserted, large_inserted))
}

/// Check which chunks from a submitted list exist in the archive.
/// Request body: null-delimited list of chunk hashes.
/// Response body: null-delimited list of hashes that exist.
async fn handle_has_chunks(
    bucket: String,
    req: Request<Incoming>,
    state: Arc<State>,
) -> ResponseFuture {
    if let Err(res) = check_auth(&req, &state, AccessType::Put) {
        warn!("Unauthorized access for has chunks {bucket}");
        return res;
    }

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
        if v.len() >= 1024 * 1024 {
            return handle_error!(StatusCode::BAD_REQUEST, "Too much data", "");
        }
    }

    let s = tryfut!(String::from_utf8(v), StatusCode::BAD_REQUEST, "Bad chunks");
    if s.is_empty() {
        return ok_message(Some(String::new()));
    }
    for chunk in s.split('\0') {
        tryfut!(check_hash(chunk), StatusCode::BAD_REQUEST, "Bad chunk");
    }

    state.stat.has_chunks_count.inc();
    let pool = Arc::clone(&state.read_pool);
    let bucket2 = bucket.clone();
    let existing = tryfut!(
        tokio::task::spawn_blocking(move || {
            let chunks: Vec<&str> = s.split('\0').collect();
            let mut conn = pool.acquire();
            do_has_chunks(&mut conn, &bucket2, &chunks)
        })
        .await
        .map_err(|_| crate::error::Error::Server("blocking task panicked"))
        .and_then(|r| r),
        StatusCode::INTERNAL_SERVER_ERROR,
        "do_has_chunks failed"
    );
    ok_message(Some(existing))
}

fn do_has_chunks(conn: &mut rusqlite::Connection, bucket: &str, chunks: &[&str]) -> Result<String> {
    debug_assert!(!chunks.is_empty());
    let mut params: Vec<&str> = vec![bucket];
    for chunk in chunks {
        params.push(chunk);
    }
    let mut stmt = conn.prepare(&format!(
        "SELECT hash FROM chunks WHERE bucket=? AND hash IN (?{})",
        ", ?".repeat(chunks.len() - 1)
    ))?;

    let mut ans = String::new();
    for row in stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| row.get(0))? {
        let hash: String = row?;
        if !ans.is_empty() {
            ans.push('\0');
        }
        ans.push_str(&hash);
    }
    Ok(ans)
}

async fn handle_delete_chunk(
    bucket: String,
    chunk: String,
    req: Request<Incoming>,
    state: Arc<State>,
) -> ResponseFuture {
    if let Err(res) = check_auth(&req, &state, AccessType::Delete) {
        warn!("Unauthorized access for delete chunk {bucket}/{chunk}");
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
    let state2 = Arc::clone(&state);
    let bucket2 = bucket.clone();
    let chunk2 = chunk.clone();
    let count = tryfut!(
        tokio::task::spawn_blocking(move || {
            let hash = chunk2.as_str().to_string();
            do_delete_chunks(
                &mut state2.conn.lock().unwrap(),
                &bucket2,
                &[hash.as_str()],
                &state2.config,
            )
        })
        .await
        .map_err(|_| crate::error::Error::Server("blocking task panicked"))
        .and_then(|r| r),
        StatusCode::INTERNAL_SERVER_ERROR,
        "do_delete_chunks failed"
    );
    state.stat.chunks_deleted.add(count);
    if count != 1 {
        return handle_error!(StatusCode::NOT_FOUND, "Missing chunk", "");
    }
    info!("{}:{}: delete chunk {} success", file!(), line!(), chunk);
    ok_message(None)
}

async fn handle_delete_chunks(
    bucket: String,
    req: Request<Incoming>,
    state: Arc<State>,
) -> ResponseFuture {
    if let Err(res) = check_auth(&req, &state, AccessType::Delete) {
        warn!("Unauthorized access for delete chunks {bucket}");
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
    let chunk_count = {
        let chunks: Vec<&str> = s.split('\0').collect();
        for chunk in chunks.iter() {
            tryfut!(check_hash(chunk), StatusCode::BAD_REQUEST, "Bad chunk");
        }
        chunks.len()
    };
    let state2 = Arc::clone(&state);
    let bucket2 = bucket.clone();
    let count = tryfut!(
        tokio::task::spawn_blocking(move || {
            let chunks: Vec<&str> = s.split('\0').collect();
            do_delete_chunks(
                &mut state2.conn.lock().unwrap(),
                &bucket2,
                &chunks,
                &state2.config,
            )
        })
        .await
        .map_err(|_| crate::error::Error::Server("blocking task panicked"))
        .and_then(|r| r),
        StatusCode::INTERNAL_SERVER_ERROR,
        "do_delete_chunks failed"
    );
    state.stat.chunks_deleted.add(count);
    if count != chunk_count {
        return handle_error!(StatusCode::NOT_FOUND, "Missing chunk", "");
    }
    info!(
        "{}:{}: delete chunks {} deleted {} chunks",
        file!(),
        line!(),
        bucket,
        count
    );
    ok_message(None)
}

async fn handle_list_chunks(
    bucket: String,
    req: Request<Incoming>,
    state: Arc<State>,
) -> ResponseFuture {
    let validate = req.uri().query().is_some_and(|q| q.contains("validate"));

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
            warn!("Unauthorized access for list chunks {bucket}");
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

    let state2 = Arc::clone(&state);
    let pool = Arc::clone(&state.read_pool);
    let bucket2 = bucket.clone();
    let ans = tryfut!(
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.acquire();
            do_list_chunks(&mut conn, &state2.config, &bucket2, validate)
        })
        .await
        .map_err(|_| crate::error::Error::Server("blocking task panicked"))
        .and_then(|r| r),
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
        warn!("Unauthorized access for get status {bucket}");
        return res;
    }
    tryfut!(
        check_hash(bucket.as_ref()),
        StatusCode::BAD_REQUEST,
        "Bad bucket"
    );

    state.stat.get_status_count.inc();

    let pool = Arc::clone(&state.read_pool);
    let bucket2 = bucket.clone();
    let time = tryfut!(
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.acquire();
            do_get_status(&mut conn, &bucket2)
        })
        .await
        .map_err(|_| crate::error::Error::Server("blocking task panicked"))
        .and_then(|r| r),
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
            warn!("Unauthorized access for get roots {bucket}");
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
    let pool = Arc::clone(&state.read_pool);
    let bucket2 = bucket.clone();
    let roots = tryfut!(
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.acquire();
            do_get_roots(&mut conn, &bucket2, earliest_root)
        })
        .await
        .map_err(|_| crate::error::Error::Server("blocking task panicked"))
        .and_then(|r| r),
        StatusCode::INTERNAL_SERVER_ERROR,
        "do_get_roots failed"
    );
    ok_message(Some(roots))
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
        warn!("Unauthorized access for put root {bucket}");
        return res;
    }

    tryfut!(
        check_hash(bucket.as_ref()),
        StatusCode::BAD_REQUEST,
        "Bad bucket"
    );

    // Max hostname length per RFC 1035 is 253 characters.
    // Only allow alphanumeric characters, hyphens, and dots.
    if host.is_empty()
        || host.len() > 253
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
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

    let state2 = Arc::clone(&state);
    let bucket2 = bucket.clone();
    let host2 = host.clone();
    tryfut!(
        tokio::task::spawn_blocking(move || -> crate::error::Result<()> {
            state2.conn.lock().unwrap().execute(
                "INSERT INTO roots (bucket, host, time, hash) VALUES (?, ?, strftime('%s', 'now'), ?)",
                params![&bucket2, &host2, &s],
            )?;
            Ok(())
        })
        .await
        .map_err(|_| crate::error::Error::Server("blocking task panicked"))
        .and_then(|r| r),
        StatusCode::INTERNAL_SERVER_ERROR,
        "Insert failed",
    );
    info!(
        "{}:{}: put root {}/{} success",
        file!(),
        line!(),
        bucket,
        host
    );
    ok_message(None)
}

async fn handle_delete_root(
    bucket: String,
    root: String,
    req: Request<Incoming>,
    state: Arc<State>,
) -> ResponseFuture {
    if let Err(res) = check_auth(&req, &state, AccessType::Delete) {
        warn!("Unauthorized access for delete root {bucket}");
        return res;
    }
    tryfut!(
        check_hash(bucket.as_ref()),
        StatusCode::BAD_REQUEST,
        "Bad bucket"
    );

    state.stat.delete_root_count.inc();

    let state2 = Arc::clone(&state);
    let bucket2 = bucket.clone();
    let root2 = root.clone();
    let rows = tryfut!(
        tokio::task::spawn_blocking(move || -> crate::error::Result<usize> {
            Ok(state2.conn.lock().unwrap().execute(
                "DELETE FROM roots WHERE bucket=? AND id=?",
                params![bucket2, root2],
            )?)
        })
        .await
        .map_err(|_| crate::error::Error::Server("blocking task panicked"))
        .and_then(|r| r),
        StatusCode::INTERNAL_SERVER_ERROR,
        "Query failed"
    );
    match rows {
        0 => handle_error!(StatusCode::NOT_FOUND, "Not found", ""),
        _ => {
            info!(
                "{}:{}: delete root {}/{} success",
                file!(),
                line!(),
                bucket,
                root
            );
            ok_message(None)
        }
    }
}

async fn handle_get_metrics(req: Request<Incoming>, state: Arc<State>) -> ResponseFuture {
    let token = match &state.config.metrics_token {
        Some(t) => t,
        None => {
            return handle_error!(
                StatusCode::FORBIDDEN,
                "Forbidden",
                "Metrics token not configured"
            );
        }
    };

    // Accept the token either as a Bearer token in the Authorization header
    // (preferred, avoids the token appearing in logs) or as a query parameter
    // (legacy). Both paths use constant-time comparison.
    let bearer = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let provided: Option<&str> = bearer.or_else(|| req.uri().query());

    let authorized = provided
        .map(|p| bool::from(p.as_bytes().ct_eq(token.as_bytes())))
        .unwrap_or(false);

    if !authorized {
        return handle_error!(StatusCode::FORBIDDEN, "Forbidden", "Missing metrics token");
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
        (&s.has_chunks_count, "has_chunks_count_total"),
        (&s.put_chunks_count, "put_chunks_count_total"),
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
    let pool = Arc::clone(&state.read_pool);
    let (roots_max_id, chunks_max_id, deletes_count): (i64, i64, i64) = tryfut!(
        tokio::task::spawn_blocking(move || -> crate::error::Result<(i64, i64, i64)> {
            let conn = pool.acquire();
            let roots_max_id: i64 =
                conn.query_row("SELECT MAX(`id`) FROM roots LIMIT 1", [], |row| row.get(0))?;
            let chunks_max_id: i64 =
                conn.query_row("SELECT MAX(`id`) FROM chunks LIMIT 1", [], |row| row.get(0))?;
            // `deletes` has no id column, but it's a tiny table,
            // so use a full table scan with COUNT(*).
            let deletes_count: i64 =
                conn.query_row("SELECT COUNT(*) FROM deletes LIMIT 1", [], |row| row.get(0))?;
            Ok((roots_max_id, chunks_max_id, deletes_count))
        })
        .await
        .map_err(|_| crate::error::Error::Server("blocking task panicked"))
        .and_then(|r| r),
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
    } else if req.method() == Method::PUT && path.len() == 3 && path[1] == "chunks" {
        handle_put_chunks(path[2].clone(), req, state).await
    } else if req.method() == Method::POST && path.len() == 3 && path[1] == "chunks" {
        handle_has_chunks(path[2].clone(), req, state).await
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
    } else {
        handle_error!(StatusCode::NOT_FOUND, "Not found", req.uri())
    }
}
