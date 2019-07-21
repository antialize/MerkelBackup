use futures::Stream;
use futures::{future, Future};
use hyper::header::CONTENT_LENGTH;
use hyper::{Body, Method, Request, Response, StatusCode};
use rusqlite::params;
use std::sync::Arc;

use crate::config::{AccessType, SMALL_SIZE};
use crate::error::{Error, ResponseFuture};
use crate::state::State;

/// Print an error to the terminal and return a future describing the error
fn handle_error_i<E: std::fmt::Debug>(
    file: &str,
    line: u32,
    code: StatusCode,
    message: &'static str,
    e: E,
) -> future::FutureResult<Response<Body>, Error> {
    //if code != StatusCode::NOT_FOUND {
    error!("{}:{}: {} {} error {:?}", file, line, message, code, e);
    //}
    future::ok(
        Response::builder()
            .status(code)
            .body(Body::from(message))
            .unwrap(),
    )
}

/// Print an error to the terminal and return a future describing the error
macro_rules! handle_error_i {
    ($code:expr, $message:expr, $e:expr) => {
        handle_error_i(file!(), line!(), $code, $message, $e)
    };
}

/// Print an error to the terminal and return a boxed future describing the error
macro_rules! handle_error {
    ($($args:expr),* $(,)?) => {
        Box::new(handle_error_i!($($args),*))
    };
}

macro_rules! tryfut_i {
    ($r:expr, $code:expr, $err:expr $(,)?) => {
        match $r {
            Ok(v) => v,
            Err(e) => return handle_error_i!($code, $err, e),
        }
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
fn ok_message_i(message: Option<String>) -> future::FutureResult<Response<Body>, Error> {
    future::ok(
        Response::builder()
            .status(StatusCode::OK)
            .body(match message {
                Some(message) => Body::from(message),
                None => Body::from(""),
            })
            .unwrap(),
    )
}

/// Construct a boxed http ok response
fn ok_message(message: Option<String>) -> ResponseFuture {
    Box::new(ok_message_i(message))
}

/// Construct an unauthorize http response
fn unauthorized_message() -> ResponseFuture {
    Box::new(future::ok(
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(
                "WWW-Authenticate",
                "Basic realm=\"mbackup\", charset=\"UTF-8\"",
            )
            .body(Body::from(""))
            .unwrap(),
    ))
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

/// Put a chunk into the chunk archive
fn handle_put_chunk(
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
            return handle_error!(StatusCode::CONFLICT, "Already there", "");
        }
    }

    // Read and handle content
    Box::new(
        req.into_body()
            .map_err(std::convert::Into::into)
            .fold(Vec::new(), |mut acc, chunk| {
                acc.extend_from_slice(&*chunk);
                if acc.len() > 1024*1024*1024 {
                    futures::future::err(Error::Server("Content too large!"))
                } else {
                    futures::future::ok(acc)
                }
            })
            .and_then(move |v| {
                let len = v.len();
                // Small content is stored directly in the DB
                if len < SMALL_SIZE {
                    let conn = state.conn.lock().unwrap();
                    tryfut_i!(
                        conn.execute(
                            "INSERT INTO chunks (bucket, hash, size, time, content) VALUES (?, ?, ?, strftime('%s', 'now'), ?)",
                            params![&bucket, &chunk, v.len() as i64, &v],
                        ),
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Insert failed",
                    );
                } else {
                    // Large content is stored on disk. We first store the data in a temp upload folder
                    // and then atomically rename into its right location
                    tryfut_i!(std::fs::create_dir_all(format!("{}/data/upload/{}", state.config.data_dir, &bucket)),
                        StatusCode::INTERNAL_SERVER_ERROR, "Could not create upload folder");
                    let temp_path = format!("{}/data/upload/{}/{}_{}", state.config.data_dir, bucket, chunk, rand::random::<u64>());
                    tryfut_i!(std::fs::write(&temp_path, v),
                        StatusCode::INTERNAL_SERVER_ERROR,  "Write failed");
                    let conn = state.conn.lock().unwrap();
                    tryfut_i!(conn.execute("INSERT INTO chunks (bucket, hash, size, time) VALUES (?, ?, ?, strftime('%s', 'now'))",
                        params![&bucket, &chunk, len as i64]),
                        StatusCode::INTERNAL_SERVER_ERROR, "Insert failed");
                    tryfut_i!(std::fs::create_dir_all(format!("{}/data/{}/{}", state.config.data_dir, &bucket, &chunk[..2])),
                        StatusCode::INTERNAL_SERVER_ERROR, "Could not create bucket folder");
                    tryfut_i!(std::fs::rename(&temp_path, format!("{}/data/{}/{}/{}", state.config.data_dir, &bucket, &chunk[..2], &chunk[2..])),
                        StatusCode::INTERNAL_SERVER_ERROR, "Move failed");
                }
                info!("{}:{}: put chunk {} success", file!(), line!(), chunk);
                ok_message_i(None)
            }).or_else(|e| {
                handle_error_i!(StatusCode::INTERNAL_SERVER_ERROR, "Ups", e)
            }))
}

/// Get a chunk from the archive
fn handle_get_chunk(
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
            return handle_error!(StatusCode::NOT_FOUND, "Not found", chunk);
        }
    };
    if head {
        info!("{}:{}: head chunk {} success", file!(), line!(), chunk);
        return Box::new(future::ok(
            Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_LENGTH, size)
                .body(Body::from(""))
                .unwrap(),
        ));
    }
    let content = match content {
        Some(content) => content,
        None => {
            let path = format!(
                "{}/data/{}/{}/{}",
                state.config.data_dir,
                &bucket,
                &chunk[..2],
                &chunk[2..]
            );
            match std::fs::read(path) {
                Ok(data) => data,
                Err(e) => {
                    return handle_error!(StatusCode::INTERNAL_SERVER_ERROR, "Chunk missing", e)
                }
            }
        }
    };

    info!("{}:{}: get chunk {} success", file!(), line!(), chunk);
    Box::new(future::ok(
        Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_LENGTH, size)
            .body(Body::from(content))
            .unwrap(),
    ))
}

fn do_delete_chunks(
    bucket: String,
    chunks: &[&str],
    state: Arc<State>,
) -> future::FutureResult<Response<Body>, Error> {
    if chunks.is_empty() {
        return ok_message_i(None);
    }
    let conn = state.conn.lock().unwrap();

    let mut stmt = conn
        .prepare(&format!(
            "SELECT hash, content IS NULL FROM chunks WHERE bucket=? AND hash IN (?{})",
            ", ?".repeat(chunks.len() - 1)
        ))
        .unwrap();

    let mut params: Vec<&str> = vec![&bucket];
    for chunk in chunks {
        params.push(chunk)
    }

    for row in stmt
        .query_map(&params, |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
    {
        let (chunk, external): (String, bool) = row.expect("Unable to read db row");
        if external {
            let path = format!(
                "{}/data/{}/{}/{}",
                state.config.data_dir,
                &bucket,
                &chunk[..2],
                &chunk[2..]
            );
            tryfut_i!(
                match std::fs::remove_file(path) {
                    Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    v => v,
                },
                StatusCode::INTERNAL_SERVER_ERROR,
                "Delete failed",
            );
        }
    }

    let count = tryfut_i!(
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

    tryfut_i!(
        conn.execute(
            "REPLACE INTO deletes VALUES (?, strftime('%s', 'now'))",
            params![bucket],
        ),
        StatusCode::INTERNAL_SERVER_ERROR,
        "Query failed",
    );

    if count != chunks.len() {
        return handle_error_i!(StatusCode::NOT_FOUND, "Missing chunk", "");
    }
    ok_message_i(None)
}

fn handle_delete_chunk(
    bucket: String,
    chunk: String,
    req: Request<Body>,
    state: Arc<State>,
) -> ResponseFuture {
    if let Some(res) = check_auth(&req, state.clone(), AccessType::Delete) {
        warn!("Unauthorized access for delete chunk {}/{}", bucket, chunk);
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
    let chu: &str = &chunk;

    Box::new(do_delete_chunks(bucket, std::slice::from_ref(&chu), state))
}

fn handle_delete_chunks(bucket: String, req: Request<Body>, state: Arc<State>) -> ResponseFuture {
    if let Some(res) = check_auth(&req, state.clone(), AccessType::Delete) {
        warn!("Unauthorized access for delete chunks {}", bucket);
        return res;
    }

    tryfut!(
        check_hash(bucket.as_ref()),
        StatusCode::BAD_REQUEST,
        "Bad bucket"
    );

    Box::new(
        req.into_body()
            .map_err(std::convert::Into::into)
            .fold(Vec::new(), |mut acc, chunk| {
                acc.extend_from_slice(&*chunk);
                futures::future::ok::<_, Error>(acc)
            })
            .and_then(move |v| {
                let s = tryfut_i!(String::from_utf8(v), StatusCode::BAD_REQUEST, "Bad chunks");
                let chunks: Vec<&str> = s.split('\0').collect();
                for chunk in chunks.iter() {
                    tryfut_i!(
                        check_hash(chunk.as_ref()),
                        StatusCode::BAD_REQUEST,
                        "Bad bucket"
                    );
                }
                do_delete_chunks(bucket, &chunks, state)
            }),
    )
}

fn handle_list_chunks(bucket: String, req: Request<Body>, state: Arc<State>) -> ResponseFuture {
    if let Some(res) = check_auth(&req, state.clone(), AccessType::Get) {
        warn!("Unauthorized access for list chunks {}", bucket);
        return res;
    }
    tryfut!(
        check_hash(bucket.as_ref()),
        StatusCode::BAD_REQUEST,
        "Bad bucket"
    );
    let mut ans = "".to_string();
    let conn = state.conn.lock().unwrap();
    let mut stmt = conn
        .prepare("SELECT hash, size FROM chunks WHERE bucket=?")
        .unwrap();

    for row in stmt
        .query_map(params![bucket], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
    {
        let (chunk, size): (String, i64) = row.unwrap();
        ans.push_str(&format!("{} {}\n", chunk, size));
    }
    ok_message(Some(ans))
}

fn handle_get_status(bucket: String, req: Request<Body>, state: Arc<State>) -> ResponseFuture {
    if let Some(res) = check_auth(&req, state.clone(), AccessType::Put) {
        warn!("Unauthorized access for get status {}", bucket);
        return res;
    }
    tryfut!(
        check_hash(bucket.as_ref()),
        StatusCode::BAD_REQUEST,
        "Bad bucket"
    );

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

fn handle_get_roots(bucket: String, req: Request<Body>, state: Arc<State>) -> ResponseFuture {
    if let Some(res) = check_auth(&req, state.clone(), AccessType::Get) {
        warn!("Unauthorized access for get roots {}", bucket);
        return res;
    }
    tryfut!(
        check_hash(bucket.as_ref()),
        StatusCode::BAD_REQUEST,
        "Bad bucket"
    );

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
    ok_message(Some(ans))
}

fn handle_put_root(
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
        return handle_error!(StatusCode::BAD_REQUEST, "Bad host name", "",);
    }

    Box::new(
        req.into_body()
            .map_err(std::convert::Into::into)
            .fold(Vec::new(), |mut acc, chunk| {
                acc.extend_from_slice(&*chunk);
                futures::future::ok::<_, Error>(acc)
            })
            .and_then(move |v| {
                let s = tryfut_i!(String::from_utf8(v), StatusCode::BAD_REQUEST, "Bad bucket");
                tryfut_i!(check_hash(s.as_ref()), StatusCode::BAD_REQUEST, "Bad bucket");
                let conn = state.conn.lock().unwrap();
                tryfut_i!(
                    conn.execute(
                        "INSERT INTO roots (bucket, host, time, hash) VALUES (?, ?, strftime('%s', 'now'), ?)",
                        params![&bucket, &host, &s],
                    ),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Insert failed",
                );
                ok_message_i(None)
            }))
}

fn handle_delete_root(
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

    match state.conn.lock().unwrap().execute(
        "DELETE FROM roots WHERE bucket=? AND id=?",
        params![bucket, root],
    ) {
        Err(e) => handle_error!(StatusCode::INTERNAL_SERVER_ERROR, "Query failed", e,),
        Ok(0) => handle_error!(StatusCode::NOT_FOUND, "Not found", ""),
        Ok(_) => ok_message(None),
    }
}

pub fn backup_serve(req: Request<Body>, state: Arc<State>) -> ResponseFuture {
    let path: Vec<String> = req
        .uri()
        .path()
        .split('/')
        .map(std::string::ToString::to_string)
        .collect();
    if req.method() == Method::GET && path.len() == 3 && path[1] == "status" {
        handle_get_status(path[2].clone(), req, state)
    } else if req.method() == Method::GET && path.len() == 4 && path[1] == "chunks" {
        handle_get_chunk(path[2].clone(), path[3].clone(), req, state, false)
    } else if req.method() == Method::PUT && path.len() == 4 && path[1] == "chunks" {
        handle_put_chunk(path[2].clone(), path[3].clone(), req, state)
    } else if req.method() == Method::DELETE && path.len() == 3 && path[1] == "chunks" {
        handle_delete_chunks(path[2].clone(), req, state)
    } else if req.method() == Method::DELETE && path.len() == 4 && path[1] == "chunks" {
        handle_delete_chunk(path[2].clone(), path[3].clone(), req, state)
    } else if req.method() == Method::HEAD && path.len() == 4 && path[1] == "chunks" {
        handle_get_chunk(path[2].clone(), path[3].clone(), req, state, true)
    } else if req.method() == Method::GET && path.len() == 3 && path[1] == "chunks" {
        handle_list_chunks(path[2].clone(), req, state)
    } else if req.method() == Method::GET && path.len() == 3 && path[1] == "roots" {
        handle_get_roots(path[2].clone(), req, state)
    } else if req.method() == Method::PUT && path.len() == 4 && path[1] == "roots" {
        handle_put_root(path[2].clone(), path[3].clone(), req, state)
    } else if req.method() == Method::DELETE && path.len() == 4 && path[1] == "roots" {
        handle_delete_root(path[2].clone(), path[3].clone(), req, state)
    } else {
        handle_error!(StatusCode::NOT_FOUND, "Not found", req.uri(),)
    }
}
