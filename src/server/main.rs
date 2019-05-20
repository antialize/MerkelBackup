extern crate futures;
extern crate hyper;
extern crate rand;
extern crate rusqlite;
extern crate tokio;
use futures::Stream;
use futures::{future, Future};
use hyper::header::CONTENT_LENGTH;
use hyper::service::service_fn;
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use rusqlite::{params, Connection, NO_PARAMS};
use std::io::Write;
use std::sync::{Arc, Mutex};


const SMALL_SIZE: u64 = 1024 * 128;

type ResponseFuture = Box<Future<Item = Response<Body>, Error = hyper::Error> + Send>;
type Conn = Arc<Mutex<Connection>>;

/** Construct a simple http responce */
fn http_message_i(
    code: StatusCode,
    message: &'static str,
) -> future::FutureResult<Response<Body>, hyper::Error> {
    return future::ok(
        Response::builder()
            .status(code)
            .body(Body::from(message))
            .unwrap(),
    );
}

/** Construct a simple boxed http responce */
fn http_message(code: StatusCode, message: &'static str) -> ResponseFuture {
    return Box::new(http_message_i(code, message));
}

/** Validate that a string is a valid hex encoding of a 256bit hash */
fn check_hash(name: &str) -> bool {
    if name.len() != 64 {
        return false;
    }
    for c in name.chars() {
        if '0' <= c && c <= '9' {
            continue;
        }
        if 'a' <= c && c <= 'f' {
            continue;
        }
        return false;
    }
    return true;
}

/** Put a chunk into the chunk archive */
fn handle_put_chunk(
    bucket: String,
    chunk: String,
    req: Request<Body>,
    conn: Conn,
) -> ResponseFuture {
    // TODO auth
    if !check_hash(bucket.as_ref()) {
        return http_message(StatusCode::BAD_REQUEST, "Bad bucket");
    }
    if !check_hash(chunk.as_ref()) {
        return http_message(StatusCode::BAD_REQUEST, "Bad chunk");
    }
    let cl: u64 = {
        let cl = match req.headers().get(CONTENT_LENGTH) {
            Some(v) => v,
            None => return http_message(StatusCode::LENGTH_REQUIRED, "Missing content length"),
        };
        let cl = match cl.to_str() {
            Ok(cl) => cl,
            Err(_) => return http_message(StatusCode::LENGTH_REQUIRED, "Bad content length"),
        };
        match cl.parse() {
            Ok(cl) => cl,
            Err(_) => return http_message(StatusCode::LENGTH_REQUIRED, "Bad content length"),
        }
    };

    if cl > 1024*1024*1024 {
        return http_message(StatusCode::BAD_REQUEST, "Too large");
    }

    {
        let conn = conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT id FROM chunks WHERE bucket=? AND hash=?")
            .unwrap();

        let mut rows = stmt.query(params![bucket, chunk]).unwrap();
        if let Some(_) = rows.next().expect("Unable to read db row") {
            return http_message(StatusCode::CONFLICT, "Already there");
        }
    }

    if cl < SMALL_SIZE {
        // Small chunks are stored directly in the db
        return Box::new(
            req.into_body()
                .fold(Vec::new(), |mut acc, chunk| {
                    acc.extend_from_slice(&*chunk);
                    futures::future::ok::<_, hyper::Error>(acc)
                })
                .and_then(move |v| {
                    if v.len() != cl as usize {
                        return http_message_i(StatusCode::LENGTH_REQUIRED, "Bad content length");
                    }
                    let res = conn.lock().unwrap().execute("INSERT INTO chunks (bucket, hash, size, time, content) VALUES (?, ?, ?, strftime('%s', 'now'), ?)",
                        params![&bucket, &chunk, v.len() as i64, &v]);
                    match res {
                        Ok(_) => http_message_i(StatusCode::OK, ""),
                        Err(_) => http_message_i(StatusCode::INTERNAL_SERVER_ERROR, "Insert failed")
                    }
                }),
        );
    } else {
        let path = format!("data/upload/{}_{}_{}", bucket, chunk, rand::random::<f64>());
        return Box::new(
            req.into_body()
                .fold((0, std::fs::File::create(&path).unwrap()), |sf, chunk| {
                    let (size, mut file) = sf;
                    file.write_all(&*chunk).expect("Did we run out of disk space?");
                    futures::future::ok::<_, hyper::Error>( (size + chunk.len(), file))
                }).and_then(move | sf| {
                    let size = sf.0;
                    drop(sf.1);
                    if size != cl as usize {
                        return http_message_i(StatusCode::BAD_REQUEST, "Bad content length");
                    }
                    let res = conn.lock().unwrap().execute("INSERT INTO chunks (bucket, hash, size, time) VALUES (?, ?, ?, strftime('%s', 'now'))",
                        params![&bucket, &chunk, size as i64]);
                    let id = match res {
                        Ok(id) => id,
                        Err(_) => return http_message_i(StatusCode::INTERNAL_SERVER_ERROR, "Insert failed")
                    };
                    match std::fs::rename(&path, format!("data/{}/{}", &bucket, id)) {
                    Ok(_) => http_message_i(StatusCode::OK, ""),
                    Err(_) => http_message_i(StatusCode::INTERNAL_SERVER_ERROR, "Move failed")
                    }
                }));
    }
}

fn handle_get_chunk(
    bucket: String,
    chunk: String,
    conn: Conn,
    opt: bool,
) -> ResponseFuture {
    // TODO auth
    if !check_hash(bucket.as_ref()) {
        return http_message(StatusCode::BAD_REQUEST, "Bad bucket");
    }
    if !check_hash(chunk.as_ref()) {
        return http_message(StatusCode::BAD_REQUEST, "Bad chunk");
    }
    let conn = conn.lock().unwrap();
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
        None => return http_message(StatusCode::NOT_FOUND, "Not found"),
    };
    if opt {
        return Box::new(future::ok(
            Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_LENGTH, size)
                .body(Body::from(""))
                .unwrap(),
        ));
    }
    match content {
        Some(content) => {
            return Box::new(future::ok(
                Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_LENGTH, size)
                    .body(Body::from(content))
                    .unwrap(),
            ))
        }
        None => return http_message(StatusCode::NOT_IMPLEMENTED, "Not implemented"),
    }
}

fn handle_delete_chunk(
    bucket: String,
    chunk: String,
    conn: Conn) -> ResponseFuture {
    // TODO auth
    if !check_hash(bucket.as_ref()) {
        return http_message(StatusCode::BAD_REQUEST, "Bad bucket");
    }
    if !check_hash(chunk.as_ref()) {
        return http_message(StatusCode::BAD_REQUEST, "Bad chunk");
    }
    match conn.lock().unwrap().execute("DELETE FROM chunks WHERE bucket=? AND hash=?", params![bucket, chunk]) {
        Err(_) => return http_message(StatusCode::INTERNAL_SERVER_ERROR, "Query failed"),
        Ok(0) => return http_message(StatusCode::NOT_FOUND, "Not found"),
        Ok(_) => return http_message(StatusCode::OK, ""),
    }
}

fn handle_list_chunks(
    bucket: String,
    conn: Conn) -> ResponseFuture {
    // TODO auth
    if !check_hash(bucket.as_ref()) {
        return http_message(StatusCode::BAD_REQUEST, "Bad bucket");
    }
    let mut ans = "".to_string();
    let conn = conn.lock().unwrap();
    let mut stmt = conn
        .prepare("SELECT hash FROM chunks WHERE bucket=?")
        .unwrap();
    
    for row in stmt.query_map(params![bucket], |row| Ok(row.get(0)?)).unwrap() {
        let row : String = row.unwrap();
        ans.push_str(&row);
        ans.push('\n');
    }
    Box::new(future::ok(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from(ans))
                    .unwrap()))
}

fn handle_get_roots(
    bucket: String,
    conn: Conn) -> ResponseFuture {

    // TODO auth
    if !check_hash(bucket.as_ref()) {
        return http_message(StatusCode::BAD_REQUEST, "Bad bucket");
    }

    let conn = conn.lock().unwrap();
    let mut stmt = conn
        .prepare("SELECT id, host, time, hash FROM roots WHERE bucket=?")
        .unwrap();
    
    let mut ans = "".to_string();
    for t in stmt.query_map(params![bucket], |row| Ok( (row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))).unwrap() {
        let t = t.unwrap();
        let id:i64 = t.0;
        let host : String = t.1;
        let time : i64 = t.2;
        let hash : String = t.3;
        if !ans.is_empty() {
             ans.push('\x01');
        }
        ans.push_str(&format!("{}\0{}\0{}\0{}", id, host, time, hash));
    }
    Box::new(future::ok(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from(ans))
                    .unwrap()))
}

fn handle_put_root(
    bucket: String,
    host: String,
    req: Request<Body>,
    conn: Conn) -> ResponseFuture {

     // TODO auth
    if !check_hash(bucket.as_ref()) {
        return http_message(StatusCode::BAD_REQUEST, "Bad bucket");
    }

    return Box::new(
        req.into_body()
            .fold(Vec::new(), |mut acc, chunk| {
                acc.extend_from_slice(&*chunk);
                futures::future::ok::<_, hyper::Error>(acc)
            })
            .and_then(move |v| {
                let s = match String::from_utf8(v) {
                    Ok(s) => s,
                    Err(_) => return http_message_i(StatusCode::BAD_REQUEST, "Bad bucket")
                };
                if !check_hash(s.as_ref()) {
                    return http_message_i(StatusCode::BAD_REQUEST, "Bad bucket");
                }
                let res = conn.lock().unwrap().execute("INSERT INTO roots (bucket, host, time, hash) VALUES (?, ?, strftime('%s', 'now'), ?)",
                    params![&bucket, &host, &s]);
                match res {
                    Ok(_) => http_message_i(StatusCode::OK, ""),
                    Err(_) => http_message_i(StatusCode::INTERNAL_SERVER_ERROR, "Insert failed")
                }
            }));
}

fn handle_delete_root(
    bucket: String,
    host: String,
    root: String,
    conn: Conn) -> ResponseFuture {

    // TODO auth
    if !check_hash(bucket.as_ref()) {
        return http_message(StatusCode::BAD_REQUEST, "Bad bucket");
    }

    match conn.lock().unwrap().execute("DELETE FROM roots WHERE bucket=? AND host=? AND id=?", params![bucket, host, root]) {
        Err(_) => return http_message(StatusCode::INTERNAL_SERVER_ERROR, "Query failed"),
        Ok(0) => return http_message(StatusCode::NOT_FOUND, "Not found"),
        Ok(_) => return http_message(StatusCode::OK, ""),
    }
}

fn backup_serve(req: Request<Body>, conn: Conn) -> ResponseFuture {
    let path: Vec<String> = req.uri().path().split("/").map(|v| v.to_string()).collect();
    if req.method() == &Method::GET && path.len() == 4 && path[1] == "chunks" {
        return handle_get_chunk(path[2].clone(), path[3].clone(), conn, false);
    } else if req.method() == &Method::PUT && path.len() == 4 && path[1] == "chunks" {
        return handle_put_chunk(path[2].clone(), path[3].clone(), req, conn);
    } else if req.method() == &Method::DELETE && path.len() == 4 && path[1] == "chunks" {
        return handle_delete_chunk(path[2].clone(), path[3].clone(), conn);
    } else if req.method() == &Method::OPTIONS && path.len() == 4 && path[1] == "chunks" {
        return handle_get_chunk(path[2].clone(), path[3].clone(), conn, true);
    } else if req.method() == &Method::GET && path.len() == 3 && path[1] == "chunks" {
        return handle_list_chunks(path[2].clone(), conn);
    } else if req.method() == &Method::GET && path.len() == 4 && path[1] == "roots" {
        return handle_get_roots(path[2].clone(), conn);
    } else if req.method() == &Method::PUT && path.len() == 3 && path[1] == "roots" {
        return handle_put_root(path[2].clone(), path[3].clone(), req, conn);
    } else if req.method() == &Method::DELETE && path.len() == 5 && path[1] == "roots" {
        return handle_delete_root(path[2].clone(), path[3].clone(), path[4].clone(), conn);
    } else {
        return http_message(StatusCode::NOT_FOUND, "Not found");
    }
}

fn setup_db() -> Conn {
    let conn = Connection::open("backup.db").expect("Unable to open hash cache");

    conn.pragma_update(None, "journal_mode", &"WAL".to_string()).expect("Cannot enable wal");

    // The chunks table contains metadata for all chunks
    // and the content of small chunks
    conn.execute(
        "CREATE TABLE IF NOT EXISTS chunks (
             id INTEGER PRIMARY KEY,
             bucket TEXT NOT NULL,
             hash TEXT NOT NULL,
             size INTEGER NOT NULL,
             time INTEGER NOT NULL,
             content BLOB
             )",
        NO_PARAMS,
    )
    .expect("Unable to create cache table");

    // The roots table records the root of the merkel tree of all backups
    conn.execute(
        "CREATE TABLE IF NOT EXISTS roots (
             id INTEGER PRIMARY KEY,
             bucket TEXT NOT NULL,
             host TEXT NOT NULL,
             time INTEGER NOT NULL,
             hash TEXT NOT NULL
             )",
        NO_PARAMS,
    )
    .expect("Unable to create cache table");

    return Arc::new(Mutex::new(conn));
}

fn main() {
    let conn = setup_db();

    let addr = ([127, 0, 0, 1], 3000).into();

    let server = Server::bind(&addr)
        .serve(move || {
            let conn = conn.clone();
            service_fn(move |req| backup_serve(req, conn.clone()))
        })
        .map_err(|e| eprintln!("server error: {}", e));

    // Run this server for... forever!
    hyper::rt::run(server);
}
