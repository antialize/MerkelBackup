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

fn http_message(code: StatusCode, message: &'static str) -> ResponseFuture {
    return Box::new(http_message_i(code, message));
}

fn handle_put_chunk(
    bucket: String,
    chunk: String,
    req: Request<Body>,
    conn: Arc<Mutex<Connection>>,
) -> ResponseFuture {
    // TODO auth
    // TODO validate bucket
    // TODO validate chunk
    let cl: u64 = {
        let cl = match req.headers().get(CONTENT_LENGTH) {
            Some(v) => v,
            None => return http_message(StatusCode::BAD_REQUEST, "Missing content length"),
        };
        let cl = match cl.to_str() {
            Ok(cl) => cl,
            Err(_) => return http_message(StatusCode::BAD_REQUEST, "Bad content length"),
        };
        match cl.parse() {
            Ok(cl) => cl,
            Err(_) => return http_message(StatusCode::BAD_REQUEST, "Bad content length"),
        }
    };
    if cl < SMALL_SIZE {
        // Small chunks are stored directly in the db
        return Box::new(
            req.into_body()
                .fold(Vec::new(), |mut acc, chunk| {
                    acc.extend_from_slice(&*chunk);
                    futures::future::ok::<_, hyper::Error>(acc)
                })
                .and_then(move |v| {
                    if v.len() != SMALL_SIZE as usize {
                        return http_message_i(StatusCode::BAD_REQUEST, "Bad content length");
                    }
                    let res = conn.lock().unwrap().execute("INSERT INTO chunks (bucket, hash, size, time, content) VALUES (?, ?, datetime('now'), ?, ?)",
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
                    if size != SMALL_SIZE as usize {
                        return http_message_i(StatusCode::BAD_REQUEST, "Bad content length");
                    }
                    let res = conn.lock().unwrap().execute("INSERT INTO chunks (bucket, hash, size, time) VALUES (?, ?, datetime('now'), ?)",
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
    conn: Arc<Mutex<Connection>>,
    opt: bool,
) -> ResponseFuture {
    // TODO auth
    // TODO validate bucket
    // TODO validate chunk
    let conn = conn.lock().unwrap();
    let mut stmt = conn
        .prepare("SELECT id, content, size, FROM chunks WHERE bucket=? AND hash=?")
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

fn backup_serve(req: Request<Body>, conn: Arc<Mutex<Connection>>) -> ResponseFuture {
    let path: Vec<String> = req.uri().path().split("/").map(|v| v.to_string()).collect();
    if req.method() == &Method::GET && path.len() == 4 && path[0] == "chunks" {
        return handle_get_chunk(path[2].clone(), path[3].clone(), conn, false);
    } else if req.method() == &Method::PUT && path.len() == 4 && path[0] == "chunks" {
        return handle_put_chunk(path[2].clone(), path[3].clone(), req, conn);
    } else if req.method() == &Method::DELETE && path.len() == 4 && path[0] == "chunks" {
        return http_message(StatusCode::NOT_IMPLEMENTED, "Not implemented");
    } else if req.method() == &Method::OPTIONS && path.len() == 4 && path[0] == "chunks" {
        return handle_get_chunk(path[2].clone(), path[3].clone(), conn, true);
    } else if req.method() == &Method::GET && path.len() == 3 && path[0] == "chunks" {
        return http_message(StatusCode::NOT_IMPLEMENTED, "Not implemented");
    } else if req.method() == &Method::GET && path.len() == 3 && path[0] == "bloom" {
        return http_message(StatusCode::NOT_IMPLEMENTED, "Not implemented");
    } else if req.method() == &Method::GET && path.len() == 3 && path[0] == "roots" {
        return http_message(StatusCode::NOT_IMPLEMENTED, "Not implemented");
    } else if req.method() == &Method::PUT && path.len() == 3 && path[0] == "roots" {
        return http_message(StatusCode::NOT_IMPLEMENTED, "Not implemented");
    } else if req.method() == &Method::DELETE && path.len() == 4 && path[0] == "roots" {
        return http_message(StatusCode::NOT_IMPLEMENTED, "Not implemented");
    } else {
        return http_message(StatusCode::NOT_IMPLEMENTED, "Not implemented");
    }
}

fn main() {
    let conn = Connection::open("backup.db").expect("Unable to open hash cache");

    // The chunks table contains metadata for all chunks
    // and the content of small chunks
    conn.execute(
        "CREATE TABLE IF NOT EXISTS chunks (
             id INT PRIMARY KEY,
             bucket TEXT NOT NULL,
             hash TEXT NOT NULL,
             size INT NOT NULL,
             time INT NOT NULL,
             content BLOB
             )",
        NO_PARAMS,
    )
    .expect("Unable to create cache table");

    // The roots table records the root of the merkel tree of all backups
    conn.execute(
        "CREATE TABLE IF NOT EXISTS roots (
             id INT PRIMARY KEY,
             bucket TEXT NOT NULL,
             host TEXT NOT NULL,
             time INT NOT NULL,
             hash TEXT NOT NULL
             )",
        NO_PARAMS,
    )
    .expect("Unable to create cache table");

    let conn = Arc::new(Mutex::new(conn));

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
