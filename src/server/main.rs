extern crate clap;
extern crate futures;
extern crate hyper;
extern crate native_tls;
extern crate rand;
extern crate rusqlite;
extern crate serde;
extern crate simple_logger;
extern crate tokio;
extern crate tokio_tls;
extern crate toml;
#[macro_use]
extern crate log;
extern crate base64;

use clap::{App, Arg};
use futures::Stream;
use futures::{future, Future};
use hyper::header::CONTENT_LENGTH;
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Method, Request, Response, StatusCode};
use native_tls::{Identity, TlsAcceptor};
use rusqlite::{params, Connection, NO_PARAMS};
use serde::Deserialize;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

const SMALL_SIZE: usize = 1024 * 128;

type ResponseFuture = Box<Future<Item = Response<Body>, Error = hyper::Error> + Send>;

#[derive(Deserialize, PartialEq, Debug)]
enum AccessType {
    Put,
    Get,
    Delete,
}

fn access_level(access_type: &AccessType) -> u8 {
    match access_type {
        AccessType::Put => 0,
        AccessType::Get => 1,
        AccessType::Delete => 2,
    }
}

#[derive(Deserialize, PartialEq, Debug)]
#[serde(deny_unknown_fields)]
struct User {
    name: String,
    password: String,
    access_level: AccessType,
}

#[derive(Deserialize, PartialEq, Debug)]
#[serde(remote = "log::LevelFilter")]
pub enum LevelFilterDef {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Deserialize, PartialEq, Debug)]
#[serde(default, deny_unknown_fields)]
struct Config {
    #[serde(with = "LevelFilterDef")]
    verbosity: log::LevelFilter,
    bind: String,
    data_dir: String,
    ssl_cert: String,
    ssl_key: String,
    users: Vec<User>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            verbosity: log::LevelFilter::Info,
            bind: "0.0.0.0:3321".to_string(),
            data_dir: ".".to_string(),
            users: Vec::new(),
            ssl_key: "".to_string(),
            ssl_cert: "".to_string(),
        }
    }
}

struct State {
    config: Config,
    conn: Mutex<Connection>,
}

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

fn unauthorized_message() -> ResponseFuture {
    return Box::new(future::ok(
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(
                "WWW-Authenticate",
                "Basic realm=\"mbackup\", charset=\"UTF-8\"",
            )
            .body(Body::from(""))
            .unwrap(),
    ));
}

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
        if access_level(&user.access_level) >= access_level(&level) {
            return None;
        }
    }

    Some(unauthorized_message())
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
    state: Arc<State>,
) -> ResponseFuture {
    if let Some(res) = check_auth(&req, state.clone(), AccessType::Put) {
        warn!("Unauthorized access for put chunk {}/{}", bucket, chunk);
        return res;
    }

    if !check_hash(bucket.as_ref()) {
        return http_message(StatusCode::BAD_REQUEST, "Bad bucket");
    }
    if !check_hash(chunk.as_ref()) {
        return http_message(StatusCode::BAD_REQUEST, "Bad chunk");
    }
    {
        let conn = state.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT id FROM chunks WHERE bucket=? AND hash=?")
            .unwrap();

        let mut rows = stmt.query(params![bucket, chunk]).unwrap();
        if let Some(_) = rows.next().expect("Unable to read db row") {
            return http_message(StatusCode::CONFLICT, "Already there");
        }
    }

    // Small chunks are stored directly in the db
    return Box::new(
        req.into_body()
            .fold(Vec::new(), |mut acc, chunk| {
                acc.extend_from_slice(&*chunk);
                if acc.len() > 1024*1024*1024 {
                    //TODO return an error somehow
                }
                futures::future::ok::<_, hyper::Error>(acc)
            })
            .and_then(move |v| {
                let len = v.len();
                if len < SMALL_SIZE {
                    if let Err(_) = state.conn.lock().unwrap().execute("INSERT INTO chunks (bucket, hash, size, time, content) VALUES (?, ?, ?, strftime('%s', 'now'), ?)",
                        params![&bucket, &chunk, v.len() as i64, &v]) {
                        return http_message_i(StatusCode::INTERNAL_SERVER_ERROR, "Insert failed")
                    }
                } else {
                     if let Err(_) = std::fs::create_dir_all(format!("{}/data/upload/{}", state.config.data_dir, &bucket)) {
                        return http_message_i(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Could not create upload folder",
                        );
                    }
                    let temp_path = format!("{}/data/upload/{}/{}_{}", state.config.data_dir, bucket, chunk, rand::random::<u64>());
                    if let Err(_) = std::fs::write(&temp_path, v) {
                        return http_message_i(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Write failed",
                        );
                    }
                    if let Err(_) = state.conn.lock().unwrap().execute("INSERT INTO chunks (bucket, hash, size, time) VALUES (?, ?, ?, strftime('%s', 'now'))",
                        params![&bucket, &chunk, len as i64]) {
                        return http_message_i(StatusCode::INTERNAL_SERVER_ERROR, "Insert failed")
                    }
                    if let Err(_) = std::fs::create_dir_all(format!("{}/data/{}/{}", state.config.data_dir, &bucket, &chunk[..2])) {
                        return http_message_i(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Could not create bucket folder",
                        );
                    }
                    if let Err(_) = std::fs::rename(&temp_path, format!("{}/data/{}/{}/{}", state.config.data_dir, &bucket, &chunk[..2], &chunk[2..])) {
                        return http_message_i(StatusCode::INTERNAL_SERVER_ERROR, "Move failed")
                    }
                }
                http_message_i(StatusCode::OK, "")
            }).or_else(|_| {
                http_message_i(StatusCode::INTERNAL_SERVER_ERROR, "Ups")
            }));
}

fn handle_get_chunk(
    bucket: String,
    chunk: String,
    req: Request<Body>,
    state: Arc<State>,
    head: bool,
) -> ResponseFuture {
    if let Some(res) = check_auth(&req, state.clone(), AccessType::Put) {
        warn!("Unauthorized access for get chunk {}/{}", bucket, chunk);
        return res;
    }

    if !check_hash(bucket.as_ref()) {
        return http_message(StatusCode::BAD_REQUEST, "Bad bucket");
    }
    if !check_hash(chunk.as_ref()) {
        return http_message(StatusCode::BAD_REQUEST, "Bad chunk");
    }
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
        None => return http_message(StatusCode::NOT_FOUND, "Not found"),
    };
    if head {
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
                Err(_) => return http_message(StatusCode::INTERNAL_SERVER_ERROR, "Chunk missing"),
            }
        }
    };

    return Box::new(future::ok(
        Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_LENGTH, size)
            .body(Body::from(content))
            .unwrap(),
    ));
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
    if !check_hash(bucket.as_ref()) {
        return http_message(StatusCode::BAD_REQUEST, "Bad bucket");
    }
    if !check_hash(chunk.as_ref()) {
        return http_message(StatusCode::BAD_REQUEST, "Bad chunk");
    }
    match state.conn.lock().unwrap().execute(
        "DELETE FROM chunks WHERE bucket=? AND hash=?",
        params![bucket, chunk],
    ) {
        Err(_) => return http_message(StatusCode::INTERNAL_SERVER_ERROR, "Query failed"),
        Ok(0) => return http_message(StatusCode::NOT_FOUND, "Not found"),
        Ok(_) => return http_message(StatusCode::OK, ""),
    }
}

fn handle_list_chunks(bucket: String, req: Request<Body>, state: Arc<State>) -> ResponseFuture {
    if let Some(res) = check_auth(&req, state.clone(), AccessType::Get) {
        warn!("Unauthorized access for list chunks {}", bucket);
        return res;
    }
    if !check_hash(bucket.as_ref()) {
        return http_message(StatusCode::BAD_REQUEST, "Bad bucket");
    }
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
    Box::new(future::ok(
        Response::builder()
            .status(StatusCode::OK)
            .body(Body::from(ans))
            .unwrap(),
    ))
}

fn handle_get_roots(bucket: String, req: Request<Body>, state: Arc<State>) -> ResponseFuture {
    if let Some(res) = check_auth(&req, state.clone(), AccessType::Get) {
        warn!("Unauthorized access for get roots {}", bucket);
        return res;
    }
    if !check_hash(bucket.as_ref()) {
        return http_message(StatusCode::BAD_REQUEST, "Bad bucket");
    }

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
    Box::new(future::ok(
        Response::builder()
            .status(StatusCode::OK)
            .body(Body::from(ans))
            .unwrap(),
    ))
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

    if !check_hash(bucket.as_ref()) {
        return http_message(StatusCode::BAD_REQUEST, "Bad bucket");
    }

    if host.contains('\0') {
        return http_message(StatusCode::BAD_REQUEST, "Bad host name");
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
                let res = state.conn.lock().unwrap().execute("INSERT INTO roots (bucket, host, time, hash) VALUES (?, ?, strftime('%s', 'now'), ?)",
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
    req: Request<Body>,
    state: Arc<State>,
) -> ResponseFuture {
    if let Some(res) = check_auth(&req, state.clone(), AccessType::Delete) {
        warn!("Unauthorized access for delete root {}", bucket);
        return res;
    }

    if !check_hash(bucket.as_ref()) {
        return http_message(StatusCode::BAD_REQUEST, "Bad bucket");
    }

    match state.conn.lock().unwrap().execute(
        "DELETE FROM roots WHERE bucket=? AND host=? AND id=?",
        params![bucket, host, root],
    ) {
        Err(_) => return http_message(StatusCode::INTERNAL_SERVER_ERROR, "Query failed"),
        Ok(0) => return http_message(StatusCode::NOT_FOUND, "Not found"),
        Ok(_) => return http_message(StatusCode::OK, ""),
    }
}

fn backup_serve(req: Request<Body>, state: Arc<State>) -> ResponseFuture {
    let path: Vec<String> = req.uri().path().split("/").map(|v| v.to_string()).collect();
    if req.method() == &Method::GET && path.len() == 4 && path[1] == "chunks" {
        return handle_get_chunk(path[2].clone(), path[3].clone(), req, state, false);
    } else if req.method() == &Method::PUT && path.len() == 4 && path[1] == "chunks" {
        return handle_put_chunk(path[2].clone(), path[3].clone(), req, state);
    } else if req.method() == &Method::DELETE && path.len() == 4 && path[1] == "chunks" {
        return handle_delete_chunk(path[2].clone(), path[3].clone(), req, state);
    } else if req.method() == &Method::HEAD && path.len() == 4 && path[1] == "chunks" {
        return handle_get_chunk(path[2].clone(), path[3].clone(), req, state, true);
    } else if req.method() == &Method::GET && path.len() == 3 && path[1] == "chunks" {
        return handle_list_chunks(path[2].clone(), req, state);
    } else if req.method() == &Method::GET && path.len() == 3 && path[1] == "roots" {
        return handle_get_roots(path[2].clone(), req, state);
    } else if req.method() == &Method::PUT && path.len() == 4 && path[1] == "roots" {
        return handle_put_root(path[2].clone(), path[3].clone(), req, state);
    } else if req.method() == &Method::DELETE && path.len() == 5 && path[1] == "roots" {
        return handle_delete_root(
            path[2].clone(),
            path[3].clone(),
            path[4].clone(),
            req,
            state,
        );
    } else {
        return http_message(StatusCode::NOT_FOUND, "Not found");
    }
}

fn setup_db(conf: &Config) -> Connection {
    trace!("opening database");
    let conn = Connection::open(format!("{}/backup.db", conf.data_dir))
        .expect("Unable to open hash cache");

    conn.pragma_update(None, "journal_mode", &"WAL".to_string())
        .expect("Cannot enable wal");

    trace!("Creating chunks table");
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

    trace!("Creating roots table");
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

    return conn;
}

fn parse_config() -> Config {
    let matches = App::new("mbackup server")
        .version("0.1")
        .about("A server for mbackup")
        .author("Jakob Truelsen <jakob@scalgo.com>")
        .arg(
            Arg::with_name("verbosity")
                .short("v")
                .long("verbosity")
                .takes_value(true)
                .possible_values(&["none", "error", "warn", "info", "debug", "trace"])
                .help("Sets the level of verbosity"),
        )
        .arg(
            Arg::with_name("bind")
                .short("b")
                .long("bind")
                .takes_value(true)
                .help("The interface/port to bind to"),
        )
        .arg(
            Arg::with_name("data_dir")
                .long("data-dir")
                .takes_value(true)
                .help("Where do we store data"),
        )
        .arg(
            Arg::with_name("config")
                .long("config")
                .short("c")
                .takes_value(true)
                .help("Path to config file"),
        )
        .arg(
            Arg::with_name("ssl_key")
                .long("ssl-key")
                .takes_value(true)
                .help("Key for ssl cert"),
        )
        .arg(
            Arg::with_name("ssl_cert")
                .long("ssl-cert")
                .takes_value(true)
                .help("Path to pkcs12 cert to use"),
        )
        .get_matches();

    let mut config: Config = match matches.value_of("config") {
        Some(path) => {
            let data = match std::fs::read_to_string(path) {
                Ok(data) => data,
                Err(e) => {
                    error!("Unable to open config file {}: {:?}", path, e);
                    std::process::exit(1)
                }
            };
            match toml::from_str(&data) {
                Ok(cfg) => cfg,
                Err(e) => {
                    error!("Unable to parse config file {}: {:?}", path, e);
                    std::process::exit(1)
                }
            }
        }
        None => Config {
            ..Default::default()
        },
    };

    match matches.value_of("verbosity") {
        Some("none") => config.verbosity = log::LevelFilter::Off,
        Some("error") => config.verbosity = log::LevelFilter::Error,
        Some("warn") => config.verbosity = log::LevelFilter::Warn,
        Some("info") => config.verbosity = log::LevelFilter::Info,
        Some("debug") => config.verbosity = log::LevelFilter::Debug,
        Some("trace") => config.verbosity = log::LevelFilter::Trace,
        Some(v) => panic!("Unknown log level {}", v),
        None => (),
    }

    if let Some(bind) = matches.value_of("bind") {
        config.bind = bind.to_string();
    }
    if let Some(dir) = matches.value_of("data_dir") {
        config.data_dir = dir.to_string();
    }
    if let Some(key) = matches.value_of("ssl_key") {
        config.ssl_key = key.to_string();
    }
    if let Some(cert) = matches.value_of("ssl_cert") {
        config.ssl_cert = cert.to_string();
    }

    if config.ssl_cert == "" {
        panic!("No ssl cert specified")
    }

    if config.ssl_key == "" {
        panic!("No ssl key specified")
    }
    return config;
}

fn main() {
    simple_logger::init_with_level(log::Level::Trace).expect("Unable to init log");

    let config = parse_config();
    log::set_max_level(config.verbosity);

    debug!("Config {:?}", config);
    let conn = setup_db(&config);
    let state = Arc::new(State {
        config: config,
        conn: Mutex::new(conn),
    });

    let cert = std::fs::read(&state.config.ssl_cert).expect("Unable to read ssl cert");
    let cert = Identity::from_pkcs12(&cert, &state.config.ssl_key).expect("Unable to read cert");
    let tls_cx = TlsAcceptor::builder(cert)
        .build()
        .expect("Uanble to set up ssl");
    let tls_cx = tokio_tls::TlsAcceptor::from(tls_cx);
    let addr = state.config.bind.parse().expect("Bad bind address");
    let srv = TcpListener::bind(&addr).expect("Error binding local port");

    info!("Server listening on {}", state.config.bind);

    let http_proto = Http::new();
    let server = http_proto
        .serve_incoming(
            srv.incoming().and_then(move |socket| {
                tls_cx
                    .accept(socket)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
            }),
            move || {
                let state = state.clone();
                service_fn(move |req| backup_serve(req, state.clone()))
            },
        )
        .then(|res| match res {
            Ok(conn) => Ok(Some(conn)),
            Err(e) => {
                eprintln!("Error: {}", e);
                Ok(None)
            }
        })
        .for_each(|conn_opt| {
            if let Some(conn) = conn_opt {
                hyper::rt::spawn(
                    conn.and_then(|c| c.map_err(|e| panic!("Hyper error {}", e)))
                        .map_err(|e| eprintln!("Connection error {}", e)),
                );
            }

            Ok(())
        });

    hyper::rt::run(server);
}
