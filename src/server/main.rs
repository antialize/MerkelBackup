//! This is the implementation for the mbackup server.
//! It presents a REST api served over a hyper https server.

extern crate clap;
extern crate hyper;
extern crate rand;
extern crate rusqlite;
extern crate serde;
extern crate tokio;
extern crate toml;
#[macro_use]
extern crate log;
extern crate base64;
extern crate chrono;

use hyper::service::make_service_fn;
use hyper::service::service_fn;
use hyper::Server;
use std::sync::{Arc, Mutex};

mod config;
mod error;
use config::parse_config;
use error::Error;
mod handler;
use handler::backup_serve;
mod state;
use state::{setup_db, Stat, State};

struct Logger {}
impl log::Log for Logger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        let level_string = record.level().to_string();
        let target = if record.target().len() > 0 {
            record.target()
        } else {
            record.module_path().unwrap_or_default()
        };
        eprintln!(
            "{} {:<5} [{}] {}",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S,%3f"),
            level_string,
            target,
            record.args()
        );
    }

    fn flush(&self) {}
}
static LOGGER: Logger = Logger {};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    log::set_logger(&LOGGER).unwrap();

    let config = parse_config();
    log::set_max_level(config.verbosity);

    debug!("Config {:?}", config);
    let conn = Mutex::new(setup_db(&config));
    let state = Arc::new(State {
        config,
        conn,
        stat: Stat {
            put_chunk_already_there: Default::default(),
            put_chunk_small: Default::default(),
            put_chunk_large: Default::default(),
            put_chunk_bytes: Default::default(),
            get_chunk_head_missing: Default::default(),
            get_chunk_head_found: Default::default(),
            get_chunk_missing: Default::default(),
            get_chunk_small: Default::default(),
            get_chunk_large: Default::default(),
            get_chunk_bytes: Default::default(),
            delete_root_count: Default::default(),
            put_root_count: Default::default(),
            get_roots_count: Default::default(),
            get_status_count: Default::default(),
            list_chunks_count: Default::default(),
            list_chunks_entries: Default::default(),
            delete_chunks_count: Default::default(),
            chunks_deleted: Default::default(),
            delete_chunk_count: Default::default(),
            start_time: std::time::SystemTime::now(),
        },
    });
    let addr = state.config.bind.parse().expect("Bad bind address");
    let bind = state.config.bind.clone();

    let service = make_service_fn(move |_| {
        let state = state.clone();
        async { Ok::<_, Error>(service_fn(move |req| backup_serve(req, state.clone()))) }
    });

    let server = Server::bind(&addr).serve(service);
    info!("Server listening on {}", &bind);
    info!("Notify started HgWiE0XJQKoFzmEzLuR9Tv0bcyWK0AR7N");
    server.await?;

    Ok(())
}
