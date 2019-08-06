//! This is the implementation for the mbackup server.
//! It presents a REST api served over a hyper https server.
#![feature(async_await)]

extern crate clap;
extern crate hyper;
extern crate rand;
extern crate rusqlite;
extern crate serde;
extern crate simple_logger;
extern crate tokio;
extern crate toml;
#[macro_use]
extern crate log;
extern crate base64;

use hyper::server::conn::Http;
use hyper::service::make_service_fn;
use hyper::service::service_fn;
use hyper::Server;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

mod config;
mod error;
use config::parse_config;
use error::Error;
mod handler;
use handler::backup_serve;
mod state;
use state::{setup_db, State};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    simple_logger::init_with_level(log::Level::Trace).expect("Unable to init log");

    let config = parse_config();
    log::set_max_level(config.verbosity);

    debug!("Config {:?}", config);
    let conn = Mutex::new(setup_db(&config));
    let state = Arc::new(State { config, conn });
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
