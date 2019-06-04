//! This is the implementation for the mbackup server.
//! It presents a REST api served over a hyper https server.

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

use futures::Stream;
use futures::{Future};
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Server};
use native_tls::{Identity, TlsAcceptor};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

mod error;
mod config;
use config::parse_config;
mod handler;
use handler::backup_serve;
mod state;
use state::{State, setup_db};

fn main() {
    simple_logger::init_with_level(log::Level::Trace).expect("Unable to init log");

    let config = parse_config();
    log::set_max_level(config.verbosity);

    debug!("Config {:?}", config);
    let conn = Mutex::new(setup_db(&config));
    let state = Arc::new(State { config, conn });
    let addr = state.config.bind.parse().expect("Bad bind address");
    let bind = state.config.bind.clone();

    if state.config.ssl_cert == "" {
        let server = Server::bind(&addr)
            .serve(move || {
                let state = state.clone();
                service_fn(move |req| backup_serve(req, state.clone()))
            })
            .map_err(|e| eprintln!("server error: {}", e));
        info!("Server listening on {}", &bind);
        info!("Notify started HgWiE0XJQKoFzmEzLuR9Tv0bcyWK0AR7N");
        hyper::rt::run(server);
    } else {
        let srv = TcpListener::bind(&addr).expect("Error binding local port");

        let cert = std::fs::read(&state.config.ssl_cert).expect("Unable to read ssl cert");
        let cert =
            Identity::from_pkcs12(&cert, &state.config.ssl_key).expect("Unable to read cert");
        let tls_cx = TlsAcceptor::builder(cert)
            .build()
            .expect("Uanble to set up ssl");
        let tls_cx = tokio_tls::TlsAcceptor::from(tls_cx);

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
        info!("Server listening on {}", &bind);
        info!("Notify started HgWiE0XJQKoFzmEzLuR9Tv0bcyWK0AR7N");
        hyper::rt::run(server);
    }
}
