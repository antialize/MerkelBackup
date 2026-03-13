use http_body_util::Full;
use hyper::{Response, body::Bytes};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("hyper {0}")]
    Hyper(#[from] hyper::Error),
    #[error("rusqlite {0}")]
    Rusqlite(#[from] rusqlite::Error),
    #[error("os random {0}")]
    OsRandom(#[from] rand::rngs::SysError),
    #[error("server error: {0}")]
    Server(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;

/// The main result type used throughout
pub type ResponseFuture = Result<Response<Full<Bytes>>>;
