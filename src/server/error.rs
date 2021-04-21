use hyper::{Body, Response};

#[derive(Debug)]
pub enum Error {
    Hyper(hyper::Error),
    Rusqlite(rusqlite::Error),
    Server(&'static str),
}

impl From<hyper::Error> for Error {
    fn from(error: hyper::Error) -> Self {
        Error::Hyper(error)
    }
}

impl From<rusqlite::Error> for Error {
    fn from(error: rusqlite::Error) -> Self {
        Error::Rusqlite(error)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Error::Hyper(ref e) => write!(f, "{}", e),
            Error::Rusqlite(ref e) => write!(f, "{}", e),
            Error::Server(s) => write!(f, "{}", s),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// The main result type used throughout
pub type ResponseFuture = Result<Response<Body>>;
