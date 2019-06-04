use futures::{Future};
use hyper::{Body, Response};

#[derive(Debug)]
pub enum Error {
    Hyper(hyper::Error),
    Server(&'static str),
}

impl From<hyper::Error> for Error {
    fn from(error: hyper::Error) -> Self {
        Error::Hyper(error)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Error::Hyper(ref e) => write!(f, "{}", e),
            Error::Server(s) => write!(f, "{}", s),
        }
    }
}

impl std::error::Error for Error {
}

/// The main result type used throughout
pub type ResponseFuture = Box<Future<Item = Response<Body>, Error = Error> + Send>;
