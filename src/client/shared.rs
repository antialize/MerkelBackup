extern crate serde;
use log::{debug, warn};
use serde::Deserialize;
extern crate crypto;

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EType {
    Root,
    File,
    Dir,
    Link,
}

impl std::str::FromStr for EType {
    type Err = Error;

    fn from_str(s: &str) -> Result<EType, Error> {
        match s {
            "root" => Ok(EType::Root),
            "file" => Ok(EType::File),
            "dir" => Ok(EType::Dir),
            "link" => Ok(EType::Link),
            _ => Err(Error::Msg("Bad type")),
        }
    }
}
impl std::fmt::Display for EType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            EType::Root => write!(f, "root"),
            EType::File => write!(f, "file"),
            EType::Dir => write!(f, "dir"),
            EType::Link => write!(f, "link"),
        }
    }
}

/// The log level as defined in the config file
#[derive(Deserialize, PartialEq, clap::ArgEnum, Clone, Copy, Debug, Eq, Ord)]
pub enum Level {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl PartialOrd for Level {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let a: log::LevelFilter = (*self).into();
        let b: log::LevelFilter = (*other).into();
        a.partial_cmp(&b)
    }
}

impl Into<log::LevelFilter> for Level {
    fn into(self) -> log::LevelFilter {
        match self {
            Level::Off => log::LevelFilter::Off,
            Level::Error => log::LevelFilter::Error,
            Level::Warn => log::LevelFilter::Warn,
            Level::Info => log::LevelFilter::Info,
            Level::Debug => log::LevelFilter::Debug,
            Level::Trace => log::LevelFilter::Trace,
        }
    }
}

#[derive(Deserialize, PartialEq, Debug)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub verbosity: Level,
    pub backup_dirs: Vec<String>,
    pub user: String,
    pub password: String,
    pub encryption_key: String,
    pub server: String,
    pub recheck: bool,
    pub cache_db: String,
    pub hostname: String,
    pub no_atime: bool,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            verbosity: Level::Info,
            backup_dirs: Vec::new(),
            user: "".to_string(),
            password: "".to_string(),
            encryption_key: "".to_string(),
            server: "".to_string(),
            recheck: false,
            cache_db: "cache.db".to_string(),
            hostname: "".to_string(),
            no_atime: true,
        }
    }
}

#[derive(Default)]
pub struct Secrets {
    pub bucket: [u8; 32],
    pub seed: [u8; 32],
    pub key: [u8; 32],
}

#[derive(Debug)]
pub enum Error {
    Sql(rusqlite::Error),
    MissingRow(),
    Reqwest(reqwest::Error),
    HttpStatus(reqwest::StatusCode),
    BadPath(std::path::PathBuf),
    Io(std::io::Error),

    ParseInt(std::num::ParseIntError),
    InvalidHash(),
    Utf8(std::string::FromUtf8Error),
    Time(std::time::SystemTimeError),
    Msg(&'static str),
    Toml(toml::de::Error),
    Nix(nix::Error),
    Lzma(lzma::LzmaError),
}

impl From<rusqlite::Error> for Error {
    fn from(error: rusqlite::Error) -> Self {
        Error::Sql(error)
    }
}

impl From<reqwest::Error> for Error {
    fn from(error: reqwest::Error) -> Self {
        Error::Reqwest(error)
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::Io(error)
    }
}

impl From<std::num::ParseIntError> for Error {
    fn from(error: std::num::ParseIntError) -> Self {
        Error::ParseInt(error)
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(error: std::string::FromUtf8Error) -> Self {
        Error::Utf8(error)
    }
}

impl From<std::time::SystemTimeError> for Error {
    fn from(error: std::time::SystemTimeError) -> Self {
        Error::Time(error)
    }
}

impl From<toml::de::Error> for Error {
    fn from(error: toml::de::Error) -> Self {
        Error::Toml(error)
    }
}

impl From<nix::Error> for Error {
    fn from(error: nix::Error) -> Self {
        Error::Nix(error)
    }
}

impl From<lzma::LzmaError> for Error {
    fn from(error: lzma::LzmaError) -> Self {
        Error::Lzma(error)
    }
}

pub fn retry<F>(f: &mut F) -> Result<reqwest::blocking::Response, reqwest::Error>
where
    F: FnMut() -> Result<reqwest::blocking::Response, reqwest::Error>,
{
    for sleep in [5, 20, 60, 120].iter() {
        match f() {
            Ok(res) => {
                if !matches!(
                    res.status(),
                    reqwest::StatusCode::REQUEST_TIMEOUT
                        | reqwest::StatusCode::TOO_MANY_REQUESTS
                        | reqwest::StatusCode::INTERNAL_SERVER_ERROR
                        | reqwest::StatusCode::BAD_GATEWAY
                        | reqwest::StatusCode::SERVICE_UNAVAILABLE
                        | reqwest::StatusCode::GATEWAY_TIMEOUT
                ) {
                    return Ok(res);
                } else {
                    warn!("Request failed, retrying {}", res.status());
                }
            }
            Err(e) => {
                if e.is_timeout() {
                    debug!("Request failed, retrying {:?}", e)
                } else {
                    warn!("Request failed, retrying {:?}", e)
                }
            }
        };
        std::thread::sleep(std::time::Duration::from_secs(*sleep));
    }
    f()
}

pub fn check_response<F>(f: &mut F) -> Result<reqwest::blocking::Response, Error>
where
    F: FnMut() -> Result<reqwest::blocking::Response, reqwest::Error>,
{
    let res = retry(f)?;
    match res.status() {
        reqwest::StatusCode::OK => Ok(res),
        code => Err(Error::HttpStatus(code)),
    }
}
