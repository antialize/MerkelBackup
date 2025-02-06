use log::{debug, warn};
use serde::Deserialize;
use thiserror::Error;

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
#[derive(Deserialize, PartialEq, clap::ValueEnum, Clone, Copy, Debug, Eq)]
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
        Some(self.cmp(other))
    }
}

impl Ord for Level {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let a: log::LevelFilter = (*self).into();
        let b: log::LevelFilter = (*other).into();
        a.cmp(&b)
    }
}

impl From<Level> for log::LevelFilter {
    fn from(l: Level) -> log::LevelFilter {
        match l {
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

#[derive(Error, Debug)]
pub enum Error {
    #[error("sql")]
    Sql(#[from] rusqlite::Error),
    #[error("missing row")]
    MissingRow(),
    #[error("reqwest")]
    Reqwest(#[from] reqwest::Error),
    #[error("http status")]
    HttpStatus(reqwest::StatusCode),
    #[error("bath path {0}")]
    BadPath(std::path::PathBuf),
    #[error("io error")]
    Io(#[from] std::io::Error),
    #[error("parse int")]
    ParseInt(#[from] std::num::ParseIntError),
    #[error("invalid hash")]
    InvalidHash(),
    #[error("utf8")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("time")]
    Time(#[from] std::time::SystemTimeError),
    #[error("msg {0}")]
    Msg(&'static str),
    #[error("toml")]
    Toml(#[from] toml::de::Error),
    #[error("nix")]
    Nix(#[from] nix::Error),
    #[error("lzma")]
    Lzma(#[from] lzma::LzmaError),
    #[error("stream cipher error {0}")]
    StreamCipher(cipher::StreamCipherError),
    #[error("os_random_error {0}")]
    OsRandom(rand_core::OsError),
}

impl From<cipher::StreamCipherError> for Error {
    fn from(error: cipher::StreamCipherError) -> Self {
        Error::StreamCipher(error)
    }
}

impl From<rand_core::OsError> for Error {
    fn from(error: rand_core::OsError) -> Self {
        Error::OsRandom(error)
    }
}


pub fn retry<F>(f: &mut F) -> Result<reqwest::blocking::Response, reqwest::Error>
where
    F: FnMut() -> Result<reqwest::blocking::Response, reqwest::Error>,
{
    for sleep in [5, 20, 60, 120, 240, 280].iter() {
        let sleep = match f() {
            Ok(res) => match res.status() {
                reqwest::StatusCode::REQUEST_TIMEOUT | reqwest::StatusCode::GATEWAY_TIMEOUT => {
                    warn!("Request timeout, retrying {}", res.status());
                    u64::max(*sleep, 2 * 60)
                }
                reqwest::StatusCode::TOO_MANY_REQUESTS
                | reqwest::StatusCode::INTERNAL_SERVER_ERROR
                | reqwest::StatusCode::BAD_GATEWAY
                | reqwest::StatusCode::SERVICE_UNAVAILABLE => {
                    warn!("Request failed, retrying {}", res.status());
                    *sleep
                }
                _ => return Ok(res),
            },
            Err(e) => {
                if e.is_timeout() {
                    debug!("Request failed, retrying {:?}", e)
                } else {
                    warn!("Request failed, retrying {:?}", e)
                }
                *sleep
            }
        };
        std::thread::sleep(std::time::Duration::from_secs(sleep));
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
