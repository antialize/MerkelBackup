extern crate serde;
use serde::Deserialize;
extern crate crypto;

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
pub struct Config {
    #[serde(with = "LevelFilterDef")]
    pub verbosity: log::LevelFilter,
    pub backup_dirs: Vec<String>,
    pub user: String,
    pub password: String,
    pub encryption_key: String,
    pub server: String,
    pub recheck: bool,
    pub cache_db: String,
    pub hostname: String,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            verbosity: log::LevelFilter::Info,
            backup_dirs: Vec::new(),
            user: "".to_string(),
            password: "".to_string(),
            encryption_key: "".to_string(),
            server: "".to_string(),
            recheck: false,
            cache_db: "cache.db".to_string(),
            hostname: "".to_string(),
        }
    }
}

#[derive(Default)]
pub struct Secrets {
    pub bucket: [u8; 32],
    pub seed: [u8; 32],
    pub key: [u8; 32],
    pub iv: [u8; 32],
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

pub fn check_response(res: reqwest::Response) -> Result<reqwest::Response, Error> {
    match res.status() {
        reqwest::StatusCode::OK => Ok(res),
        code => Err(Error::HttpStatus(code)),
    }
}
