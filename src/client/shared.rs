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
