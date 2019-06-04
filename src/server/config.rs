use clap::{App, Arg};
use serde::Deserialize;

/// Chunks smaller that this goes into the sqlite database instead of directly on disk
pub const SMALL_SIZE: usize = 1024 * 128;

/// The access level required, Put is the minimal, Delete is the maximal
#[derive(Deserialize, PartialEq, Debug)]
pub enum AccessType {
    Put,
    Get,
    Delete,
}

/// Convert an access lever to a number for comparison
fn access_level(access_type: &AccessType) -> u8 {
    match access_type {
        AccessType::Put => 0,
        AccessType::Get => 1,
        AccessType::Delete => 2,
    }
}

impl std::cmp::PartialOrd for AccessType {
    fn partial_cmp(&self, other: &AccessType) -> Option<std::cmp::Ordering> {
        access_level(self).partial_cmp(&access_level(other))
    }
}

/// A user as defined in the config file
#[derive(Deserialize, PartialEq, Debug)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub name: String,
    pub password: String,
    pub access_level: AccessType,
}

/// The log level as defined in the config file
///
/// We need this duplication hack so we can get serde to deserialise it
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

/// The main configuration structure
#[derive(Deserialize, PartialEq, Debug)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    #[serde(with = "LevelFilterDef")]
    pub verbosity: log::LevelFilter,
    pub bind: String,
    pub data_dir: String,
    pub ssl_cert: String,
    pub ssl_key: String,
    pub users: Vec<User>,
}

/// Provide default values for the configuration
impl Default for Config {
    fn default() -> Config {
        Config {
            verbosity: log::LevelFilter::Info,
            bind: "0.0.0.0:3321".to_string(),
            data_dir: ".".to_string(),
            users: Vec::new(),
            ssl_key: "".to_string(),
            ssl_cert: "".to_string(),
        }
    }
}

pub fn parse_config() -> Config {
    let matches = App::new("mbackup server")
        .version("0.1")
        .about("A server for mbackup")
        .author("Jakob Truelsen <jakob@scalgo.com>")
        .arg(
            Arg::with_name("verbosity")
                .short("v")
                .long("verbosity")
                .takes_value(true)
                .possible_values(&["none", "error", "warn", "info", "debug", "trace"])
                .help("Sets the level of verbosity"),
        )
        .arg(
            Arg::with_name("bind")
                .short("b")
                .long("bind")
                .takes_value(true)
                .help("The interface/port to bind to"),
        )
        .arg(
            Arg::with_name("data_dir")
                .long("data-dir")
                .takes_value(true)
                .help("Where do we store data"),
        )
        .arg(
            Arg::with_name("config")
                .long("config")
                .short("c")
                .takes_value(true)
                .help("Path to config file"),
        )
        .arg(
            Arg::with_name("ssl_key")
                .long("ssl-key")
                .takes_value(true)
                .help("Key for ssl cert"),
        )
        .arg(
            Arg::with_name("ssl_cert")
                .long("ssl-cert")
                .takes_value(true)
                .help("Path to pkcs12 cert to use"),
        )
        .get_matches();

    let mut config: Config = match matches.value_of("config") {
        Some(path) => {
            let data = match std::fs::read_to_string(path) {
                Ok(data) => data,
                Err(e) => {
                    error!("Unable to open config file {}: {:?}", path, e);
                    std::process::exit(1)
                }
            };
            match toml::from_str(&data) {
                Ok(cfg) => cfg,
                Err(e) => {
                    error!("Unable to parse config file {}: {:?}", path, e);
                    std::process::exit(1)
                }
            }
        }
        None => Default::default(),
    };

    match matches.value_of("verbosity") {
        Some("none") => config.verbosity = log::LevelFilter::Off,
        Some("error") => config.verbosity = log::LevelFilter::Error,
        Some("warn") => config.verbosity = log::LevelFilter::Warn,
        Some("info") => config.verbosity = log::LevelFilter::Info,
        Some("debug") => config.verbosity = log::LevelFilter::Debug,
        Some("trace") => config.verbosity = log::LevelFilter::Trace,
        Some(v) => panic!("Unknown log level {}", v),
        None => (),
    }

    if let Some(bind) = matches.value_of("bind") {
        config.bind = bind.to_string();
    }
    if let Some(dir) = matches.value_of("data_dir") {
        config.data_dir = dir.to_string();
    }
    if let Some(key) = matches.value_of("ssl_key") {
        config.ssl_key = key.to_string();
    }
    if let Some(cert) = matches.value_of("ssl_cert") {
        config.ssl_cert = cert.to_string();
    }

    config
}
