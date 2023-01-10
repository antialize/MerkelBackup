use clap::Parser;
use serde::Deserialize;

/// Chunks smaller that this goes into the sqlite database instead of directly on disk
pub const SMALL_SIZE: usize = 1024 * 8;

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
#[derive(Deserialize, PartialEq, clap::ValueEnum, Clone, Copy, Debug)]
pub enum Level {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl From<Level> for log::LevelFilter {
    fn from(l: Level) -> Self {
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
/// The main configuration structure
#[derive(Deserialize, PartialEq, Debug)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub verbosity: Level,
    pub bind: String,
    pub data_dir: String,
    pub users: Vec<User>,
    pub metrics_token: Option<String>,
}

/// Provide default values for the configuration
impl Default for Config {
    fn default() -> Config {
        Config {
            verbosity: Level::Info,
            bind: "0.0.0.0:3321".to_string(),
            data_dir: ".".to_string(),
            users: Vec::new(),
            metrics_token: std::env::var("METRICS_TOKEN").ok(),
        }
    }
}

#[derive(Parser)]
#[clap(author, version, about="A server for mbackup", long_about = None)]
struct Args {
    /// Sets the level of verbosity
    #[clap(value_enum, short, long)]
    verbosity: Option<Level>, //Option<log::LevelFilter>,

    /// The interface/port to bind to
    #[clap(short, long)]
    bind: Option<String>,

    /// Where do we store data
    #[clap(long = "data-dir")]
    data_dir: Option<String>,

    /// Path to config file
    #[clap(short, long)]
    config: Option<std::path::PathBuf>,
}

pub fn parse_config() -> Config {
    let args = Args::parse();
    let mut config: Config = match args.config {
        Some(path) => {
            let data = match std::fs::read_to_string(&path) {
                Ok(data) => data,
                Err(e) => {
                    error!("Unable to open config file {:?}: {:?}", path, e);
                    std::process::exit(1)
                }
            };
            match toml::from_str(&data) {
                Ok(cfg) => cfg,
                Err(e) => {
                    error!("Unable to parse config file {:?}: {:?}", path, e);
                    std::process::exit(1)
                }
            }
        }
        None => Default::default(),
    };

    if let Some(verbosity) = args.verbosity {
        config.verbosity = verbosity;
    }

    if let Some(bind) = args.bind {
        config.bind = bind;
    }
    if let Some(dir) = args.data_dir {
        config.data_dir = dir;
    }

    config
}
