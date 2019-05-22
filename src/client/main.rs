extern crate clap;
extern crate crypto;
extern crate hex;
extern crate reqwest;
extern crate rusqlite;
extern crate serde;
extern crate simple_logger;

use clap::{App, Arg, ArgMatches, SubCommand};
use crypto::blake2b::Blake2b;
use crypto::digest::Digest;
mod backup;
mod shared;
use shared::{Config, Secrets};

#[macro_use]
extern crate log;

fn derive_secrets(password: &str) -> Secrets {
    // Derive secrets from password, since we need the same value every time
    // on different machines we cannot use salts or nonces
    // We derive the secrects
    // by repeatibly filling out
    // hashes[i] = HASH(
    //   password,
    //   hashes[i-1],
    //   hashes[ hashes[i-1][0] ],
    //   hashes[ hashes[i-1][1] ])
    // That way the computation cannot be parallelalized since it depends on
    // the previsous value
    // and it will require a modest amount of memory to compute
    // since it depends on 'random' previous values
    const ITEMS: usize = 1024 * 128;
    const ROUNDS: usize = 16;
    const W: usize = 32;
    const X: usize = std::mem::size_of::<usize>();
    let mut hasher = Blake2b::new(W);
    let mut data: Vec<u8> = Vec::new();
    data.resize(W * ITEMS, 42);
    for _ in 0..ROUNDS {
        let mut prev = ITEMS - 1;
        for cur in 0..ITEMS {
            let mut o1: [u8; X] = [0; X];
            o1.copy_from_slice(&data[prev * W..prev * W + X]);
            let o1 = usize::from_ne_bytes(o1) & (ITEMS - 1);
            let mut o2: [u8; X] = [0; X];
            o2.copy_from_slice(&data[prev * W + X..prev * W + 2 * X]);
            let o2 = usize::from_ne_bytes(o2) & (ITEMS - 1);
            hasher.reset();
            hasher.input(&password.as_bytes());
            hasher.input(&data[prev * W..(prev + 1) * W]);
            hasher.input(&data[o1 * W..(o1 + 1) * W]);
            hasher.input(&data[o2 * W..(o2 + 1) * W]);
            hasher.result(&mut data[cur * W..(cur + 1) * W]);
            prev = cur;
        }
    }
    let mut secrets: Secrets = Default::default();
    secrets.bucket.copy_from_slice(&data[0..W]);
    secrets.seed.copy_from_slice(&data[128..128 + W]);
    secrets.iv.copy_from_slice(&data[1024..1024 + W]);
    secrets.key.copy_from_slice(&data[(ITEMS - 1) * W..]);
    secrets
}

fn parse_config() -> (Config, ArgMatches<'static>) {
    let matches = App::new("mbackup client")
        .version("0.1")
        .about("A client for mbackup")
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
            Arg::with_name("user")
                .short("u")
                .long("user")
                .takes_value(true)
                .help("The user to connect as"),
        )
        .arg(
            Arg::with_name("password")
                .short("p")
                .long("password")
                .takes_value(true)
                .help("The password to connect with"),
        )
        .arg(
            Arg::with_name("encryption_key")
                .short("k")
                .long("key")
                .takes_value(true)
                .help("The key to use when encrypting data"),
        )
        .arg(
            Arg::with_name("server")
                .short("s")
                .long("server")
                .takes_value(true)
                .help("The remote server to connect to"),
        )
        .arg(
            Arg::with_name("config")
                .long("config")
                .short("c")
                .takes_value(true)
                .help("Path to config file"),
        )
        .subcommand(
            SubCommand::with_name("backup")
                .about("perform a backp")
                .arg(
                    Arg::with_name("recheck")
                        .long("recheck")
                        .help("Recheck all the hashes"),
                )
                .arg(
                    Arg::with_name("cache_db")
                        .long("cache-db")
                        .takes_value(true)
                        .help("The path to the hash cache db"),
                )
                .arg(
                    Arg::with_name("hostname")
                        .long("hostname")
                        .takes_value(true)
                        .help("Hostname to back up as"),
                )
                .arg(
                    Arg::with_name("dir")
                        .long("dir")
                        .takes_value(true)
                        .multiple(true)
                        .help("Directories to backup"),
                ),
        )
        .subcommand(
            SubCommand::with_name("prune")
                .about("Remove old roots, and then perform garbage collection"),
        )
        .subcommand(SubCommand::with_name("validate").about("Validate all backed up content"))
        .subcommand(
            SubCommand::with_name("restore")
                .about("restore backup files")
                .arg(
                    Arg::with_name("root")
                        .index(1)
                        .required(true)
                        .help("the root to restore"),
                )
                .arg(
                    Arg::with_name("pattern")
                        .index(2)
                        .required(true)
                        .help("pattern of files to restore"),
                )
                .arg(
                    Arg::with_name("hostname")
                        .long("hostname")
                        .takes_value(true)
                        .help("Hostname to restore from"),
                )
                .arg(
                    Arg::with_name("dest")
                        .long("dest")
                        .short("d")
                        .takes_value(true)
                        .default_value("/")
                        .help("Where to store the restored files"),
                ),
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
        None => Config {
            ..Default::default()
        },
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

    //TODO copy in more strings and validate that they are non empty

    return (config, matches);
}

fn main() {
    simple_logger::init_with_level(log::Level::Trace).expect("Unable to init log");

    let (config, matches) = parse_config();
    log::set_max_level(config.verbosity);
    debug!("Config {:?}", config);

    info!("Derive secret!!\n");
    let secrets = derive_secrets(&config.encryption_key);
    info!("Derive secret!!\n");

    match matches.subcommand_name() {
        Some("backup") => backup::run(config, secrets),
        _ => panic!("No sub command"),
    }
}
