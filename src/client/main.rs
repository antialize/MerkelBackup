extern crate chrono;
extern crate clap;
extern crate crypto;
extern crate filetime;
extern crate hex;
extern crate nix;
extern crate pbr;
extern crate reqwest;
extern crate rusqlite;
extern crate serde;
extern crate simple_logger;

use clap::{App, Arg, ArgMatches, SubCommand};
use crypto::blake2b::Blake2b;
use crypto::digest::Digest;
mod backup;
mod shared;
mod visit;
use chrono::NaiveDateTime;
use shared::{check_response, Config, Error, Secrets};

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

fn parse_config() -> Result<(Config, ArgMatches<'static>), Error> {
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
                .about("perform a backup")
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
                .arg(
                    Arg::with_name("dry")
                        .long("dry")
                        .help("Don't actually remove anything"),
                )
                .about("Remove old roots, and then perform garbage collection"),
        )
        .subcommand(
            SubCommand::with_name("validate")
                .arg(
                    Arg::with_name("full")
                        .long("full")
                        .help("Also check that all files have the right content"),
                )
                .about("Validate all backed up content"),
        )
        .subcommand(
            SubCommand::with_name("roots").about("list roots").arg(
                Arg::with_name("hostname")
                    .long("hostname")
                    .takes_value(true)
                    .help("Hostname to restore from"),
            ),
        )
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
                        .long("pattern")
                        .short("p")
                        .required(true)
                        .default_value("/")
                        .help("pattern of files to restore"),
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
        Some(path) => toml::from_str(&std::fs::read_to_string(path)?)?,
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
        Some(_) => return Err(Error::Msg("Unknown log level")),
        None => (),
    }

    if let Some(v) = matches.value_of("user") {
        config.user = v.to_string();
    }
    if config.user.is_empty() {
        return Err(Error::Msg("No user specified"));
    }

    if let Some(v) = matches.value_of("password") {
        config.password = v.to_string();
    }
    if config.password.is_empty() {
        return Err(Error::Msg("No password specified"));
    }

    if let Some(v) = matches.value_of("encryption_key") {
        config.encryption_key = v.to_string();
    }
    if config.encryption_key.is_empty() {
        return Err(Error::Msg("No encryption key specified"));
    }

    if let Some(v) = matches.value_of("server") {
        config.server = v.to_string();
    }
    if config.server.is_empty() {
        return Err(Error::Msg("No servers pecified"));
    }

    if let Some(m) = matches.subcommand_matches("backup") {
        if m.is_present("recheck") {
            config.recheck = true;
        }

        if let Some(v) = m.value_of("cache_db") {
            config.cache_db = v.to_string();
        }
        if config.cache_db.is_empty() {
            return Err(Error::Msg("No cache_db specified"));
        }

        if let Some(v) = m.value_of("hostname") {
            config.hostname = v.to_string();
        }
        if config.hostname.is_empty() {
            return Err(Error::Msg("No host name specified"));
        }

        if let Some(v) = m.values_of("dir") {
            config.backup_dirs = v.map(|v| v.to_string()).collect();
        }
        if config.backup_dirs.is_empty() {
            return Err(Error::Msg("No backup dirs specified"));
        }
    } else if let Some(m) = matches.subcommand_matches("validate") {
    } else if let Some(m) = matches.subcommand_matches("prune") {
    } else if let Some(m) = matches.subcommand_matches("roots") {
    } else if let Some(m) = matches.subcommand_matches("restore") {

    } else {
        return Err(Error::Msg("No sub command specified"));
    }

    return Ok((config, matches));
}

fn list_roots(host_name: Option<&str>, config: Config, secrets: Secrets) -> Result<(), Error> {
    let client = reqwest::Client::new();
    let url = format!("{}/roots/{}", &config.server, hex::encode(&secrets.bucket));
    let mut res = check_response(
        client
            .get(&url[..])
            .basic_auth(&config.user, Some(&config.password))
            .send()?,
    )?;
    println!("{:5} {:12} {}", "ID", "HOST", "TIME");

    for row in res.text().expect("utf-8").split("\0\0") {
        if row.is_empty() {
            continue;
        }
        let ans: Vec<&str> = row.split('\0').collect();
        let id: u64 = ans.get(0).ok_or(Error::MissingRow())?.parse()?;
        let host: &str = ans.get(1).ok_or(Error::MissingRow())?;
        let time: i64 = ans.get(2).ok_or(Error::MissingRow())?.parse()?;
        if let Some(name) = host_name {
            if name != host {
                continue;
            }
        }
        println!(
            "{:<5} {:12} {}",
            id,
            host,
            NaiveDateTime::from_timestamp(time, 0)
        );
    }

    Ok(())
}

fn main() -> Result<(), Error> {
    simple_logger::init_with_level(log::Level::Trace)
        .map_err(|_| Error::Msg("Unable to init log"))?;

    let (config, matches) = parse_config()?;
    log::set_max_level(config.verbosity);
    debug!("Config {:?}", config);

    info!("Derive secret!!\n");
    let secrets = derive_secrets(&config.encryption_key);
    if let Some(_) = matches.subcommand_matches("backup") {
        backup::run(config, secrets)?;
    } else if let Some(m) = matches.subcommand_matches("validate") {
        visit::run(
            config,
            secrets,
            visit::Mode::Validate {
                full: m.is_present("full"),
            },
        )?;
    } else if let Some(m) = matches.subcommand_matches("prune") {
        visit::run(
            config,
            secrets,
            visit::Mode::Prune {
                dry: m.is_present("dry"),
            },
        )?;
    } else if let Some(m) = matches.subcommand_matches("restore") {
        visit::run(
            config,
            secrets,
            visit::Mode::Restore {
                root: m
                    .value_of("root")
                    .ok_or(Error::Msg("Missing root"))?
                    .to_string(),
                pattern: m
                    .value_of("pattern")
                    .ok_or(Error::Msg("Missing pattern"))?
                    .to_string(),
                dest: m
                    .value_of("dest")
                    .ok_or(Error::Msg("Missing dest"))?
                    .to_string(),
                dry: m.is_present("dry"),
            },
        )?;
    } else if let Some(m) = matches.subcommand_matches("roots") {
        list_roots(m.value_of("hostname"), config, secrets)?;
    } else {
        panic!("unknown subcommand");
    }

    return Ok(());
}
