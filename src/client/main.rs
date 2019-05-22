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
use crypto::symmetriccipher::SynchronousStreamCipher;
use rusqlite::{params, Connection, NO_PARAMS};
use serde::Deserialize;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::time::SystemTime;

#[macro_use]
extern crate log;

const CHUNK_SIZE: u64 = 64 * 1024 * 1024;

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
struct Config {
    #[serde(with = "LevelFilterDef")]
    verbosity: log::LevelFilter,
    backup_dirs: Vec<String>,
    user: String,
    password: String,
    encryption_key: String,
    server: String,
    recheck: bool,
    cache_db: String,
    host: String,
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
            cache_db: "chace.db".to_string(),
            host: "".to_string(),
        }
    }
}

#[derive(Default)]
struct Secrets {
    bucket: [u8; 32],
    seed : [u8; 32],
    key: [u8; 32],
    iv: [u8; 32],
}

struct State {
    secrets: Secrets,
    config: Config,
    conn: Connection,
    client: reqwest::Client,
    scan: bool,
    current_bytes: u64,
    current_files: u64,
    current_folders: u64,
    transfer_bytes: u64,
    transfer_files: u64,
    total_files: u64,
    total_folders: u64,
    total_bytes: u64,
    last_progress_time: std::time::Instant,
}

fn emit_progress(state: &mut State) {
    let now = std::time::Instant::now();
    if now.duration_since(state.last_progress_time).as_millis() < 500 {
        return;
    }
    if state.scan {
        info!(
            "Scanning: {} folders, {}/{} files, {}/{} Mb",
            state.total_folders,
            state.transfer_files,
            state.total_files,
            state.transfer_bytes / 1024 / 1024,
            state.total_bytes / 1024 / 1024
        );
    } else {
        info!(
            "Backing up: {} / {} folders, {}/{}/{} files, {}/{}/{} Mb",
            state.current_folders,
            state.total_folders,
            state.current_files,
            state.transfer_files,
            state.total_files,
            state.current_bytes / 1024 / 1024,
            state.transfer_bytes / 1024 / 1024,
            state.total_bytes / 1024 / 1024
        );
    }

    state.last_progress_time = now;
}

fn push_chunk(content: &[u8], state: &mut State) -> String {
    let mut hasher = Blake2b::new(256 / 8);
    hasher.input(&state.secrets.seed);
    hasher.input(content);
    let hash = hasher.result_str().to_string();

    let url = format!(
        "{}/chunks/{}/{}",
        &state.config.server,
        hex::encode(&state.secrets.bucket),
        &hash
    );
    let res = state.client.head(&url[..]).send().expect("Head failed");
    let send = match res.status() {
        reqwest::StatusCode::OK => false,
        reqwest::StatusCode::NOT_FOUND => true,
        _ => panic!("Upload of chunk failed"),
    };

    if send {
        let mut crypted = Vec::new();
        crypted.resize(content.len(), 0);
        crypto::chacha20::ChaCha20::new(&state.secrets.key, &state.secrets.iv[0..12])
            .process(content, &mut crypted);

        let res = state
            .client
            .put(&url[..])
            .body(reqwest::Body::from(crypted))
            .send()
            .expect("Send failed");
        if res.status() != reqwest::StatusCode::OK {
            panic!("Upload of chunk failed")
        }
    }

    state.current_bytes += content.len() as u64;
    emit_progress(state);
    return hash;
}

fn backup_file(path: &Path, size: u64, mtime: u64, state: &mut State) -> Option<String> {
    if state.scan {
        state.total_files += 1;
        state.total_bytes += size;
    }

    emit_progress(state);

    // IF the file is empty we just do nothing
    if size == 0 {
        return Some("".to_string());
    }

    // Check if we have allready checked the file once
    if !state.config.recheck {
        let mut stmt = state
            .conn
            .prepare("SELECT chunks FROM files WHERE path = ? AND size = ? AND mtime = ?")
            .unwrap();
        let mut rows = stmt
            .query(params![path.to_str().unwrap(), size as i64, mtime as i64])
            .unwrap();
        match rows.next().expect("Unable to read db row") {
            Some(row) => {
                let s: String = row.get(0).expect("chunks should not be null");
                //debug!("Skipping file {:?}: {}", path, &s);
                return Some(s);
            }
            None => (),
        }
    }

    if state.scan {
        state.transfer_files += 1;
        state.transfer_bytes += size;
        return Some("_".repeat((65 * (size + CHUNK_SIZE - 1) / CHUNK_SIZE - 1) as usize));
    } else {
        state.current_files += 1;
    }

    // Open the file and read each chunk
    let mut file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) => {
            warn!("Unable to open file {:?}: {:?}", path, error);
            return None;
        }
    };

    let mut buffer: Vec<u8> = Vec::new();
    buffer.resize(u64::min(size, CHUNK_SIZE) as usize, 0);
    let mut chunks = "".to_string();
    loop {
        let mut used = 0;
        while used < buffer.len() {
            let w = match file.read(&mut buffer[used..]) {
                Ok(w) => w,
                Err(error) => {
                    warn!("Unable to read from {:?}: {:?}", path, error);
                    return None;
                }
            };
            if w == 0 {
                break;
            }
            used += w;
        }
        if used == 0 {
            break;
        }

        if chunks.len() != 0 {
            chunks.push_str(&",");
        }
        chunks.push_str(&push_chunk(&buffer[..used], state));

        if used != buffer.len() {
            break;
        }
    }

    //TODO check if the mtime has changed while we where pushing

    state
        .conn
        .execute(
            "REPLACE INTO files (path, size, mtime, chunks) VALUES (?, ?, ?, ?)",
            params![&path.to_str().unwrap(), size as i64, mtime as i64, &chunks],
        )
        .expect("insert failed");

    return None;
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DirEnt {
    name: String,
    type_: String,
    content: String,
}

fn push_ents(mut entries: Vec<DirEnt>, state: &mut State) -> String {
    entries.sort();
    let mut ans = "".to_string();
    for ent in entries {
        if !ans.is_empty() {
            ans.push('\0');
        }
        ans.push_str(&ent.name);
        ans.push('\x01');
        ans.push_str(&ent.type_);
        ans.push('\x01');
        ans.push_str(&ent.content);
    }
    return push_chunk(ans.as_bytes(), state);
}

fn bytes_ents(entries: Vec<DirEnt>) -> u64 {
    let mut ans = 0;
    for ent in entries {
        if ans != 0 {
            ans += 1
        }
        ans += ent.name.len() + 2 + ent.type_.len() + ent.content.len()
    }
    return ans as u64;
}

fn backup_folder(dir: &Path, state: &mut State) -> Option<String> {
    if state.scan {
        state.total_folders += 1;
    } else {
        state.current_folders += 1;
    }
    emit_progress(state);
    let raw_entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) => {
            warn!("Unable to list dir {:?}: {:?}", dir, error);
            return None;
        }
    };

    let mut entries: Vec<DirEnt> = Vec::new();

    for entry in raw_entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                warn!("Unable to read dir entry in {:?}: {:?}", dir, error);
                continue;
            }
        };
        let path = entry.path();
        let md = match fs::metadata(&path) {
            Ok(md) => md,
            Err(error) => {
                warn!("Unable to read md for {:?}: {:?}", path, error);
                continue;
            }
        };
        let filename = match path.file_name().unwrap().to_str() {
            Some(n) => n,
            None => {
                warn!("Bad file name for {:?}", path);
                continue;
            }
        };
        if filename.contains("\0") || filename.contains("\x01") {
            warn!("Bad file name for {:?}", path);
            continue;
        }

        if md.is_dir() {
            match backup_folder(&path, state) {
                Some(chunks) => entries.push(DirEnt {
                    name: filename.to_string(),
                    type_: "file".to_string(),
                    content: chunks,
                }),
                None => continue,
            }
        } else if md.is_file() {
            let mtime = match md.modified() {
                Ok(mtime) => mtime
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                Err(error) => {
                    warn!("Unable to read mtime for {:?}: {:?}", path, error);
                    continue;
                }
            };
            let chunks = match backup_file(&path, md.len(), mtime, state) {
                Some(chunks) => chunks,
                None => continue,
            };
            entries.push(DirEnt {
                name: filename.to_string(),
                type_: "file".to_string(),
                content: chunks,
            });
        } else {

        }
    }
    if state.scan {
        state.total_bytes += bytes_ents(entries);
        return Some("00000000000000000000000000000000".to_string());
    } else {
        return Some(push_ents(entries, state));
    }
}

fn backup(config: Config, secrets: Secrets) {
    let conn = Connection::open(&config.cache_db).expect("Unable to open hash cache");
    {
        conn.pragma_update(None, "journal_mode", &"WAL".to_string())
            .expect("Cannot enable wal");

        conn.execute(
            "create table if not exists files (
                id integer primary key,
                path text not null unique,
                size integer not null,
                mtime integer not null,
                chunks text not null
            )",
            NO_PARAMS,
        )
        .expect("Unable to create cache table");
    }

    let mut state = State {
        secrets: secrets,
        config: config,
        conn: conn,
        client: reqwest::Client::new(),
        scan: true,
        current_bytes: 0,
        current_files: 0,
        current_folders: 0,
        transfer_bytes: 0,
        transfer_files: 0,
        total_files: 0,
        total_folders: 0,
        total_bytes: 0,
        last_progress_time: std::time::Instant::now(),
    };

    info!("Scanning");
    backup_folder(Path::new("/home/test/test"), &mut state).unwrap();

    state.scan = false;
    info!("Backup started");
    info!(
        "Root item {}",
        backup_folder(Path::new("/home/test/test"), &mut state).unwrap()
    );
}



fn derive_secrets(
    password: &str
) -> Secrets {
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
    let mut secrets:Secrets = Default::default();
    secrets.bucket.copy_from_slice(&data[0..W]);
    secrets.seed.copy_from_slice(&data[128..128 + W]);
    secrets.iv.copy_from_slice(&data[1024..1024 + W]);
    secrets.key.copy_from_slice(&data[(ITEMS - 1) * W..]);
    secrets
}

fn parse_config() -> (Config, ArgMatches<'static>) {
    let matches = App::new("mbackup server")
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
    let secrets = derive_secrets(
        &config.encryption_key,
    );
    info!("Derive secret!!\n");

    match matches.subcommand_name() {
        Some("backup") => backup(config, secrets),
        _ => panic!("No sub command"),
    }
}
