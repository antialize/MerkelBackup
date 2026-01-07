use std::path::{Path, PathBuf};

use abi_stable::std_types::RStr;
use clap::{Parser, Subcommand};
mod backup;
mod shared;
mod visit;

use blake2::Digest;
use chrono::DateTime;
use log::{debug, error};
use shared::{Config, Error, Level, Secrets, check_response};

struct Logger {}
impl log::Log for Logger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        let level_string = record.level().to_string();
        let target = if !record.target().is_empty() {
            record.target()
        } else {
            record.module_path().unwrap_or_default()
        };
        eprintln!(
            "{} {:<5} [{}] {}",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S,%3f"),
            level_string,
            target,
            record.args()
        );
    }

    fn flush(&self) {}
}
static LOGGER: Logger = Logger {};

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
    let mut hasher = blake2::Blake2b::<digest::consts::U32>::new();
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
            hasher.update(password.as_bytes());
            hasher.update(&data[prev * W..(prev + 1) * W]);
            hasher.update(&data[o1 * W..(o1 + 1) * W]);
            hasher.update(&data[o2 * W..(o2 + 1) * W]);
            hasher.finalize_into_reset(digest::generic_array::GenericArray::from_mut_slice(
                &mut data[cur * W..(cur + 1) * W],
            ));
            prev = cur;
        }
    }
    let mut secrets: Secrets = Default::default();
    secrets.bucket.copy_from_slice(&data[0..W]);
    secrets.seed.copy_from_slice(&data[128..128 + W]);
    secrets.key.copy_from_slice(&data[(ITEMS - 1) * W..]);
    secrets
}

#[derive(Parser)]
#[clap(author, version, about="A client for mbackup", long_about = None)]
struct Args {
    /// Sets the level of verbosity
    #[clap(value_enum, short, long)]
    verbosity: Option<Level>, //Option<log::LevelFilter>,

    /// The user to connect as
    #[clap(short, long)]
    user: Option<String>,

    /// The password to connect with
    #[clap(short, long)]
    password: Option<String>,

    /// The key to use when encrypting data
    #[clap(short = 'k', long = "key")]
    encryption_key: Option<String>,

    /// The remote server to connect to
    #[clap(short, long)]
    server: Option<String>,

    /// Path to config file
    #[clap(short, long)]
    config: Option<std::path::PathBuf>,

    #[clap(subcommand)]
    command: Commands,
}

#[derive(Parser)]
struct BackupCommand {
    /// Recheck all the hashes
    #[clap(long)]
    recheck: Option<bool>,

    /// The path to the hash cache db
    #[clap(long = "cache-db")]
    cache_db: Option<String>,

    /// Hostname to back up as
    #[clap(long)]
    hostname: Option<String>,

    /// Path to config file
    #[clap(short, long)]
    dir: Vec<String>,
}

#[derive(Parser)]
struct PruneCommand {
    /// Don't actually remove anything
    #[clap(long)]
    dry: bool,

    /// Prune all roots older than this many days
    #[clap(long)]
    age: Option<u32>,

    /// Keep roots one for the last 12 days, the last 12 weeks
    /// the last 12 months, and every half year for each host
    #[clap(long)]
    exponential: bool,
}

#[derive(Parser)]
struct ValidateCommand {
    /// Also check that all files have the right content
    #[clap(long)]
    full: bool,
}

#[derive(Parser)]
struct RootsCommand {
    /// Hostname to list roots from
    #[clap(long)]
    hostname: Option<String>,
}

#[derive(Parser)]
struct LsCommand {
    /// The root to list
    root: String,
}

#[derive(Parser)]
struct DeleteRootCommand {
    /// The root to delete
    root: String,
}

#[derive(Parser)]
pub struct RestoreCommand {
    /// The root to restore
    pub root: String,

    /// Pattern of files to restore
    #[clap(short, long)]
    pub pattern: PathBuf,

    /// Where to store the restored files
    #[clap(short, long, default_value = "/")]
    pub dest: PathBuf,

    /// Chown restored objects
    #[clap(long)]
    pub preserve_owner: bool,

    /// Don't actually restore anything
    #[clap(long)]
    pub dry: bool,
}

#[derive(Parser)]
struct CatCommand {
    // The root to delete
    root: String,

    // Path of file to restore
    path: std::path::PathBuf,
}

#[derive(Subcommand)]
enum Commands {
    /// Perform a backup
    Backup(BackupCommand),
    /// Remove old roots, and then perform garbage collection
    Prune(PruneCommand),
    /// Validate all backed up content
    Validate(ValidateCommand),
    /// List roots
    Roots(RootsCommand),
    /// List disk usage
    Du,
    /// Measure ping time
    Ping,
    /// List files in root
    Ls(LsCommand),
    /// Delete a root
    DeleteRoot(DeleteRootCommand),
    /// Delete a root
    Restore(RestoreCommand),
    /// Dump file to stdout
    Cat(CatCommand),
}

fn parse_config() -> Result<(Config, Commands), Error> {
    let args = Args::parse();

    let mut config: Config = match args.config {
        Some(path) => toml::from_str(&std::fs::read_to_string(path)?)?,
        None => Config {
            ..Default::default()
        },
    };

    if let Some(v) = args.verbosity {
        config.verbosity = v;
    }

    if let Some(v) = args.user {
        config.user = v;
    }

    if config.user.is_empty() {
        return Err(Error::Msg("No user specified"));
    }

    if let Some(v) = args.password {
        config.password = v;
    }
    if config.password.is_empty()
        && let Ok(v) = std::env::var("PASSWORD")
    {
        config.password = v;
    }
    if config.password.is_empty() {
        return Err(Error::Msg("No password specified"));
    }

    if let Some(v) = args.encryption_key {
        config.encryption_key = v;
    }
    if config.encryption_key.is_empty()
        && let Ok(v) = std::env::var("KEY")
    {
        config.encryption_key = v;
    }
    if config.encryption_key.is_empty() {
        return Err(Error::Msg("No encryption key specified"));
    }

    if let Some(v) = args.server {
        config.server = v;
    }
    if config.server.is_empty() {
        return Err(Error::Msg("No servers pecified"));
    }

    if let Commands::Backup(b) = &args.command {
        if let Some(r) = b.recheck {
            config.recheck = r;
        }

        if let Some(v) = &b.cache_db {
            config.cache_db = v.to_string();
        }
        if config.cache_db.is_empty() {
            return Err(Error::Msg("No cache_db specified"));
        }

        if let Some(v) = &b.hostname {
            config.hostname = v.to_string();
        }
        if config.hostname.is_empty() {
            return Err(Error::Msg("No host name specified"));
        }

        if !b.dir.is_empty() {
            config.backup_dirs = b.dir.iter().map(std::string::ToString::to_string).collect();
        }
        if config.backup_dirs.is_empty() && config.plugin.is_empty() {
            return Err(Error::Msg("No backup dirs specified or plugins"));
        }
    }

    Ok((config, args.command))
}

fn list_roots(host_name: Option<&str>, config: Config, secrets: Secrets) -> Result<(), Error> {
    let client = reqwest::blocking::Client::new();
    let url = format!("{}/roots/{}", &config.server, hex::encode(secrets.bucket));
    let res = check_response(&mut || {
        client
            .get(&url[..])
            .basic_auth(&config.user, Some(&config.password))
            .send()
    })?;
    println!("{:5} {:12} TIME", "ID", "HOST");

    for row in res.text().expect("utf-8").split("\0\0") {
        if row.is_empty() {
            continue;
        }
        let ans: Vec<&str> = row.split('\0').collect();
        let id: u64 = ans.first().ok_or(Error::MissingRow())?.parse()?;
        let host: &str = ans.get(1).ok_or(Error::MissingRow())?;
        let time: i64 = ans.get(2).ok_or(Error::MissingRow())?.parse()?;
        if let Some(name) = host_name
            && name != host
        {
            continue;
        }
        println!(
            "{:<5} {:12} {}",
            id,
            host,
            DateTime::from_timestamp(time, 0).ok_or(Error::Msg("Invalid time"))?
        );
    }
    Ok(())
}

fn delete_root(root: &str, config: Config, secrets: Secrets) -> Result<(), Error> {
    let client = reqwest::blocking::Client::new();
    match visit::roots(&config, &secrets, &client, Some(root))?
        .iter()
        .next()
    {
        Some(Err(e)) => error!("Bad root: {e:?}"),
        Some(Ok(root)) => {
            let url = format!(
                "{}/roots/{}/{}",
                &config.server,
                hex::encode(secrets.bucket),
                root.id
            );
            check_response(&mut || {
                client
                    .delete(&url[..])
                    .basic_auth(&config.user, Some(&config.password))
                    .send()
            })?;
        }
        None => {
            error!("Could not find root {root}");
        }
    }
    Ok(())
}

fn ping(config: Config, secrets: Secrets) -> Result<(), Error> {
    let client = reqwest::blocking::Client::new();
    loop {
        let start = std::time::Instant::now();
        visit::roots(&config, &secrets, &client, None)?;
        let duration = start.elapsed();
        println!("Ping {duration:?}");
    }
}

fn main() -> Result<(), Error> {
    log::set_logger(&LOGGER).unwrap();
    let (config, command) = parse_config()?;
    log::set_max_level(config.verbosity.into());
    debug!("Config {config:?}");

    debug!("Derive secret!!\n");

    let mut plugins: Vec<merkel_backup_plugin::PluginBox> = vec![];
    for plugin in &config.plugin {
        let config = match toml::to_string_pretty(&plugin) {
            Ok(v) => v,
            Err(e) => {
                error!(
                    "Failed to serialize plugin config for {}: {e:?}",
                    plugin.file
                );
                std::process::exit(1);
            }
        };
        let lib = match merkel_backup_plugin::load_plugin(Path::new(&plugin.file)) {
            Ok(v) => v,
            Err(e) => {
                error!("Failed to load plugin for {}: {e:?}", plugin.file);
                std::process::exit(1);
            }
        };
        let plugin = match lib.new_plugin()(RStr::from_str(&config)) {
            abi_stable::std_types::RResult::ROk(v) => v,
            abi_stable::std_types::RResult::RErr(e) => {
                error!("Failed loading plugin from {}: {e:?}", plugin.file);
                std::process::exit(1);
            }
        };
        plugins.push(plugin);
    }

    let secrets = derive_secrets(&config.encryption_key);
    let ok = match command {
        Commands::Backup(_) => {
            backup::run(config, secrets, &mut plugins)?;
            true
        }
        Commands::Validate(c) => visit::run_validate(config, secrets, c.full, &mut plugins)?,
        Commands::Prune(c) => {
            visit::run_prune(config, secrets, c.dry, c.age, c.exponential, &mut plugins)?
        }
        Commands::Restore(c) => visit::run_restore(config, secrets, c, &mut plugins)?,
        Commands::Cat(c) => visit::run_cat(config, secrets, c.root, c.path, &mut plugins)?,
        Commands::DeleteRoot(c) => {
            delete_root(&c.root, config, secrets)?;
            true
        }
        Commands::Roots(c) => {
            list_roots(c.hostname.as_deref(), config, secrets)?;
            true
        }
        Commands::Du => {
            visit::disk_usage(config, secrets, &mut plugins)?;
            true
        }
        Commands::Ping => {
            ping(config, secrets)?;
            true
        }
        Commands::Ls(c) => {
            visit::list_root(&c.root, config, secrets, &mut plugins)?;
            true
        }
    };
    if !ok {
        std::process::exit(1);
    }
    Ok(())
}
