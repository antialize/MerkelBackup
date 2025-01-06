use std::path::Path;

use clap::Parser;
use log::info;
use rusqlite::{params, Connection};

#[derive(Parser)]
struct Args {
    /// Where do we store data
    #[clap(long = "hdd-data-dir")]
    hdd_data_dir: String,

    /// Where do we store data
    #[clap(long = "ssd-data-dir")]
    ssd_data_dir: String,
}

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

fn main() {
    log::set_logger(&LOGGER).unwrap();
    log::set_max_level(log::LevelFilter::Info);

    let args = Args::parse();
    let ssd_data_dir = Path::new(&args.ssd_data_dir);
    let hdd_data_dir = Path::new(&args.hdd_data_dir);

    let i = Connection::open(hdd_data_dir.join("backup.db")).expect("Unable to open db");
    i.pragma_update(None, "journal_mode", "WAL")
        .expect("Cannot enable wal");

    let o = Connection::open(ssd_data_dir.join("backup2.db")).expect("Unable to open new db");

    o.pragma_update(None, "journal_mode", "WAL")
        .expect("Cannot enable wal");

    info!("Creating chunks table");
    // The chunks table contains metadata for all chunks
    o.execute(
        "CREATE TABLE chunks (
            id INTEGER PRIMARY KEY NOT NULL,
            bucket TEXT NOT NULL,
            hash TEXT NOT NULL,
            size INTEGER NOT NULL,
            time INTEGER NOT NULL,
            ssd INTEGER NOT NULL
            ) STRICT",
        [],
    )
    .expect("Unable to create chunks table");

    o.execute(
        "CREATE INDEX idx_bucket_hash
        ON chunks (bucket,hash)",
        [],
    )
    .expect("Unable to create chunks table index");

    info!("Creating roots table");
    // The roots table records the root of the merkel tree of all backups
    o.execute(
        "CREATE TABLE roots (
            id INTEGER PRIMARY KEY NOT NULL,
            bucket TEXT NOT NULL,
            host TEXT NOT NULL,
            time INTEGER NOT NULL,
            hash TEXT NOT NULL
            ) STRICT",
        [],
    )
    .expect("Unable to create roots");

    info!("Creating deletes table");
    o.execute(
        "CREATE TABLE deletes (
            bucket TEXT NOT NULL UNIQUE,
            time INTEGER NOT NULL
            ) STRICT",
        [],
    )
    .expect("Unable to create deletes table");

    info!("Migrating data");
    let mut is = i.prepare("SELECT bucket, time FROM deletes").unwrap();
    let mut os = o
        .prepare("INSERT INTO deletes (bucket, time) VALUES (?, ?)")
        .unwrap();
    let mut rows = is.query(params![]).unwrap();
    while let Some(row) = rows.next().unwrap() {
        let bucket: String = row.get(0).unwrap();
        let time: i64 = row.get(1).unwrap();
        os.execute(params![bucket, time]).unwrap();
    }

    let mut is = i
        .prepare("SELECT bucket, host, time, hash FROM roots")
        .unwrap();
    let mut os = o
        .prepare("INSERT INTO roots (bucket, host, time, hash) VALUES (?, ?, ?, ?)")
        .unwrap();
    let mut rows = is.query(params![]).unwrap();
    while let Some(row) = rows.next().unwrap() {
        let bucket: String = row.get(0).unwrap();
        let host: String = row.get(1).unwrap();
        let time: i64 = row.get(2).unwrap();
        let hash: String = row.get(3).unwrap();
        os.execute(params![bucket, host, time, hash]).unwrap();
    }

    info!("Migrating chunks");
    let mut is1 = i
        .prepare("SELECT id, bucket, hash, size, time, has_content FROM chunks")
        .unwrap();
    let mut rows = is1.query(params![]).unwrap();
    let mut is2 = i
        .prepare("SELECT content FROM chunk_content WHERE chunk_id=?")
        .unwrap();
    let mut os = o
        .prepare("INSERT INTO chunks (bucket, hash, size, time, ssd) VALUES (?, ?, ?, ?, ?)")
        .unwrap();
    let mut small_count = 0;
    let mut small_size = 0;
    let mut idx = 0;
    while let Some(row) = rows.next().unwrap() {
        idx += 1;
        let id: i64 = row.get(0).unwrap();
        let bucket: String = row.get(1).unwrap();
        let hash: String = row.get(2).unwrap();
        let size: i64 = row.get(3).unwrap();
        let time: i64 = row.get(4).unwrap();
        let has_content: Option<bool> = row.get(5).unwrap();
        let has_content = has_content.unwrap_or_default();
        if has_content {
            small_count += 1;
            let mut rows = is2.query(params![id]).unwrap();
            let row = rows.next().unwrap().unwrap();
            let content: Vec<u8> = row.get(0).unwrap();
            small_size += content.len();

            let p = format!(
                "{}/data/{}/{}/{}",
                args.ssd_data_dir,
                &bucket,
                &hash[..2],
                &hash[2..]
            );
            std::fs::create_dir_all(format!(
                "{}/data/{}/{}",
                args.ssd_data_dir,
                &bucket,
                &hash[..2]
            ))
            .unwrap();
            std::fs::write(&p, content).unwrap();
        }
        os.execute(params![bucket, hash, size, time, has_content])
            .unwrap();

        if idx & 0x3FFF == 0 {
            info!(
                "cnt: {} id: {} small_files: {} small_bytes: {}",
                idx, id, small_count, small_size
            );
        }
    }
}
