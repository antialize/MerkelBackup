use rusqlite::Connection;
use std::sync::Mutex;

use crate::config::Config;

#[derive(Default)]
pub struct StatCounter {
    value: std::sync::atomic::AtomicUsize,
}

impl StatCounter {
    pub fn add(&self, value: usize) {
        self.value
            .fetch_add(value, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn inc(&self) {
        self.add(1);
    }

    pub fn read(&self) -> usize {
        self.value.load(std::sync::atomic::Ordering::SeqCst)
    }
}

pub struct Stat {
    pub put_chunk_already_there: StatCounter,
    pub put_chunk_small: StatCounter,
    pub put_chunk_large: StatCounter,
    pub put_chunk_bytes: StatCounter,
    pub get_chunk_head_missing: StatCounter,
    pub get_chunk_head_found: StatCounter,
    pub get_chunk_missing: StatCounter,
    pub get_chunk_small: StatCounter,
    pub get_chunk_large: StatCounter,
    pub get_chunk_bytes: StatCounter,
    pub delete_root_count: StatCounter,
    pub put_root_count: StatCounter,
    pub get_roots_count: StatCounter,
    pub get_status_count: StatCounter,
    pub list_chunks_count: StatCounter,
    pub list_chunks_entries: StatCounter,
    pub delete_chunks_count: StatCounter,
    pub chunks_deleted: StatCounter,
    pub delete_chunk_count: StatCounter,
    pub start_time: std::time::SystemTime,
}

/// The state passed around the variaus methods
pub struct State {
    pub config: Config,
    pub conn: Mutex<Connection>,
    pub stat: Stat,
}

pub fn setup_db(conf: &Config) -> Connection {
    trace!("opening database");
    let conn = Connection::open(format!("{}/backup.db", conf.data_dir))
        .expect("Unable to open hash cache");

    conn.pragma_update(None, "journal_mode", "WAL")
        .expect("Cannot enable wal");

    trace!("Creating chunks table");
    // The chunks table contains metadata for all chunks
    conn.execute(
        "CREATE TABLE IF NOT EXISTS chunks (
             id INTEGER PRIMARY KEY,
             bucket TEXT NOT NULL,
             hash TEXT NOT NULL,
             size INTEGER NOT NULL,
             time INTEGER NOT NULL,
             has_content BOOLEAN NOT NULL
             )",
        [],
    )
    .expect("Unable to create cache table");

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_bucket_hash
        ON chunks (bucket,hash)",
        [],
    )
    .expect("Unable to create cache table index");

    // The chunk_content table contains data for small chunks
    conn.execute(
        "CREATE TABLE IF NOT EXISTS chunk_content (
             chunk_id INTEGER PRIMARY KEY,
             content BLOB
             )",
        [],
    )
    .expect("Unable to create cache table");

    trace!("Creating roots table");
    // The roots table records the root of the merkel tree of all backups
    conn.execute(
        "CREATE TABLE IF NOT EXISTS roots (
             id INTEGER PRIMARY KEY,
             bucket TEXT NOT NULL,
             host TEXT NOT NULL,
             time INTEGER NOT NULL,
             hash TEXT NOT NULL
             )",
        [],
    )
    .expect("Unable to create cache table");

    trace!("Creating deletes table");
    conn.execute(
        "CREATE TABLE IF NOT EXISTS deletes (
             bucket TEXT NOT NULL UNIQUE,
             time INTEGER NOT NULL
             )",
        [],
    )
    .expect("Unable to deletes cache table");

    conn
}
