use rusqlite::{Connection, NO_PARAMS};
use std::sync::Mutex;

use crate::config::Config;

/// The state passed around the variaus methods
pub struct State {
    pub config: Config,
    pub conn: Mutex<Connection>,
}

pub fn setup_db(conf: &Config) -> Connection {
    trace!("opening database");
    let conn = Connection::open(format!("{}/backup.db", conf.data_dir))
        .expect("Unable to open hash cache");

    conn.pragma_update(None, "journal_mode", &"WAL".to_string())
        .expect("Cannot enable wal");

    trace!("Creating chunks table");
    // The chunks table contains metadata for all chunks
    // and the content of small chunks
    conn.execute(
        "CREATE TABLE IF NOT EXISTS chunks (
             id INTEGER PRIMARY KEY,
             bucket TEXT NOT NULL,
             hash TEXT NOT NULL,
             size INTEGER NOT NULL,
             time INTEGER NOT NULL,
             content BLOB
             )",
        NO_PARAMS,
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
        NO_PARAMS,
    )
    .expect("Unable to create cache table");

    trace!("Creating deletes table");
    conn.execute(
        "CREATE TABLE IF NOT EXISTS deletes (
             bucket TEXT NOT NULL UNIQUE,
             time INTEGER NOT NULL
             )",
        NO_PARAMS,
    )
    .expect("Unable to deletes cache table");

    conn
}
