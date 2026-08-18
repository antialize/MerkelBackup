use rusqlite::Connection;
use rusqlite::OptionalExtension;
use std::collections::HashMap;
use std::sync::RwLock;
use std::sync::{Arc, Mutex};

use crate::config::Config;
use crate::read_pool::ReadConnectionPool;

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
    pub delete_status_count: StatCounter,
    pub get_deleted_count: StatCounter,
    pub get_deleted_entries: StatCounter,
    pub list_chunks_count: StatCounter,
    pub list_chunks_entries: StatCounter,
    pub delete_chunks_count: StatCounter,
    pub chunks_deleted: StatCounter,
    pub delete_chunk_count: StatCounter,
    pub has_chunks_count: StatCounter,
    pub put_chunks_count: StatCounter,
    pub start_time: std::time::SystemTime,
}

/// The state passed around the variaus methods
pub struct State {
    pub config: Config,
    /// Write connection. Holds the exclusive writer lock and is used for all mutating handlers.
    pub conn: Mutex<Connection>,
    /// Read-only connection. WAL mode allows this to run concurrently with the writer.
    /// Used by read-only handlers (has_chunks, get_chunk, get_status, get_roots, list_chunks).
    pub read_pool: Arc<ReadConnectionPool>,
    pub buckets: RwLock<HashMap<String, i64>>,
    pub stat: Stat,
}

/// Page cache for the single writer connection, in KiB (negative `cache_size` means KiB rather
/// than pages).
pub const WRITER_CACHE_KIB: i64 = -4 * 1024 * 1024;

/// Page cache for each of the read pool connections, in KiB. There are 16 of them, so this is
/// ~4 GiB total; the memory mapped region is shared with the OS page cache on top of that.
pub const READER_CACHE_KIB: i64 = -256 * 1024;

/// Size of the memory mapped region, in bytes. Reads are then served straight out of the OS
/// page cache with no copy into a per-connection buffer. Shared across connections, so setting
/// it large on all 16 readers costs nothing extra.
pub const MMAP_BYTES: i64 = 16 * 1024 * 1024 * 1024;

/// Apply the shared performance pragmas to a connection. `cache_kib` is a negative `cache_size`
/// value (KiB). Called on both the writer and every read pool connection.
pub fn tune_connection(conn: &Connection, cache_kib: i64) {
    conn.pragma_update(None, "cache_size", cache_kib)
        .expect("Cannot set cache_size");
    conn.pragma_update(None, "mmap_size", MMAP_BYTES)
        .expect("Cannot set mmap_size");
    // Sorts and temp b-trees (e.g. the ORDER BY in the deleted-list query) stay in RAM.
    conn.pragma_update(None, "temp_store", "MEMORY")
        .expect("Cannot set temp_store");
    conn.busy_timeout(std::time::Duration::from_secs(30))
        .expect("Cannot set busy_timeout");
}

/// One-time migration of the `chunks` table from a 64 character hex `bucket` string to a small
/// integer `buckets.id`. There are only a handful of distinct buckets, so storing an integer
/// per row instead of a 64 byte string roughly halves the giant `idx_bucket_hash` index and
/// removes ~64 bytes per row from the table. Rebuilds the table (preserving `id`, so the
/// `chunk_content.chunk_id` relationship stays valid) rather than adding a column, which also
/// compacts it and drops the old fat index in one pass. No-op on a fresh or already-migrated DB.
fn migrate_chunks_bucket_to_id(conn: &Connection) {
    let bucket_type: Option<String> = conn
        .query_row(
            "SELECT type FROM pragma_table_info('chunks') WHERE name = 'bucket'",
            [],
            |row| row.get(0),
        )
        .optional()
        .expect("Unable to inspect chunks schema");
    match bucket_type.as_deref() {
        None => return,            // no chunks table yet (fresh DB)
        Some("INTEGER") => return, // already migrated to INTEGER
        Some("TEXT") => {}         // legacy schema, needs migration
        Some(t) => {
            panic!("Unexpected chunks.bucket type {t}");
        }
    }
    info!("Migrating chunks.bucket from hex string to integer id; this may take a few minutes");
    conn.execute_batch(
        "BEGIN;
         INSERT OR IGNORE INTO buckets (bucket) SELECT DISTINCT bucket FROM chunks;
         CREATE TABLE chunks_new (
             id INTEGER PRIMARY KEY,
             bucket INTEGER NOT NULL,
             hash TEXT NOT NULL,
             size INTEGER NOT NULL,
             time INTEGER NOT NULL,
             has_content BOOLEAN NOT NULL
         );
         INSERT INTO chunks_new (id, bucket, hash, size, time, has_content)
             SELECT c.id, b.id, c.hash, c.size, c.time, c.has_content
             FROM chunks c JOIN buckets b ON b.bucket = c.bucket;
         DROP TABLE chunks;
         ALTER TABLE chunks_new RENAME TO chunks;
         CREATE INDEX IF NOT EXISTS idx_bucket_hash ON chunks (bucket, hash);
         COMMIT;",
    )
    .expect("chunks bucket migration failed");
    info!("Migration of chunks.bucket complete");
}

pub fn setup_db(conf: &Config) -> Connection {
    trace!("opening database");
    let conn = Connection::open(format!("{}/backup.db", conf.data_dir))
        .expect("Unable to open hash cache");

    conn.pragma_update(None, "journal_mode", "WAL")
        .expect("Cannot enable wal");
    tune_connection(&conn, WRITER_CACHE_KIB);
    // WAL + NORMAL only risks losing the last committed transaction on power loss, never
    // corruption, and avoids an fsync per commit. Only meaningful on the writer.
    conn.pragma_update(None, "synchronous", "NORMAL")
        .expect("Cannot set synchronous");

    trace!("Creating buckets table");
    // Maps a bucket to a small integer id, so the huge chunks table and its index (and the
    // tombstone log) store a 1-byte integer per row rather than the 64 character hex string.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS buckets (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             bucket TEXT NOT NULL UNIQUE
             )",
        [],
    )
    .expect("Unable to create buckets table");

    // Convert a legacy text-bucket chunks table to the integer id schema, if present.
    migrate_chunks_bucket_to_id(&conn);

    trace!("Creating chunks table");
    // The chunks table contains metadata for all chunks. `bucket` is a `buckets.id`, not the
    // hex string; see migrate_chunks_bucket_to_id.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS chunks (
             id INTEGER PRIMARY KEY,
             bucket INTEGER NOT NULL,
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

    trace!("Creating deleted table");
    // Tombstone log. `prefix` holds the top 64 bits of the deleted chunk hash, bit cast to i64;
    // ordering is done in memory when serving, so the sign does not matter. AUTOINCREMENT rather
    // than a plain rowid, because retention deletes from the front and plain rowids would be
    // reused once the table is emptied, breaking client watermarks.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS deleted (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             bucket INTEGER NOT NULL,
             prefix INTEGER NOT NULL
             )",
        [],
    )
    .expect("Unable to create deleted table");

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_deleted_bucket_id
        ON deleted (bucket,id)",
        [],
    )
    .expect("Unable to create deleted table index");

    // The oldest watermark a client may present and still be served incrementally. Rises only
    // when tombstones are garbage collected; absent means the whole log is still intact.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS deleted_floor (
             bucket INTEGER PRIMARY KEY,
             floor INTEGER NOT NULL
             )",
        [],
    )
    .expect("Unable to create deleted_floor table");

    conn
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;

    #[test]
    fn migrate_bucket_to_id_preserves_ids_and_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE buckets (id INTEGER PRIMARY KEY AUTOINCREMENT, bucket TEXT NOT NULL UNIQUE);
             CREATE TABLE chunks (id INTEGER PRIMARY KEY, bucket TEXT NOT NULL, hash TEXT NOT NULL,
                 size INTEGER NOT NULL, time INTEGER NOT NULL, has_content BOOLEAN NOT NULL);
             CREATE TABLE chunk_content (chunk_id INTEGER PRIMARY KEY, content BLOB);",
        )
        .unwrap();
        let bkt_a = "a".repeat(64);
        let bkt_b = "b".repeat(64);
        // Non-contiguous ids, to prove they survive the rebuild (chunk_content depends on them).
        conn.execute(
            "INSERT INTO chunks (id, bucket, hash, size, time, has_content) VALUES (1, ?, ?, 10, 0, 1)",
            params![bkt_a, "h1"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO chunks (id, bucket, hash, size, time, has_content) VALUES (2, ?, ?, 20, 0, 0)",
            params![bkt_a, "h2"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO chunks (id, bucket, hash, size, time, has_content) VALUES (5, ?, ?, 30, 0, 1)",
            params![bkt_b, "h3"],
        )
        .unwrap();

        migrate_chunks_bucket_to_id(&conn);

        let coltype: String = conn
            .query_row(
                "SELECT type FROM pragma_table_info('chunks') WHERE name = 'bucket'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(coltype, "INTEGER");

        let a_id: i64 = conn
            .query_row(
                "SELECT id FROM buckets WHERE bucket = ?",
                params![bkt_a],
                |r| r.get(0),
            )
            .unwrap();
        let bucket_of_1: i64 = conn
            .query_row("SELECT bucket FROM chunks WHERE id = 1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(bucket_of_1, a_id);
        let bucket_of_5_hash: String = conn
            .query_row("SELECT hash FROM chunks WHERE id = 5", [], |r| r.get(0))
            .unwrap();
        assert_eq!(bucket_of_5_hash, "h3");
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM chunks", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 3);

        // Running again must be a no-op, not a second migration.
        migrate_chunks_bucket_to_id(&conn);
        let count_after: i64 = conn
            .query_row("SELECT COUNT(*) FROM chunks", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count_after, 3);
    }
}
