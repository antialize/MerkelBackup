//! A simple connection pool for read-only SQLite connections.
//! This is used to allow multiple concurrent read requests without blocking each other,
//! while still allowing the main thread to perform writes
use rusqlite::{Connection, OpenFlags};
use std::sync::{Arc, Condvar, Mutex};

use crate::config::Config;

/// A simple connection pool for read-only SQLite connections.
pub struct ReadConnectionPool {
    free: Mutex<Vec<Connection>>,
    free_cond: Condvar,
}

/// A connection acquired from the pool. When dropped, it will be returned to the pool.
pub struct ReadPoolConnection {
    conn: Option<Connection>,
    pool: Arc<ReadConnectionPool>,
}

impl std::ops::Deref for ReadPoolConnection {
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        self.conn.as_ref().unwrap()
    }
}

impl std::ops::DerefMut for ReadPoolConnection {
    fn deref_mut(&mut self) -> &mut Connection {
        self.conn.as_mut().unwrap()
    }
}

impl Drop for ReadPoolConnection {
    fn drop(&mut self) {
        let mut free = self.pool.free.lock().unwrap();
        free.push(self.conn.take().unwrap());
        self.pool.free_cond.notify_one();
    }
}

impl ReadConnectionPool {
    /// Acquire a connection from the pool, blocking if necessary until one is available.
    pub fn acquire(self: &Arc<Self>) -> ReadPoolConnection {
        let mut free = self.free.lock().unwrap();
        loop {
            if let Some(conn) = free.pop() {
                return ReadPoolConnection {
                    conn: Some(conn),
                    pool: self.clone(),
                };
            }
            free = self.free_cond.wait(free).unwrap();
        }
    }

    /// Create a new connection pool with the specified number of connections.
    pub fn new(conf: &Config, size: usize) -> Arc<Self> {
        let mut free = Vec::with_capacity(size);
        for _ in 0..size {
            let conn = Connection::open_with_flags(
                format!("{}/backup.db", conf.data_dir),
                OpenFlags::SQLITE_OPEN_READ_ONLY
                    | OpenFlags::SQLITE_OPEN_URI
                    | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .expect("Unable to open read-only connection");
            // Read-only connections cannot switch journal mode; they must verify the
            // database has already been configured to use WAL by a writable connection.
            let journal_mode: String = conn
                .pragma_query_value(None, "journal_mode", |row| row.get(0))
                .expect("Cannot read journal mode on read connection");
            if !journal_mode.eq_ignore_ascii_case("wal") {
                panic!(
                    "Read connection requires WAL mode, but database journal_mode is {}",
                    journal_mode
                );
            }
            free.push(conn);
        }
        Arc::new(Self {
            free: Mutex::new(free),
            free_cond: Condvar::new(),
        })
    }
}
