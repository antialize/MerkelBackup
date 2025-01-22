use rusqlite::Connection;

pub fn main() -> () {
    unsafe {libc::clearenv();}
    let conn = Connection::open("/ssd/merkelbackupserver/backup.db").expect("Unable to open database /ssd/merkelbackupserver/backup.d");
    conn.pragma_update(None, "wal_checkpoint", "TRUNCATE").expect("Unable to flush wal");
}