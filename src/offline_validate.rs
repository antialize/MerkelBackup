use rusqlite::{params, Connection};

fn main() {
    let conn = Connection::open("backup.db").expect("Unable to open hash cache");
    conn.pragma_update(None, "journal_mode", "WAL")
        .expect("Cannot enable wal");

    let mut stmt0 = conn
        .prepare("SELECT MAX(_ROWID_) FROM chunks")
        .expect("Unable to query row count");
    let max_id: usize = stmt0
        .query_row(params![], |row| row.get(0))
        .expect("Unable to get count");

    let mut stmt = conn
        .prepare("SELECT id, hash, size, has_content, bucket FROM chunks")
        .expect("HAPS");

    let mut stmt2 = conn
        .prepare("SELECT length(content) FROM chunk_content WHERE chunk_id=?")
        .expect("HAPS");

    let iter = stmt
        .query_map(params![], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })
        .expect("ok");

    let mut cnt: u64 = 0;
    let mut bytes: u64 = 0;

    for row in iter {
        let (id, hash, size, has_content, bucket): (u64, String, u64, bool, String) =
            row.expect("Bad row");
        cnt += 1;
        if (cnt & 255) == 0 {
            println!(
                "cnt: {}, size: {}Gb, id: {}/{}",
                cnt,
                bytes / 1024 / 1024 / 1024,
                id,
                max_id
            );
        }
        if has_content {
            let row: Result<u64, _> = stmt2.query_row(params![id], |v| v.get(0));
            match row {
                Ok(found_size) => {
                    if size != found_size {
                        println!("Object {id} {hash} of size {size} internal content is wrong size {found_size}");
                    }
                }
                Err(_) => {
                    println!("Object {id} {hash} of size {size} internal content is missing");
                }
            }
        } else {
            let path = format!("data/{}/{}/{}", bucket, &hash[..2], &hash[2..]);
            match std::fs::metadata(&path) {
                Ok(s) => {
                    if s.len() != size {
                        println!(
                            "Object {} {} of size {} internal content is wrong size {} at {}",
                            id,
                            hash,
                            size,
                            s.len(),
                            path
                        );
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    println!("Object {id} {hash} of size {size} not found at {path}");
                }
                Err(e) => {
                    println!("Object {id} {hash} of size {size} stat failed {e:?} at {path}");
                }
            }
        }
        bytes += size;
    }
}
