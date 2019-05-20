use std::fs;
use std::path::Path;
extern crate simple_logger;
use std::io::Read;

#[macro_use]
extern crate log;

extern crate crypto;
extern crate rusqlite;

use rusqlite::{params, Connection, NO_PARAMS};

use crypto::blake2b::Blake2b;
use crypto::digest::Digest;
use std::time::SystemTime;
const CHUNK_SIZE: u64 = 64 * 1024 * 1024;

fn push_chunk(content: &[u8]) -> String {
    let mut hasher = Blake2b::new(256 / 8);
    //TODO seed with key derived value
    hasher.input(content);

    //TODO try to send the content to remote server if it is not in the bloom filter

    return hasher.result_str().to_string();
}

fn backup_file(path: &Path, size: u64, mtime: u64, conn: &Connection) -> Option<String> {
    // IF the file is empty we just do nothing
    if size == 0 {
        return Some("".to_string());
    }

    // Check if we have allready checked the file once
    // TODO jakob: One should be able to recheck everything with a commandline switch
    let mut stmt = conn
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
        chunks.push_str(&push_chunk(&buffer[..used]));

        if used != buffer.len() {
            break;
        }
    }

    //TODO check if the mtime has changed while we where pushing

    conn.execute(
        "REPLACE INTO files (path, size, mtime, chunks) VALUES (?, ?, ?, ?)",
        params![&path.to_str().unwrap(), size as i64, mtime as i64, &chunks],
    )
    .expect("insert failed");

    //info!("Visited file {:?}: {}", path, chunks);
    return None;
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DirEnt {
    name: String,
    type_: String,
    content: String,
}

fn push_ents(mut ents: Vec<DirEnt>) -> String {
    ents.sort();
    let mut ans = "".to_string();
    for ent in ents {
        if !ans.is_empty() {
            ans.push('\0');
        }
        ans.push_str(&ent.name);
        ans.push('\x01');
        ans.push_str(&ent.type_);
        ans.push('\x01');
        ans.push_str(&ent.content);
    }
    return push_chunk(ans.as_bytes());
}

fn backup_folder(dir: &Path, conn: &Connection) -> Option<String> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) => {
            warn!("Unable to list dir {:?}: {:?}", dir, error);
            return None;
        }
    };

    let mut ents: Vec<DirEnt> = Vec::new();

    for entry in entries {
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
            match backup_folder(&path, conn) {
                Some(chunks) => ents.push(DirEnt {
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
            let chunks = match backup_file(&path, md.len(), mtime, conn) {
                Some(chunks) => chunks,
                None => continue,
            };
            ents.push(DirEnt {
                name: filename.to_string(),
                type_: "file".to_string(),
                content: chunks,
            });
        } else {

        }
    }
    return Some(push_ents(ents));
}

fn derive_secrets(password: &str, root: &mut [u8], key: &mut [u8], seed: &mut [u8], iv: &mut [u8]) {
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
    root.copy_from_slice(&data[0..64]);
    seed.copy_from_slice(&data[128..128 + 64]);
    iv.copy_from_slice(&data[1024..1024 + 64]);
    key.copy_from_slice(&data[(ITEMS - 1) * 64..]);
}

fn main() {
    simple_logger::init().expect("Unable to init log");
    info!("Derive secret!!\n");
    let mut root = [0; 32];
    let mut seed = [0; 32];
    let mut key = [0; 32];
    let mut iv = [0; 32];
    derive_secrets("hunter2", &mut root, &mut key, &mut seed, &mut iv);
    info!("Derive secret!!\n");

    let conn = Connection::open("cache.db").expect("Unable to open hash cache");
    conn.pragma_update(None, "journal_mode", &"WAL".to_string()).expect("Cannot enable wal");

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

    info!("Backup started");
    info!(
        "Root item {}",
        backup_folder(Path::new("/home/test/test"), &conn).unwrap()
    );
}
