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
use crypto::symmetriccipher::SynchronousStreamCipher;
use std::time::SystemTime;
extern crate hex;

const CHUNK_SIZE: u64 = 64 * 1024 * 1024;

extern crate reqwest;

struct State {
    bucket: [u8; 32],
    seed: [u8; 32],
    key: [u8; 32],
    iv: [u8; 32],
    host: String,
    conn: Connection,
    recheck: bool,
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
    hasher.input(&state.seed);
    hasher.input(content);
    let hash = hasher.result_str().to_string();

    let url = format!(
        "{}/chunks/{}/{}",
        state.host,
        hex::encode(&state.bucket),
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
        crypto::chacha20::ChaCha20::new(&state.key, &state.iv[0..12])
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
    if !state.recheck {
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

fn derive_secrets(
    password: &str,
    bucket: &mut [u8],
    key: &mut [u8],
    seed: &mut [u8],
    iv: &mut [u8],
) {
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
    bucket.copy_from_slice(&data[0..W]);
    seed.copy_from_slice(&data[128..128 + W]);
    iv.copy_from_slice(&data[1024..1024 + W]);
    key.copy_from_slice(&data[(ITEMS - 1) * W..]);
}

fn main() {
    simple_logger::init_with_level(log::Level::Info).expect("Unable to init log");
    info!("Derive secret!!\n");
    let mut bucket = [0; 32];
    let mut seed = [0; 32];
    let mut key = [0; 32];
    let mut iv = [0; 32];
    derive_secrets("hunter2", &mut bucket, &mut key, &mut seed, &mut iv);
    info!("Derive secret!!\n");

    let conn = Connection::open("cache.db").expect("Unable to open hash cache");
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
        bucket: bucket,
        seed: seed,
        key: key,
        iv: iv,
        host: "http://localhost:3321".to_string(),
        conn: conn,
        recheck: false,
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
