use crypto::blake2b::Blake2b;
use crypto::digest::Digest;
use crypto::symmetriccipher::SynchronousStreamCipher;
use pbr::ProgressBar;
use rusqlite::{params, Connection, NO_PARAMS};
use shared::{Config, Secrets};
use std::fs;
use std::io::Read;
use std::path::Path;
use std::time::Duration;
use std::time::SystemTime;

const CHUNK_SIZE: u64 = 64 * 1024 * 1024;

struct State {
    secrets: Secrets,
    config: Config,
    conn: Connection,
    client: reqwest::Client,
    scan: bool,
    transfer_bytes: u64,
    progress: Option<ProgressBar<std::io::Stdout>>,
    last_delete: i64,
}

fn push_chunk(content: &[u8], state: &mut State) -> String {
    let mut hasher = Blake2b::new(256 / 8);
    hasher.input(&state.secrets.seed);
    hasher.input(content);
    let hash = hasher.result_str().to_string();

    let mut stmt = state
        .conn
        .prepare("SELECT count(*) FROM remote WHERE chunk = ? AND time > ?")
        .unwrap();
    let cnt: i64 = stmt
        .query(params![hash, state.last_delete])
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap();
    if cnt == 1 {
        return hash;
    }

    let url = format!(
        "{}/chunks/{}/{}",
        &state.config.server,
        hex::encode(&state.secrets.bucket),
        &hash
    );
    let res = state
        .client
        .head(&url[..])
        .basic_auth(&state.config.user, Some(&state.config.password))
        .send()
        .expect("Head failed");
    let send = match res.status() {
        reqwest::StatusCode::OK => false,
        reqwest::StatusCode::NOT_FOUND => true,
        code => panic!("Upload of chunk failed {:?}", code),
    };

    if send {
        let mut crypted = Vec::new();
        crypted.resize(content.len(), 0);
        crypto::chacha20::ChaCha20::new(&state.secrets.key, &state.secrets.iv[0..12])
            .process(content, &mut crypted);

        let res = state
            .client
            .put(&url[..])
            .basic_auth(&state.config.user, Some(&state.config.password))
            .body(reqwest::Body::from(crypted))
            .send()
            .expect("Send failed");
        if res.status() != reqwest::StatusCode::OK {
            panic!("Upload of chunk failed {:?}", res.status())
        }
    }

    let mut stmt = state
        .conn
        .prepare("REPLACE INTO remote VALUES (?, strftime('%s', 'now'))")
        .unwrap();
    stmt.query(params![hash]).unwrap();

    if let Some(p) = &mut state.progress {
        p.add(content.len() as u64);
    }
    return hash;
}

fn backup_file(path: &Path, size: u64, mtime: u64, state: &mut State) -> Option<String> {
    if let Some(p) = &mut state.progress {
        p.message(path.to_str().unwrap_or(""))
    }

    // IF the file is empty we just do nothing
    if size == 0 {
        return Some("empty".to_string());
    }

    // Check if we have allready checked the file once
    if !state.config.recheck {
        let mut stmt = state
            .conn
            .prepare("SELECT chunks FROM files WHERE path = ? AND size = ? AND mtime = ?")
            .unwrap();
        let mut rows = stmt
            .query(params![path.to_str().unwrap(), size as i64, mtime as i64])
            .unwrap();
        if let Some(row) = rows.next().unwrap() {
            let s: String = row.get(0).expect("chunks should not be null");
            let mut good = true;
            let mut stmt = state
                .conn
                .prepare("SELECT count(*) FROM remote WHERE chunk = ? AND time > ?")
                .unwrap();

            for chunk in s.split(',') {
                let cnt: i64 = stmt
                    .query(params![chunk, state.last_delete])
                    .unwrap()
                    .next()
                    .unwrap()
                    .unwrap()
                    .get(0)
                    .unwrap();
                if cnt == 0 {
                    good = false;
                }
            }
            if (good) {
                return Some(s);
            }
        }
    }

    if state.scan {
        state.transfer_bytes += size;
        return Some("_".repeat((65 * (size + CHUNK_SIZE - 1) / CHUNK_SIZE - 1) as usize));
    }

    // Open the file and read each chunk
    let mut file = match fs::File::open(&path) {
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
            ans.push('\0');
        }
        ans.push_str(&ent.name);
        ans.push('\0');
        ans.push_str(&ent.type_);
        ans.push('\0');
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
                    type_: "dir".to_string(),
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
        state.transfer_bytes += bytes_ents(entries);
        return Some("00000000000000000000000000000000".to_string());
    } else {
        return Some(push_ents(entries, state));
    }
}

pub fn run(config: Config, secrets: Secrets) {
    let conn = Connection::open(&config.cache_db).expect("Unable to open hash cache");
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

        conn.execute(
            "create table if not exists remote (
                chunk text not null unique,
                time integer not null
            )",
            NO_PARAMS,
        )
        .expect("Unable to create cache table");
    }

    let mut state = State {
        secrets: secrets,
        config: config,
        conn: conn,
        client: reqwest::Client::new(),
        scan: true,
        transfer_bytes: 0,
        progress: None,
        last_delete: 0,
    };

    {
        let url = format!(
            "{}/status/{}",
            &state.config.server,
            hex::encode(&state.secrets.bucket)
        );
        let mut res = state
            .client
            .get(&url[..])
            .basic_auth(&state.config.user, Some(&state.config.password))
            .send()
            .expect("Head failed");

        if res.status() != reqwest::StatusCode::OK {
            panic!("Uanble to get status, {}", res.status());
        }
        state.last_delete = res.text().expect("utf-8").parse().expect("Bad time");
    }

    let dirs = state.config.backup_dirs.clone();
    for dir in dirs.iter() {
        info!("Scanning {}", &dir);
        backup_folder(Path::new(dir), &mut state).unwrap();
    }

    state.progress = Some({
        let mut p = ProgressBar::new(state.transfer_bytes);
        p.set_max_refresh_rate(Some(Duration::from_millis(500)));
        p.set_units(pbr::Units::Bytes);
        p
    });

    let mut entries: Vec<DirEnt> = Vec::new();
    state.scan = false;
    for dir in dirs.iter() {
        info!("Backing up {}", &dir);
        entries.push(DirEnt {
            name: dir.to_string(),
            type_: "dir".to_string(),
            content: backup_folder(Path::new(dir), &mut state).unwrap(),
        });
    }

    info!("Storing root");
    let root = push_ents(entries, &mut state);

    let url = format!(
        "{}/roots/{}/{}",
        &state.config.server,
        hex::encode(&state.secrets.bucket),
        &state.config.hostname
    );

    let res = state
        .client
        .put(&url[..])
        .basic_auth(&state.config.user, Some(&state.config.password))
        .body(root)
        .send()
        .expect("Send failed");
    if res.status() != reqwest::StatusCode::OK {
        panic!("Put root failed {}", res.status())
    }
}
