use crypto::blake2b::Blake2b;
use crypto::digest::Digest;
use crypto::symmetriccipher::SynchronousStreamCipher;
use pbr::ProgressBar;
use rusqlite::{params, Connection, Statement, NO_PARAMS};
use shared::{check_response, Config, Error, Secrets};
use std::fs;
use std::io::Read;
use std::path::Path;
use std::time::Duration;
use std::time::SystemTime;

const CHUNK_SIZE: u64 = 64 * 1024 * 1024;

struct State<'a> {
    secrets: Secrets,
    config: Config,
    client: reqwest::Client,
    scan: bool,
    transfer_bytes: u64,
    progress: Option<ProgressBar<std::io::Stdout>>,
    last_delete: i64,
    has_remote_stmt: Statement<'a>,
    update_remote_stmt: Statement<'a>,
    get_chunks_stmt: Statement<'a>,
    update_chunks_stmt: Statement<'a>,
}

fn has_chunk(chunk: &str, state: &mut State) -> Result<bool, Error> {
    let cnt: i64 = state
        .has_remote_stmt
        .query(params![chunk, state.last_delete])?
        .next()?
        .ok_or(Error::MissingRow())?
        .get(0)?;
    if cnt == 1 {
        return Ok(true);
    }

    let url = format!(
        "{}/chunks/{}/{}",
        &state.config.server,
        hex::encode(&state.secrets.bucket),
        &chunk
    );
    let res = state
        .client
        .head(&url[..])
        .basic_auth(&state.config.user, Some(&state.config.password))
        .send()?;
    match res.status() {
        reqwest::StatusCode::OK => Ok(true),
        reqwest::StatusCode::NOT_FOUND => Ok(false),
        code => Err(Error::HttpStatus(code)),
    }
}

fn push_chunk(content: &[u8], state: &mut State) -> Result<String, Error> {
    let mut hasher = Blake2b::new(256 / 8);
    hasher.input(&state.secrets.seed);
    hasher.input(content);
    let hash = hasher.result_str().to_string();

    if !has_chunk(&hash, state)? {
        let url = format!(
            "{}/chunks/{}/{}",
            &state.config.server,
            hex::encode(&state.secrets.bucket),
            &hash
        );

        let mut crypted = Vec::new();
        crypted.resize(content.len(), 0);
        crypto::chacha20::ChaCha20::new(&state.secrets.key, &state.secrets.iv[0..12])
            .process(content, &mut crypted);

        check_response(
            state
                .client
                .put(&url[..])
                .basic_auth(&state.config.user, Some(&state.config.password))
                .body(reqwest::Body::from(crypted))
                .send()?,
        )?;
    }

    state.update_remote_stmt.execute(params![hash])?;

    if let Some(p) = &mut state.progress {
        p.add(content.len() as u64);
    }
    return Ok(hash);
}

fn backup_file(path: &Path, size: u64, mtime: u64, state: &mut State) -> Result<String, Error> {
    let path_str = path.to_str().ok_or(Error::BadPath(path.to_path_buf()))?;
    if let Some(p) = &mut state.progress {
        p.message(path_str);
    }

    // IF the file is empty we just do nothing
    if size == 0 {
        return Ok("empty".to_string());
    }

    // Check if we have allready checked the file once
    if !state.config.recheck {
        let chunks: Option<String> = {
            let mut rows =
                state
                    .get_chunks_stmt
                    .query(params![path_str, size as i64, mtime as i64])?;
            match rows.next()? {
                Some(row) => row.get(0)?,
                None => None,
            }
        };
        if let Some(chunks) = chunks {
            let mut good = true;
            for chunk in chunks.split(',') {
                if !has_chunk(chunk, state)? {
                    good = false;
                    break;
                }
            }
            if good {
                return Ok(chunks);
            }
        }
    }

    if state.scan {
        state.transfer_bytes += size;
        return Ok("_".repeat((65 * (size + CHUNK_SIZE - 1) / CHUNK_SIZE - 1) as usize));
    }

    // Open the file and read each chunk
    let mut file = fs::File::open(&path)?;

    let mut buffer: Vec<u8> = Vec::new();
    buffer.resize(u64::min(size, CHUNK_SIZE) as usize, 0);
    let mut chunks = "".to_string();
    loop {
        let mut used = 0;
        while used < buffer.len() {
            let w = file.read(&mut buffer[used..])?;
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
        chunks.push_str(&push_chunk(&buffer[..used], state)?);

        if used != buffer.len() {
            break;
        }
    }

    //TODO check if the mtime has changed while we where pushing

    state.update_chunks_stmt.execute(params![
        &path.to_str().unwrap(),
        size as i64,
        mtime as i64,
        &chunks
    ])?;

    return Ok(chunks);
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DirEnt {
    name: String,
    type_: String,
    content: String,
}

fn push_ents(mut entries: Vec<DirEnt>, state: &mut State) -> Result<String, Error> {
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

fn backup_folder(dir: &Path, state: &mut State) -> Result<String, Error> {
    let raw_entries = fs::read_dir(dir)?;
    let mut entries: Vec<DirEnt> = Vec::new();
    for entry in raw_entries {
        let path = entry?.path();
        let md = fs::metadata(&path)?;
        let filename = path
            .file_name()
            .ok_or_else(|| Error::BadPath(path.to_path_buf()))?
            .to_str()
            .ok_or_else(|| Error::BadPath(path.to_path_buf()))?;
        if filename.contains("\0") || filename.contains("\x01") {
            return Err(Error::BadPath(path.to_path_buf()));
        }

        if md.is_dir() {
            entries.push(DirEnt {
                name: filename.to_string(),
                type_: "dir".to_string(),
                content: backup_folder(&path, state)?,
            });
        } else if md.is_file() {
            let mtime = md
                .modified()?
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            entries.push(DirEnt {
                name: filename.to_string(),
                type_: "file".to_string(),
                content: backup_file(&path, md.len(), mtime, state)?,
            });
        } else {

        }
    }
    if state.scan {
        state.transfer_bytes += bytes_ents(entries);
        return Ok("00000000000000000000000000000000".to_string());
    } else {
        return push_ents(entries, state);
    }
}

pub fn run(config: Config, secrets: Secrets) -> Result<(), Error> {
    let conn = Connection::open(&config.cache_db)?;

    conn.pragma_update(None, "journal_mode", &"WAL".to_string())?;

    conn.execute(
        "create table if not exists files (
            path text not null unique,
            size integer not null,
            mtime integer not null,
            chunks text not null
        )",
        NO_PARAMS,
    )?;

    conn.execute(
        "create table if not exists remote (
            chunk text not null unique,
            time integer not null
        )",
        NO_PARAMS,
    )?;

    let mut state = State {
        secrets,
        config,
        client: reqwest::Client::new(),
        scan: true,
        transfer_bytes: 0,
        progress: None,
        last_delete: 0,
        has_remote_stmt: conn
            .prepare("SELECT count(*) FROM remote WHERE chunk = ? AND time > ?")?,
        update_remote_stmt: conn
            .prepare("REPLACE INTO remote VALUES (?, strftime('%s', 'now'))")?,
        get_chunks_stmt: conn
            .prepare("SELECT chunks FROM files WHERE path = ? AND size = ? AND mtime = ?")?,
        update_chunks_stmt: conn
            .prepare("REPLACE INTO files (path, size, mtime, chunks) VALUES (?, ?, ?, ?)")?,
    };

    {
        let url = format!(
            "{}/status/{}",
            &state.config.server,
            hex::encode(&state.secrets.bucket)
        );

        state.last_delete = check_response(
            state
                .client
                .get(&url[..])
                .basic_auth(&state.config.user, Some(&state.config.password))
                .send()?,
        )?
        .text()?
        .parse()?
    }

    let dirs = state.config.backup_dirs.clone();
    for dir in dirs.iter() {
        info!("Scanning {}", &dir);
        backup_folder(Path::new(dir), &mut state)?;
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
            content: backup_folder(Path::new(dir), &mut state)?,
        });
    }

    info!("Storing root");
    let root = push_ents(entries, &mut state)?;

    let url = format!(
        "{}/roots/{}/{}",
        &state.config.server,
        hex::encode(&state.secrets.bucket),
        &state.config.hostname
    );

    check_response(
        state
            .client
            .put(&url[..])
            .basic_auth(&state.config.user, Some(&state.config.password))
            .body(root)
            .send()?,
    )?;
    Ok(())
}
