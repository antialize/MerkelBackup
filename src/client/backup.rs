use std::fs;
use std::io::Read;
use std::os::linux::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;
use std::time::SystemTime;

use crate::shared::Level;
use crate::shared::{Config, EType, Error, Secrets, check_response, retry};
use abi_stable::sabi_trait::TD_Opaque;
use abi_stable::std_types::RBoxError;
use abi_stable::std_types::RCowStr;
use abi_stable::std_types::ROption;
use abi_stable::std_types::ROption::RNone;
use abi_stable::std_types::ROption::RSome;
use abi_stable::std_types::RResult::RErr;
use abi_stable::std_types::RResult::ROk;
use abi_stable::std_types::RSlice;
use abi_stable::std_types::RStr;
use abi_stable::std_types::RString;
use blake2::Digest;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use log::debug;
use log::error;
use log::info;
use merkel_backup_plugin::BackupContext;
use merkel_backup_plugin::BackupContextRef;
use merkel_backup_plugin::Chunks;
use merkel_backup_plugin::PluginBox;
use pbr::ProgressBar;
use rand::TryRng;
use rand::rngs::SysRng;
use rusqlite::{Connection, Statement, params};

use merkel_backup_plugin::Result as PResult;

const CHUNK_SIZE: u64 = 64 * 1024 * 1024;
// Chunks with an encrypted size below this threshold are deferred and sent
// via the batch PUT /chunks/{bucket} endpoint instead of individual PUTs.
// The server stores chunks below its own SMALL_SIZE in SQLite and larger ones
// on disk; the batch endpoint handles both, so this threshold is independent.
const BATCH_UPLOAD_MAX_ENCRYPTED: usize = 64 * 1024 + 12;
// Flush the pending batch whenever this many bytes have accumulated.
const BATCH_FLUSH_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DirEnt {
    path: String,
    etype: EType,
    content: String,
    size: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: i64,
    ctime: i64,
}

struct State<'a> {
    secrets: Secrets,
    config: Config,
    client: reqwest::blocking::Client,
    scan: bool,
    transfer_bytes: u64,
    progress: Option<ProgressBar<std::io::Stdout>>,
    has_remote_stmt: Statement<'a>,
    update_remote_stmt: Statement<'a>,
    get_chunks_stmt: Statement<'a>,
    get_chunks_unsized_stmt: Statement<'a>,
    update_chunks_stmt: Statement<'a>,
    rng: SysRng,
    entries: Vec<DirEnt>,
    modified_files_count: u64,
    transfered_bytes: usize,
    skipped_bytes: usize,
    conflict_bytes: usize,
    plugin: RCowStr<'static>,
    plugin_name: RCowStr<'static>,
    plugin_entries: Vec<String>,
    pending_verify: std::collections::HashSet<String>,
    /// Encrypted small chunks deferred for batch upload: hash -> (encrypted_data, original_content_len)
    pending_small_uploads: std::collections::HashMap<String, (Vec<u8>, usize)>,
    pending_small_size: usize,
}

#[derive(PartialEq)]
enum HasChunkResult {
    YesCached,
    Yes,
    No,
}

fn has_chunk(chunk: &str, state: &mut State, size: Option<usize>) -> Result<HasChunkResult, Error> {
    let cnt: i64 = state
        .has_remote_stmt
        .query(params![chunk])?
        .next()?
        .ok_or(Error::MissingRow())?
        .get(0)?;
    if cnt == 1 {
        return Ok(HasChunkResult::YesCached);
    }

    // For small chunks it is quicker to just reupload
    if let Some(size) = size
        && size < 1024 * 16
    {
        return Ok(HasChunkResult::No);
    }

    let url = format!(
        "{}/chunks/{}/{}",
        &state.config.server,
        hex::encode(state.secrets.bucket),
        &chunk
    );
    let res = retry(&mut || {
        state
            .client
            .head(&url[..])
            .basic_auth(&state.config.user, Some(&state.config.password))
            .send()
    })?;
    match res.status() {
        reqwest::StatusCode::OK => Ok(HasChunkResult::Yes),
        reqwest::StatusCode::NOT_FOUND => Ok(HasChunkResult::No),
        code => Err(Error::HttpStatus(code)),
    }
}

/// Result of a has_chunks_remote() call: the subset of queried chunks that were found to exist on the server.
struct ChunksResult(String);
/// Iterator over the individual chunk hashes in a ChunksResult.
struct ChunksResultIter<'a>(&'a str);

impl ChunksResult {
    /// Split the result string into individual chunk hashes.
    fn iter<'a>(&'a self) -> ChunksResultIter<'a> {
        ChunksResultIter(&self.0)
    }
}

impl<'a> Iterator for ChunksResultIter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            return None;
        }
        if let Some((f, r)) = self.0.split_once('\0') {
            self.0 = r;
            Some(f)
        } else {
            let item = self.0;
            self.0 = "";
            Some(item)
        }
    }
}

/// Check whether all chunks from `chunks` exist on the server in a single HTTP request.
/// Returns the subset of `chunks` that were found to exist on the server.
fn has_chunks_remote(chunks: &[&str], state: &mut State) -> Result<ChunksResult, Error> {
    debug_assert!(!chunks.is_empty());
    let url = format!(
        "{}/chunks/{}",
        &state.config.server,
        hex::encode(state.secrets.bucket),
    );
    let body = chunks.join("\0");
    let res = retry(&mut || {
        state
            .client
            .post(&url)
            .basic_auth(&state.config.user, Some(&state.config.password))
            .body(body.clone())
            .send()
    })?;
    match res.status() {
        reqwest::StatusCode::OK => {
            let text = res.text()?;
            Ok(ChunksResult(text))
        }
        code => Err(Error::HttpStatus(code)),
    }
}

impl<'a> State<'a> {
    fn get_chunks_impl(
        &mut self,
        path: &str,
        size: Option<i64>,
        mtime: i64,
    ) -> Result<Option<Chunks>, Error> {
        if self.config.recheck {
            return Ok(None);
        };
        let path = format!("@{}/{}/{}", self.plugin, self.plugin_name, path);
        let chunks = if let Some(size) = size {
            let mut rows = self.get_chunks_stmt.query(params![path, size, mtime])?;
            match rows.next()? {
                Some(row) => {
                    let chunks: String = row.get(0)?;
                    Some(Chunks {
                        chunks: chunks.into(),
                        size,
                    })
                }
                None => None,
            }
        } else {
            let mut rows = self.get_chunks_unsized_stmt.query(params![path, mtime])?;
            match rows.next()? {
                Some(row) => {
                    let chunks: String = row.get(0)?;
                    let size: i64 = row.get(1)?;
                    Some(Chunks {
                        chunks: chunks.into(),
                        size,
                    })
                }
                None => None,
            }
        };
        Ok(chunks)
    }
}

impl<'a> BackupContext for State<'a> {
    fn chunk_size(&self) -> usize {
        CHUNK_SIZE as usize
    }

    fn get_chunks(
        &mut self,
        path: RStr,
        size: ROption<i64>,
        mtime: i64,
    ) -> PResult<ROption<Chunks>> {
        match self.get_chunks_impl(path.as_str(), size.into_option(), mtime) {
            Ok(Some(v)) => ROk(RSome(v)),
            Ok(None) => ROk(RNone),
            Err(e) => RErr(RBoxError::new(e)),
        }
    }

    fn has_chunks(&mut self, chunks: RStr) -> PResult<bool> {
        let chunk_list: Vec<&str> = chunks.split(",").collect();
        let mut uncached: Vec<&str> = Vec::new();
        for &chunk in &chunk_list {
            let mut rows = match self.has_remote_stmt.query(params![chunk]) {
                Ok(r) => r,
                Err(e) => return RErr(RBoxError::new(Error::Sql(e))),
            };
            let cnt: i64 = match rows.next() {
                Err(e) => return RErr(RBoxError::new(Error::Sql(e))),
                Ok(None) => return RErr(RBoxError::new(Error::MissingRow())),
                Ok(Some(row)) => match row.get(0) {
                    Ok(v) => v,
                    Err(e) => return RErr(RBoxError::new(Error::Sql(e))),
                },
            };
            if cnt == 0 {
                uncached.push(chunk);
            }
        }
        if uncached.is_empty() {
            return ROk(true);
        }
        if self.scan {
            for c in &uncached {
                self.pending_verify.insert(c.to_string());
            }
            return ROk(true); // optimistic during scan; verified in batch after scan completes
        }
        match has_chunks_remote(&uncached, self) {
            Ok(r) => ROk(r.iter().count() == uncached.len()),
            Err(e) => RErr(RBoxError::new(e)),
        }
    }

    fn push_chunk(&mut self, content: RSlice<u8>) -> PResult<RString> {
        match push_chunk(content.as_slice(), self) {
            Ok(v) => ROk(v.into()),
            Err(e) => RErr(RBoxError::new(e)),
        }
    }

    fn add_entry(&mut self, line: RStr) -> PResult<()> {
        self.plugin_entries
            .push(format!("@{}\0{}\0{}", self.plugin, self.plugin_name, line));
        ROk(())
    }

    fn update_chunks(&mut self, path: RStr, size: i64, mtime: i64, chunks: RStr) -> PResult<()> {
        let path = format!("@{}/{}/{}", self.plugin, self.plugin_name, path);
        match self
            .update_chunks_stmt
            .execute(params![path.as_str(), size, mtime, chunks.as_str()])
        {
            Ok(_) => ROk(()),
            Err(e) => RErr(RBoxError::new(e)),
        }
    }

    fn scan_register(&mut self, files: usize, bytes: usize) {
        self.modified_files_count += files as u64;
        self.transfer_bytes += bytes as u64;
    }
}

fn push_chunk(content: &[u8], state: &mut State) -> Result<String, Error> {
    let now = std::time::Instant::now();
    let mut hasher = blake2::Blake2b::<digest::consts::U32>::new();
    hasher.update(state.secrets.seed);
    hasher.update(content);
    let hash = hex::encode(hasher.finalize());
    let t0 = now.elapsed().as_millis();
    let hc = has_chunk(&hash, state, Some(content.len()))?;
    let t1 = now.elapsed().as_millis();
    let mut t2 = t1;
    if hc == HasChunkResult::No {
        let mut crypted = vec![0; content.len() + 12];
        state.rng.try_fill_bytes(&mut crypted[..12])?;

        let nonce: [u8; 12] = crypted[..12].try_into().unwrap();
        chacha20::ChaCha20::new(&state.secrets.key.into(), &nonce.into())
            .apply_keystream_b2b(content, &mut crypted[12..]);
        t2 = now.elapsed().as_millis();

        if crypted.len() < BATCH_UPLOAD_MAX_ENCRYPTED {
            if let std::collections::hash_map::Entry::Vacant(e) =
                state.pending_small_uploads.entry(hash.clone())
            {
                // Defer small chunk: batch it up and send later to avoid per-file HTTP overhead.
                state.pending_small_size += crypted.len();
                e.insert((crypted, content.len()));
                if state.pending_small_size >= BATCH_FLUSH_BYTES {
                    flush_pending_uploads(state)?;
                }
            } else {
                state.skipped_bytes += content.len();
            }
            // remote cache and progress updated by flush_pending_uploads
            return Ok(hash);
        }

        let url = format!(
            "{}/chunks/{}/{}",
            &state.config.server,
            hex::encode(state.secrets.bucket),
            &hash
        );
        let res = retry(&mut || {
            state
                .client
                .put(&url[..])
                .basic_auth(&state.config.user, Some(&state.config.password))
                .body(reqwest::blocking::Body::from(crypted.clone()))
                .send()
        })?;
        match res.status() {
            reqwest::StatusCode::OK => {
                state.transfered_bytes += crypted.len();
            }
            reqwest::StatusCode::CONFLICT => {
                state.conflict_bytes += crypted.len();
                debug!("Conflict in upload");
            }
            code => return Err(Error::HttpStatus(code)),
        }
    } else {
        state.skipped_bytes += content.len();
    }
    let t3 = now.elapsed().as_millis();
    if hc != HasChunkResult::YesCached {
        state.update_remote_stmt.execute(params![hash])?;
    }
    if let Some(p) = &mut state.progress {
        p.add(content.len() as u64);
    }
    let t4 = now.elapsed().as_millis();
    debug!(
        "Put chunk; chunk: {}, size: {}, hash: {}, head: {}, crypt: {} put: {}, insert: {}",
        hash,
        content.len(),
        t0,
        t1 - t0,
        t2 - t1,
        t3 - t2,
        t4 - t3
    );
    Ok(hash)
}

/// Flush all deferred small-chunk uploads in a single batch PUT request.
fn flush_pending_uploads(state: &mut State) -> Result<(), Error> {
    if state.pending_small_uploads.is_empty() {
        return Ok(());
    }
    let bucket = hex::encode(state.secrets.bucket);
    let url = format!("{}/chunks/{}", &state.config.server, bucket);

    // Build binary body: for each chunk: [64-char hash][\0][4-byte LE size][encrypted data]
    let body = {
        let pending = &state.pending_small_uploads;
        let mut b = Vec::with_capacity(pending.values().map(|(d, _)| 69 + d.len()).sum());
        for (hash, (data, _)) in pending {
            b.extend_from_slice(hash.as_bytes());
            b.push(b'\0');
            b.extend_from_slice(&(data.len() as u32).to_le_bytes());
            b.extend_from_slice(data);
        }
        b
    };

    let res = retry(&mut || {
        state
            .client
            .put(&url)
            .basic_auth(&state.config.user, Some(&state.config.password))
            .body(body.clone())
            .send()
    })?;
    match res.status() {
        reqwest::StatusCode::OK => (),
        code => return Err(Error::HttpStatus(code)),
    }

    // Request succeeded — now drain the pending list.
    let pending = std::mem::take(&mut state.pending_small_uploads);
    state.pending_small_size = 0;

    let total_original: usize = pending.values().map(|(_, orig)| orig).sum();
    let total_encrypted: usize = pending.values().map(|(d, _)| d.len()).sum();
    state.transfered_bytes += total_encrypted;
    for (hash, (_, orig_len)) in &pending {
        state.update_remote_stmt.execute(params![hash])?;
        if let Some(p) = &mut state.progress {
            p.add(*orig_len as u64);
        }
    }
    info!(
        "Batch uploaded {} small chunks ({} bytes)",
        pending.len(),
        total_original
    );
    Ok(())
}

fn backup_file(path: &Path, size: u64, mtime: u64, state: &mut State) -> Result<String, Error> {
    let path_str = path
        .to_str()
        .ok_or_else(|| Error::BadPath(path.to_path_buf()))?;
    if let Some(p) = &mut state.progress {
        let mut start = i64::max(0, path_str.len() as i64 - 40) as usize;
        while !path_str.is_char_boundary(start) {
            start -= 1;
        }
        p.message(&format!("{} ", &path_str[start..]));
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
            let chunk_list: Vec<&str> = chunks.split(',').collect();
            let mut uncached = Vec::new();
            for chunk in &chunk_list {
                let cnt: i64 = state
                    .has_remote_stmt
                    .query(params![chunk])?
                    .next()?
                    .ok_or(Error::MissingRow())?
                    .get(0)?;
                if cnt == 0 {
                    uncached.push(*chunk);
                }
            }
            let good = uncached.is_empty() || {
                if state.scan {
                    for c in &uncached {
                        state.pending_verify.insert(c.to_string());
                    }
                    true // optimistic during scan; verified in batch after scan completes
                } else {
                    has_chunks_remote(&uncached, state).iter().count() == uncached.len()
                }
            };
            if good {
                return Ok(chunks);
            }
        }
    }

    if state.scan {
        state.modified_files_count += 1;
        state.transfer_bytes += size;
        return Ok("_".repeat((65 * (size + CHUNK_SIZE - 1) / CHUNK_SIZE - 1) as usize));
    }

    // Open the file and read each chunk
    let mut file = fs::File::open(path)?;

    let mut buffer = vec![0u8; u64::min(size, CHUNK_SIZE) as usize];
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

        if !chunks.is_empty() {
            chunks.push(',');
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
    Ok(chunks)
}

fn backup_folder(dir: &Path, state: &mut State) -> Result<(), Error> {
    let raw_entries = match fs::read_dir(dir) {
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            error!("Unable to backup folder {dir:?}: {e:?}\n");
            return Ok(());
        }
        Ok(v) => v,
    };
    for entry in raw_entries {
        let mut path = entry?.path();
        let md = match fs::symlink_metadata(&path) {
            Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                error!("Unable to backup entry {path:?}: {e:?}\n");
                continue;
            }
            Ok(v) => v,
        };
        let path_string = path
            .to_str()
            .ok_or_else(|| Error::BadPath(path.to_path_buf()))?
            .to_string();
        if path_string.contains('\0') {
            return Err(Error::BadPath(path.to_path_buf()));
        }
        let ft = md.file_type();
        let mode = md.st_mode() & 0xFFF;
        if ft.is_dir() {
            path.push(".mbackupskip");
            let should_skip = path.exists();
            path.pop();
            if should_skip {
                continue;
            }
            state.entries.push(DirEnt {
                path: path_string,
                etype: EType::Dir,
                content: "0".to_string(),
                size: 0,
                mode,
                uid: md.st_uid(),
                gid: md.st_gid(),
                mtime: md.st_mtime(),
                ctime: md.st_ctime(),
            });
            backup_folder(&path, state)?;
        } else if ft.is_file() {
            let mtime = md
                .modified()?
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let content = match backup_file(&path, md.len(), mtime, state) {
                Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    error!("Unable to backup file {}: {:?}\n", &path_string, e);
                    continue;
                }
                Ok(v) => v,
            };
            let ent = DirEnt {
                path: path_string,
                etype: EType::File,
                content,
                size: md.len(),
                mode,
                uid: md.st_uid(),
                gid: md.st_gid(),
                mtime: md.st_mtime(),
                ctime: md.st_ctime(),
            };
            state.entries.push(ent);
        } else if ft.is_symlink() {
            let link = match fs::read_link(&path) {
                Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    error!("Unable to backup link {path:?}: {e:?}\n");
                    continue;
                }
                Ok(v) => v,
            };
            state.entries.push(DirEnt {
                path: path_string,
                etype: EType::Link,
                content: link
                    .to_str()
                    .ok_or_else(|| Error::BadPath(link.to_path_buf()))?
                    .to_string(),
                size: 0,
                mode,
                uid: md.st_uid(),
                gid: md.st_gid(),
                mtime: md.st_mtime(),
                ctime: md.st_ctime(),
            });
        }
    }

    Ok(())
}

fn update_remote(conn: &Connection, state: &mut State) -> Result<(), Error> {
    let url = format!(
        "{}/status/{}",
        &state.config.server,
        hex::encode(state.secrets.bucket)
    );

    let last_delete: i64 = check_response(&mut || {
        state
            .client
            .get(&url[..])
            .basic_auth(&state.config.user, Some(&state.config.password))
            .send()
    })?
    .text()?
    .parse()?;

    let oldest_remote: Option<i64> =
        conn.query_row("SELECT min(time) FROM remote", [], |row| row.get(0))?;

    let should_update_remote = match oldest_remote {
        Some(t) => t < last_delete,
        None => true,
    };

    if !should_update_remote {
        return Ok(());
    }
    conn.execute("DELETE FROM remote", [])?;
    let url = format!(
        "{}/chunks/{}",
        &state.config.server,
        hex::encode(state.secrets.bucket)
    );
    let content = check_response(&mut || {
        state
            .client
            .get(&url[..])
            .basic_auth(&state.config.user, Some(&state.config.password))
            .send()
    })?
    .text()?;
    let mut cnt = 0;
    for row in content.split('\n') {
        let mut row = row.split(' ');
        let chunk = row.next().ok_or(Error::Msg("Missing churk"))?;
        state.update_remote_stmt.execute(params![chunk])?;
        cnt += 1;
    }
    info!("Prune detected. {cnt} objects reloaded from remote state");
    Ok(())
}

/// Batch-verify the chunk hashes currently accumulated in `pending_verify`
/// against the server and populate the local remote cache for any hashes
/// that exist remotely.
/// This avoids per-file network round-trips for many small files by verifying
/// queued hashes in batches of up to 900 per POST, after which `has_chunk()`
/// can check chunk existence using only the local DB.
fn flush_pending_verify(state: &mut State) -> Result<(), Error> {
    let chunks: Vec<String> = state.pending_verify.drain().collect();
    if chunks.is_empty() {
        return Ok(());
    }
    info!("Batch-verifying {} chunks against server", chunks.len());
    // SQLite's default SQLITE_MAX_VARIABLE_NUMBER is 999; do_has_chunks binds
    // chunks.len() + 1 params (bucket), so the safe ceiling is 998. Use 900.
    const BATCH_SIZE: usize = 900;
    for batch in chunks.chunks(BATCH_SIZE) {
        let refs: Vec<&str> = batch.iter().map(String::as_str).collect();
        let found = has_chunks_remote(&refs, state)?;
        for hash in found.iter() {
            state.update_remote_stmt.execute(params![hash])?;
        }
    }
    Ok(())
}

pub fn run(config: Config, secrets: Secrets, plugins: &mut [PluginBox]) -> Result<(), Error> {
    let t1 = SystemTime::now();

    let conn = Connection::open(&config.cache_db)?;

    conn.pragma_update(None, "journal_mode", "WAL")?;

    // Note that UNIQUE constraints automatically create indexes
    // (according to experimentation).
    conn.execute(
        "CREATE TABLE IF NOT EXISTS files (
            path TEXT NOT NULL UNIQUE,
            size INTEGER NOT NULL,
            mtime INTEGER NOT NULL,
            chunks TEXT NOT NULL
        )",
        [],
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS remote (
            chunk TEXT NOT NULL UNIQUE,
            time INTEGER NOT NULL
        )",
        [],
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS remote_server (
            server TEXT NOT NULL
        )",
        [],
    )?;

    // Check if the server changed since last backup, if so clear the remote cache
    match conn.query_one("SELECT server FROM remote_server", [], |row| {
        row.get::<_, String>(0)
    }) {
        Ok(v) if v != config.server => {
            error!("Remote server changed, clearing remote cache");
            conn.execute("DELETE FROM remote", [])?;
            conn.execute("DELETE FROM remote_server", [])?;
            conn.execute(
                "INSERT INTO remote_server (server) VALUES (?)",
                params![config.server],
            )?;
        }
        Ok(_) => (),
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            // No server stored, insert the current one
            conn.execute(
                "INSERT INTO remote_server (server) VALUES (?)",
                params![config.server],
            )?;
        }
        Err(e) => return Err(Error::Sql(e)),
    };

    let mut state = State {
        secrets,
        config,
        client: reqwest::blocking::ClientBuilder::new()
            .timeout(Duration::from_secs(60 * 4)) // Increase timeout from default 30 seconds to 5 minutes
            .no_brotli()
            .no_deflate()
            .no_gzip()
            .build()?,
        scan: true,
        transfer_bytes: 0,
        progress: None,
        has_remote_stmt: conn.prepare("SELECT count(*) FROM remote WHERE chunk = ?")?,
        update_remote_stmt: conn
            .prepare("REPLACE INTO remote VALUES (?, strftime('%s', 'now'))")?,
        get_chunks_stmt: conn
            .prepare("SELECT chunks FROM files WHERE path = ? AND size = ? AND mtime = ?")?,
        get_chunks_unsized_stmt: conn
            .prepare("SELECT chunks, size FROM files WHERE path = ? AND mtime = ?")?,
        update_chunks_stmt: conn
            .prepare("REPLACE INTO files (path, size, mtime, chunks) VALUES (?, ?, ?, ?)")?,
        rng: SysRng,
        entries: Vec::new(),
        modified_files_count: 0,
        transfered_bytes: 0,
        conflict_bytes: 0,
        skipped_bytes: 0,
        plugin_entries: Vec::new(),
        plugin: RCowStr::from_str(""),
        plugin_name: RCowStr::from_str(""),
        pending_verify: std::collections::HashSet::new(),
        pending_small_uploads: std::collections::HashMap::new(),
        pending_small_size: 0,
    };

    update_remote(&conn, &mut state)?;

    let dirs = state.config.backup_dirs.clone();
    for dir in dirs.iter() {
        let path = Path::new(dir);
        if !path.is_dir() {
            info!("Skipping {}", &dir);
            continue;
        }
        info!("Scanning {}", &dir);
        backup_folder(path, &mut state)?;
    }

    for plugin in plugins.iter_mut() {
        info!("Scanning plugin {}: {}", plugin.plugin(), plugin.name());
        state.plugin = plugin.plugin();
        state.plugin_name = plugin.name();
        let state = BackupContextRef::from_ptr(&mut state, TD_Opaque);
        plugin.scan(state).into_result().map_err(Error::Plugin)?;
    }

    if state.config.verbosity >= Level::Info {
        state.progress = Some({
            let mut p = ProgressBar::new(state.transfer_bytes);
            p.set_max_refresh_rate(Some(Duration::from_millis(500)));
            p.set_units(pbr::Units::Bytes);
            p.set_width(Some(140));
            p
        });
    }

    let t2 = SystemTime::now();
    info!(
        "Scan complete after {:?}, {} modified files, {} bytes to transfer\n",
        t2.duration_since(t1),
        state.modified_files_count,
        state.transfer_bytes
    );

    state.entries.clear();
    state.plugin_entries.clear();
    flush_pending_verify(&mut state)?;
    state.scan = false;
    for dir in dirs.iter() {
        let path = Path::new(dir);
        if !path.is_dir() {
            info!("Skipping {}", &dir);
            continue;
        }
        info!("Backing up {}", &dir);

        let md = fs::metadata(path)?;
        state.entries.push(DirEnt {
            path: dir.to_string(),
            etype: EType::Dir,
            content: "0".to_string(),
            size: 0,
            mode: md.st_mode() & 0xFFF,
            uid: md.st_uid(),
            gid: md.st_gid(),
            mtime: md.st_mtime(),
            ctime: md.st_ctime(),
        });
        backup_folder(path, &mut state)?;
    }

    for plugin in plugins.iter_mut() {
        info!("Backing up plugin {}: {}", plugin.plugin(), plugin.name());
        state.plugin = plugin.plugin();
        state.plugin_name = plugin.name();
        let state = BackupContextRef::from_ptr(&mut state, TD_Opaque);
        plugin.backup(state).into_result().map_err(Error::Plugin)?;
    }

    let t3 = SystemTime::now();
    info!(
        "Backup complete after {:?}, {} bytes transfered, {} bytes conflict, {} bytes skipped\n",
        t3.duration_since(t2),
        state.transfered_bytes,
        state.conflict_bytes,
        state.skipped_bytes
    );

    info!("Storing root");

    let mut ans = "".to_string();
    for ent in state.entries.iter() {
        if !ans.is_empty() {
            ans.push('\0');
            ans.push('\0');
        }
        ans.push_str(&format!(
            "{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
            ent.path,
            ent.etype,
            ent.size,
            ent.content,
            ent.mode,
            ent.uid,
            ent.gid,
            ent.mtime,
            ent.ctime,
        ));
    }
    for ent in state.plugin_entries.iter() {
        if !ans.is_empty() {
            ans.push('\0');
            ans.push('\0');
        }
        ans.push_str(ent);
    }

    let root = push_chunk(&lzma::compress(ans.as_bytes(), 7)?, &mut state)?;

    // Flush any remaining deferred small-chunk uploads (including the root manifest
    // if it was small enough to be deferred) before registering the root with the server.
    flush_pending_uploads(&mut state)?;

    let url = format!(
        "{}/roots/{}/{}",
        &state.config.server,
        hex::encode(state.secrets.bucket),
        &state.config.hostname
    );

    check_response(&mut || {
        state
            .client
            .put(&url[..])
            .basic_auth(&state.config.user, Some(&state.config.password))
            .body(root.clone())
            .send()
    })?;
    Ok(())
}
