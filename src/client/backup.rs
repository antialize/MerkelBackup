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
const BATCH_UPLOAD_MAX: usize = 128 * 1024;
// Flush the pending batch whenever this many bytes have accumulated.
const BATCH_FLUSH_BYTES: usize = 4 * 1024 * 1024;
// Flush pending_verify during scan whenever this many unconfirmed chunks accumulate,
// so progress is saved durably even if the job is killed mid-scan.
const PENDING_VERIFY_FLUSH_THRESHOLD: usize = 50_000;
// Number of concurrent upload workers (each handles encryption + HTTP independently).
const N_UPLOAD_WORKERS: usize = 4;

// Upload pipeline

/// A task for an upload worker: either a complete batch of small plaintext chunks
/// to encrypt and POST together, or a single large plaintext chunk to encrypt and PUT.
enum UploadTask {
    /// A complete batch of plaintext small chunks; the worker encrypts and POSTs them.
    Batch {
        chunks: Vec<(String, Vec<u8>)>, // (hash, plaintext)
    },
    /// A single large plaintext chunk; the worker encrypts and PUTs it.
    LargeChunk { hash: String, content: Vec<u8> },
}

/// Acknowledgement sent back from the upload thread to the main thread.
enum UploadResult {
    /// One chunk (large, or one from a flushed batch) was successfully uploaded.
    Uploaded { hash: String, transferred: usize },
    /// A conflict: the server already had this chunk (CONFLICT response).
    Conflict { hash: String, orig_len: usize },
    /// The batch flush finished; these hashes were newly uploaded.
    BatchFlushed {
        hashes: Vec<(String, usize)>, // (hash, orig_len)
        total_transferred: usize,
    },
    /// An unrecoverable error occurred in the upload thread.
    Err(crate::shared::Error),
}

/// Runs in a worker thread. Pulls UploadTasks from the shared queue, encrypts the
/// plaintext payloads with ChaCha20, performs HTTP, and sends UploadResults back.
/// Multiple workers share the same Receiver via Arc<Mutex<...>> for load-balancing.
fn upload_worker(
    key: [u8; 32],
    server: String,
    bucket_hex: String,
    user: String,
    password: String,
    rx: crossbeam_channel::Receiver<UploadTask>,
    tx: crossbeam_channel::Sender<UploadResult>,
) {
    let mut rng = SysRng;
    let client = reqwest::blocking::ClientBuilder::new()
        .timeout(Duration::from_secs(60 * 4))
        .no_brotli()
        .no_deflate()
        .no_gzip()
        .build()
        .expect("upload worker: failed to build reqwest client");

    loop {
        let task = match rx.recv() {
            Ok(t) => t,
            Err(_) => return, // channel closed, no more tasks
        };

        match task {
            UploadTask::Batch { chunks } => {
                let url = format!("{}/chunks/{}", server, bucket_hex);
                // Build the POST body and collect result metadata in a single pass,
                // encrypting directly into the body buffer to avoid a separate allocation.
                let body_capacity: usize = chunks
                    .iter()
                    .map(|(h, c)| h.len() + 1 + 4 + c.len() + 12)
                    .sum();
                let mut body = Vec::with_capacity(body_capacity);
                let mut hashes: Vec<(String, usize)> = Vec::with_capacity(chunks.len());
                let mut total_transferred: usize = 0;
                for (hash, content) in chunks {
                    let orig_len = content.len();
                    let encrypted_len = orig_len + 12;
                    body.extend_from_slice(hash.as_bytes());
                    body.push(b'\0');
                    body.extend_from_slice(&(encrypted_len as u32).to_le_bytes());
                    // Write nonce, then copy plaintext and encrypt it in-place.
                    let nonce_start = body.len();
                    body.resize(nonce_start + 12, 0);
                    rng.try_fill_bytes(&mut body[nonce_start..nonce_start + 12])
                        .expect("OS RNG failed");
                    let nonce: [u8; 12] = body[nonce_start..nonce_start + 12].try_into().unwrap();
                    let ct_start = body.len();
                    body.extend_from_slice(&content);
                    chacha20::ChaCha20::new(&key.into(), &nonce.into())
                        .apply_keystream(&mut body[ct_start..]);
                    total_transferred += encrypted_len;
                    hashes.push((hash, orig_len));
                }
                let res = retry(&mut || {
                    client
                        .put(&url)
                        .basic_auth(&user, Some(&password))
                        .body(body.clone())
                        .send()
                });
                let result = match res {
                    Err(e) => UploadResult::Err(crate::shared::Error::Reqwest(e)),
                    Ok(r) if r.status() != reqwest::StatusCode::OK => {
                        UploadResult::Err(crate::shared::Error::HttpStatus(r.status()))
                    }
                    Ok(_) => UploadResult::BatchFlushed {
                        hashes,
                        total_transferred,
                    },
                };
                let _ = tx.send(result);
            }
            UploadTask::LargeChunk { hash, content } => {
                let orig_len = content.len();
                let url = format!("{}/chunks/{}/{}", server, bucket_hex, hash);
                let res = retry(&mut || {
                    let mut crypted = vec![0u8; orig_len + 12];
                    rng.try_fill_bytes(&mut crypted[..12])
                        .expect("OS RNG failed");
                    let nonce: [u8; 12] = crypted[..12].try_into().unwrap();
                    chacha20::ChaCha20::new(&key.into(), &nonce.into())
                        .apply_keystream_b2b(&content, &mut crypted[12..]);
                    client
                        .put(&url)
                        .basic_auth(&user, Some(&password))
                        .body(reqwest::blocking::Body::from(crypted))
                        .send()
                });
                let result = match res {
                    Err(e) => UploadResult::Err(crate::shared::Error::Reqwest(e)),
                    Ok(r) => match r.status() {
                        reqwest::StatusCode::OK => UploadResult::Uploaded {
                            hash,
                            transferred: orig_len + 12,
                        },
                        reqwest::StatusCode::CONFLICT => UploadResult::Conflict { hash, orig_len },
                        code => UploadResult::Err(crate::shared::Error::HttpStatus(code)),
                    },
                };
                let _ = tx.send(result);
            }
        }
    }
}

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
    /// HTTP client used for non-upload requests (has_chunks, get_status, put_root, etc.)
    client: reqwest::blocking::Client,
    scan: bool,
    transfer_bytes: u64,
    progress: Option<ProgressBar<std::io::Stdout>>,
    has_remote_stmt: Statement<'a>,
    update_remote_stmt: Statement<'a>,
    insert_absent_stmt: Statement<'a>,
    get_chunks_stmt: Statement<'a>,
    get_chunks_unsized_stmt: Statement<'a>,
    update_chunks_stmt: Statement<'a>,
    entries: Vec<DirEnt>,
    modified_files_count: u64,
    transfered_bytes: usize,
    skipped_bytes: usize,
    conflict_bytes: usize,
    plugin: RCowStr<'static>,
    plugin_name: RCowStr<'static>,
    plugin_entries: Vec<String>,
    pending_verify: std::collections::HashSet<String>,
    /// Total non-empty files checked during the scan phase (for progress display).
    scan_files_count: u64,
    /// Files that had chunks to upload during the upload phase.
    upload_files_new: u64,
    /// Files confirmed already present on the server during the upload phase.
    upload_files_unchanged: u64,
    /// Plaintext small chunks buffered on the main thread, awaiting dispatch to a worker.
    pending_batch: Vec<(String, Vec<u8>)>,
    /// Approximate encrypted byte count of chunks currently in pending_batch.
    pending_batch_bytes: usize,
    /// Send side of the upload pipeline (to the worker pool).
    upload_tx: crossbeam_channel::Sender<UploadTask>,
    /// Receive side of the upload pipeline (results from workers).
    upload_rx: crossbeam_channel::Receiver<UploadResult>,
}

#[derive(PartialEq)]
enum HasChunkResult {
    YesCached,
    Yes,
    No,
}

fn has_chunk(chunk: &str, state: &mut State, size: Option<usize>) -> Result<HasChunkResult, Error> {
    let mut rows = state.has_remote_stmt.query(params![chunk])?;
    if let Some(row) = rows.next()? {
        let present: i64 = row.get(0)?;
        if present == 1 {
            return Ok(HasChunkResult::YesCached);
        }
        // present == 0 means confirmed absent on the server, so skip the HEAD request and upload directly
        return Ok(HasChunkResult::No);
    }

    // Not in local cache at all, so the server state is unknown
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
        let mut unknown: Vec<&str> = Vec::new();
        for &chunk in &chunk_list {
            let mut rows = match self.has_remote_stmt.query(params![chunk]) {
                Ok(r) => r,
                Err(e) => return RErr(RBoxError::new(Error::Sql(e))),
            };
            match rows.next() {
                Err(e) => return RErr(RBoxError::new(Error::Sql(e))),
                Ok(None) => {
                    // Not in local cache, so existence on the server is unknown
                    unknown.push(chunk);
                }
                Ok(Some(row)) => {
                    let present: i64 = match row.get(0) {
                        Ok(v) => v,
                        Err(e) => return RErr(RBoxError::new(Error::Sql(e))),
                    };
                    if present == 0 {
                        // Confirmed absent, so no network check is needed
                        return ROk(false);
                    }
                    // present == 1: confirmed on server, continue
                }
            }
        }
        if unknown.is_empty() {
            return ROk(true);
        }
        if self.scan {
            for c in &unknown {
                self.pending_verify.insert(c.to_string());
            }
            if self.pending_verify.len() >= PENDING_VERIFY_FLUSH_THRESHOLD {
                match flush_pending_verify(self) {
                    Ok(()) => {}
                    Err(e) => return RErr(RBoxError::new(e)),
                }
            }
            return ROk(true); // optimistic during scan; verified in batch after scan completes
        }
        match has_chunks_remote(&unknown, self) {
            Ok(r) => ROk(r.iter().count() == unknown.len()),
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

/// Dispatch the current pending_batch to a worker. No-op if the batch is empty.
fn send_pending_batch(state: &mut State) -> Result<(), Error> {
    if state.pending_batch.is_empty() {
        return Ok(());
    }
    let chunks = std::mem::take(&mut state.pending_batch);
    state.pending_batch_bytes = 0;
    state
        .upload_tx
        .send(UploadTask::Batch { chunks })
        .map_err(|_| Error::Msg("upload workers gone"))
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

    if hc == HasChunkResult::No {
        // Handing plaintext to a worker; it will encrypt and upload.
        if content.len() < BATCH_UPLOAD_MAX {
            // Small chunk: accumulate in the pending batch on the main thread.
            state.pending_batch.push((hash.clone(), content.to_vec()));
            state.pending_batch_bytes += content.len() + 12;
            if state.pending_batch_bytes >= BATCH_FLUSH_BYTES {
                send_pending_batch(state)?;
            }
        } else {
            // Large chunk: send as its own task directly.
            state
                .upload_tx
                .send(UploadTask::LargeChunk {
                    hash: hash.clone(),
                    content: content.to_vec(),
                })
                .map_err(|_| Error::Msg("upload workers gone"))?;
        }
        // Non-blocking drain to keep the result channel from backing up.
        drain_results(state)?
    } else {
        state.skipped_bytes += content.len();

        // The chunk was already present on the server; no upload task is enqueued,
        // so we must handle progress and cache updates here directly.
        if hc == HasChunkResult::Yes {
            // HEAD-confirmed present but not yet in the local cache; record it now.
            state.update_remote_stmt.execute(params![hash])?;
        }
        // YesCached: already in the local cache, no DB write needed.

        // Advance the upload progress bar for skipped chunks so it reflects all
        // bytes processed, not just bytes that were actually transferred.
        if let Some(p) = &mut state.progress {
            p.add(content.len() as u64);
        }
    }

    let t2 = now.elapsed().as_millis();
    // Progress and cache updates for uploaded chunks happen in drain_results when ack arrives.
    debug!(
        "Put chunk; hash: {}, size: {}, t_hash_ms: {}, t_lookup_ms: {}, t_enqueue_ms: {}",
        hash,
        content.len(),
        t0,
        t1 - t0,
        t2 - t1,
    );
    Ok(hash)
}

fn process_upload_result(state: &mut State, result: UploadResult) -> Result<(), Error> {
    match result {
        UploadResult::Uploaded { hash, transferred } => {
            state.transfered_bytes += transferred;
            state.update_remote_stmt.execute(params![hash])?;
            if let Some(p) = &mut state.progress {
                p.add(transferred as u64);
            }
        }
        UploadResult::Conflict { hash, orig_len } => {
            state.conflict_bytes += orig_len;
            state.update_remote_stmt.execute(params![hash])?;
            if let Some(p) = &mut state.progress {
                p.add(orig_len as u64);
            }
        }
        UploadResult::BatchFlushed {
            hashes,
            total_transferred,
        } => {
            state.transfered_bytes += total_transferred;
            for (hash, orig_len) in &hashes {
                state.update_remote_stmt.execute(params![hash])?;
                if let Some(p) = &mut state.progress {
                    p.add(*orig_len as u64);
                }
            }
            info!("Batch uploaded {} small chunks", hashes.len());
        }
        UploadResult::Err(e) => return Err(e),
    }
    Ok(())
}

/// Non-blocking drain of any completed upload results.
fn drain_results(state: &mut State) -> Result<(), Error> {
    loop {
        match state.upload_rx.try_recv() {
            Ok(result) => process_upload_result(state, result)?,
            Err(crossbeam_channel::TryRecvError::Empty) => return Ok(()),
            Err(crossbeam_channel::TryRecvError::Disconnected) => {
                return Err(Error::Msg("upload workers gone"));
            }
        }
    }
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

    // Count every non-empty file during the scan phase for periodic progress display.
    if state.scan {
        state.scan_files_count += 1;
        if state.scan_files_count.is_multiple_of(10_000) {
            info!(
                "Scanning: {} files checked, {} to upload so far",
                state.scan_files_count, state.modified_files_count
            );
        }
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
            let mut unknown = Vec::new();
            let mut has_absent = false;
            for chunk in &chunk_list {
                let mut rows = state.has_remote_stmt.query(params![chunk])?;
                match rows.next()? {
                    None => unknown.push(*chunk),
                    Some(row) => {
                        let present: i64 = row.get(0)?;
                        if present == 0 {
                            has_absent = true;
                            break; // confirmed absent, no need to check remaining chunks
                        }
                    }
                }
            }
            if !has_absent {
                let good = unknown.is_empty() || {
                    if state.scan {
                        for c in &unknown {
                            state.pending_verify.insert(c.to_string());
                        }
                        if state.pending_verify.len() >= PENDING_VERIFY_FLUSH_THRESHOLD {
                            flush_pending_verify(state)?;
                        }
                        true // optimistic during scan; verified in batch after scan completes
                    } else {
                        has_chunks_remote(&unknown, state)?.iter().count() == unknown.len()
                    }
                };
                if good {
                    if !state.scan {
                        state.upload_files_unchanged += 1;
                    }
                    return Ok(chunks);
                }
            }
        }
    }

    if state.scan {
        state.modified_files_count += 1;
        state.transfer_bytes += size;
        return Ok("_".repeat((65 * (size + CHUNK_SIZE - 1) / CHUNK_SIZE - 1) as usize));
    }

    // Open the file and read each chunk.
    state.upload_files_new += 1;
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
    let total = chunks.len();
    info!("Batch-verifying {} chunks against server", total);
    let mut bar: Option<ProgressBar<std::io::Stderr>> = if state.config.verbosity >= Level::Info {
        let mut p = ProgressBar::on(std::io::stderr(), total as u64);
        p.set_max_refresh_rate(Some(Duration::from_millis(500)));
        p.message("Verifying: ");
        Some(p)
    } else {
        None
    };
    // SQLite's default SQLITE_MAX_VARIABLE_NUMBER is 999; do_has_chunks binds
    // chunks.len() + 1 params (bucket), so the safe ceiling is 998. Use 900.
    const BATCH_SIZE: usize = 900;
    let mut verified: u64 = 0;
    for batch in chunks.chunks(BATCH_SIZE) {
        let refs: Vec<&str> = batch.iter().map(String::as_str).collect();
        let found = has_chunks_remote(&refs, state)?;
        let found_set: std::collections::HashSet<&str> = found.iter().collect();
        for hash in found.iter() {
            state.update_remote_stmt.execute(params![hash])?;
        }
        for &hash in &refs {
            if !found_set.contains(hash) {
                state.insert_absent_stmt.execute(params![hash])?;
            }
        }
        verified += batch.len() as u64;
        if let Some(ref mut p) = bar {
            p.set(verified);
        }
    }
    if let Some(ref mut p) = bar {
        p.finish_print(&format!("Verified {} chunks", total));
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
            time INTEGER NOT NULL,
            present INTEGER NOT NULL DEFAULT 1
        )",
        [],
    )?;
    // Migrate existing databases that predate the 'present' column.
    // Ignore only the expected "duplicate column name" error on
    // already-migrated databases, and propagate every other failure.
    match conn.execute(
        "ALTER TABLE remote ADD COLUMN present INTEGER NOT NULL DEFAULT 1",
        [],
    ) {
        Ok(_) => (),
        Err(rusqlite::Error::SqliteFailure(_, Some(ref message)))
            if message.contains("duplicate column name") => {}
        Err(e) => return Err(Error::Sql(e)),
    }
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
        has_remote_stmt: conn.prepare("SELECT present FROM remote WHERE chunk = ?")?,
        update_remote_stmt: conn.prepare(
            "REPLACE INTO remote (chunk, time, present) VALUES (?, strftime('%s', 'now'), 1)",
        )?,
        insert_absent_stmt: conn.prepare(
            "REPLACE INTO remote (chunk, time, present) VALUES (?, strftime('%s', 'now'), 0)",
        )?,
        get_chunks_stmt: conn
            .prepare("SELECT chunks FROM files WHERE path = ? AND size = ? AND mtime = ?")?,
        get_chunks_unsized_stmt: conn
            .prepare("SELECT chunks, size FROM files WHERE path = ? AND mtime = ?")?,
        update_chunks_stmt: conn
            .prepare("REPLACE INTO files (path, size, mtime, chunks) VALUES (?, ?, ?, ?)")?,
        entries: Vec::new(),
        modified_files_count: 0,
        transfered_bytes: 0,
        conflict_bytes: 0,
        skipped_bytes: 0,
        plugin_entries: Vec::new(),
        plugin: RCowStr::from_str(""),
        plugin_name: RCowStr::from_str(""),
        pending_verify: std::collections::HashSet::new(),
        scan_files_count: 0,
        upload_files_new: 0,
        upload_files_unchanged: 0,
        pending_batch: Vec::new(),
        pending_batch_bytes: 0,
        upload_tx: {
            // Placeholder; replaced below after workers are spawned.
            let (tx, _) = crossbeam_channel::bounded(0);
            tx
        },
        upload_rx: {
            let (_, rx) = crossbeam_channel::bounded(0);
            rx
        },
    };

    // Spawn upload worker pool with a shared task receiver.
    {
        let (task_tx, task_rx) = crossbeam_channel::bounded::<UploadTask>(N_UPLOAD_WORKERS * 2);
        let (result_tx, result_rx) =
            crossbeam_channel::bounded::<UploadResult>(N_UPLOAD_WORKERS * 16);
        let key = state.secrets.key;
        let server = state.config.server.clone();
        let bucket_hex = hex::encode(state.secrets.bucket);
        let user = state.config.user.clone();
        let password = state.config.password.clone();
        for _ in 0..N_UPLOAD_WORKERS {
            let task_rx = task_rx.clone();
            let result_tx = result_tx.clone();
            let server = server.clone();
            let bucket_hex = bucket_hex.clone();
            let user = user.clone();
            let password = password.clone();
            std::thread::spawn(move || {
                upload_worker(key, server, bucket_hex, user, password, task_rx, result_tx);
            });
        }
        state.upload_tx = task_tx;
        state.upload_rx = result_rx;
    }

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
            p.show_speed = true;
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
        let before_new = state.upload_files_new;
        let before_unchanged = state.upload_files_unchanged;

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
        info!(
            "Finished {}: {} new files, {} unchanged files",
            dir,
            state.upload_files_new - before_new,
            state.upload_files_unchanged - before_unchanged
        );
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

    // Flush any remaining buffered small chunks, then drop the sender so workers
    // exit after draining the queue, and process all remaining results.
    send_pending_batch(&mut state)?;
    drop(std::mem::replace(
        &mut state.upload_tx,
        crossbeam_channel::bounded(0).0,
    ));
    while let Ok(result) = state.upload_rx.recv() {
        process_upload_result(&mut state, result)?;
    }

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
