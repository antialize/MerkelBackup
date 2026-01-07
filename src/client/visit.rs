use crate::RestoreCommand;
use crate::shared::{Config, EType, Error, Level, Secrets, check_response};
use abi_stable::sabi_trait::TD_Opaque;
use abi_stable::std_types::RResult::{RErr, ROk};
use abi_stable::std_types::{RBoxError, RStr, RVec};
use blake2::Digest;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chrono::DateTime;
use itertools::Itertools;
use log::{debug, error, info};
use merkel_backup_plugin::{ParsedEnt, PluginBox, ReadContext, ReadContextRef, Result as PResult};
use pbr::ProgressBar;
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::time::SystemTime;

struct Size {
    bytes: u64,
}

impl std::fmt::Display for Size {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes = self.bytes;
        if bytes < 1024 {
            write!(f, "{bytes} B")
        } else if bytes < 1024 * 64 {
            write!(f, "{:.1} KiB", bytes as f64 / 1024.0)
        } else if bytes < 1024 * 1024 {
            write!(f, "{:.0} KiB", bytes as f64 / 1024.0)
        } else if bytes < 1024 * 1024 * 64 {
            write!(f, "{:.1} MiB", bytes as f64 / 1024.0 / 1024.0)
        } else if bytes < 1024 * 1024 * 1024 {
            write!(f, "{:.0} MiB", bytes as f64 / 1024.0 / 1024.0)
        } else if bytes < 1024 * 1024 * 1024 * 64 {
            write!(f, "{:.1} GiB", bytes as f64 / 1024.0 / 1024.0 / 1024.0)
        } else if bytes < 1024 * 1024 * 1024 * 1024 {
            write!(f, "{:.0} GiB", bytes as f64 / 1024.0 / 1024.0 / 1024.0)
        } else if bytes < 1024 * 1024 * 1024 * 1024 * 64 {
            write!(
                f,
                "{:.1} TiB",
                bytes as f64 / 1024.0 / 1024.0 / 1024.0 / 1024.0
            )
        } else {
            write!(
                f,
                "{:.0} TiB",
                bytes as f64 / 1024.0 / 1024.0 / 1024.0 / 1024.0
            )
        }
    }
}

impl From<u64> for Size {
    fn from(v: u64) -> Size {
        Size { bytes: v }
    }
}

fn get_chunk(
    client: &mut reqwest::blocking::Client,
    config: &Config,
    secrets: &Secrets,
    hash: &str,
) -> Result<Vec<u8>, Error> {
    if hash == "empty" {
        return Ok(Vec::new());
    }
    let url = format!(
        "{}/chunks/{}/{}",
        &config.server,
        hex::encode(secrets.bucket),
        &hash
    );

    let mut res = check_response(&mut || {
        client
            .get(&url[..])
            .timeout(Duration::from_secs(10 * 60))
            .basic_auth(&config.user, Some(&config.password))
            .send()
    })?;

    let len = res.content_length().unwrap_or(0);
    let mut encrypted = Vec::with_capacity(len as usize);
    let len = res.read_to_end(&mut encrypted)?;
    if len < 12 {
        return Err(Error::Msg("Missing nonce"));
    }

    let mut content = Vec::with_capacity(encrypted.len());
    content.resize(encrypted.len() - 12, 0);
    let nonce: [u8; 12] = encrypted[..12].try_into().unwrap();
    chacha20::ChaCha20::new(&secrets.key.into(), &nonce.into())
        .apply_keystream_b2b(&encrypted[12..], &mut content)?;

    let mut hasher = blake2::Blake2b::<digest::consts::U32>::new();
    hasher.update(secrets.seed);
    hasher.update(&content);

    if hex::encode(hasher.finalize()) != hash {
        Err(Error::InvalidHash())
    } else {
        Ok(content)
    }
}

fn get_root(
    client: &mut reqwest::blocking::Client,
    config: &Config,
    secrets: &Secrets,
    hash: &str,
) -> Result<String, Error> {
    Ok(String::from_utf8(lzma::decompress(&get_chunk(
        client, config, secrets, hash,
    )?)?)?)
}

struct Ent {
    etype: EType,
    path: std::path::PathBuf,
    size: u64,
    st_mode: u32,
    uid: u32,
    gid: u32,
    mtime: i64,
    chunks: Vec<String>,
}

fn row_entry(row: &str) -> Result<Option<Ent>, Error> {
    if row.is_empty() {
        return Ok(None);
    }
    use std::str::FromStr;
    let mut ans = row.split('\0');
    let name = ans.next().ok_or(Error::Msg("Missing name"))?;
    let etype: EType = ans.next().ok_or(Error::Msg("Missing type"))?.parse()?;
    let size: u64 = ans.next().ok_or(Error::Msg("Missing size"))?.parse()?;
    let reference = ans.next().ok_or(Error::Msg("Missing reference"))?;
    let st_mode: u32 = ans.next().ok_or(Error::Msg("Missing mode"))?.parse()?;
    let uid: u32 = ans.next().ok_or(Error::Msg("Missing uid"))?.parse()?;
    let gid: u32 = ans.next().ok_or(Error::Msg("Missing gid"))?.parse()?;
    let mtime: i64 = ans.next().ok_or(Error::Msg("Missing mtime"))?.parse()?;
    let _ctime: i64 = ans.next().ok_or(Error::Msg("Missing ctime"))?.parse()?;
    let path = PathBuf::from_str(name).map_err(|_| Error::Msg("Bad path"))?;

    Ok(Some(Ent {
        path,
        etype,
        size,
        st_mode,
        uid,
        gid,
        mtime,
        chunks: reference
            .split(',')
            .map(std::string::ToString::to_string)
            .collect(),
    }))
}

enum ParsedEntry<'a> {
    None,
    Normal(Ent),
    Plugin {
        plugin_idx: usize,
        plugin: &'a mut PluginBox,
        line: &'a str,
    },
}

fn parse_entry<'a>(row: &'a str, plugins: &'a mut [PluginBox]) -> Result<ParsedEntry<'a>, Error> {
    if let Some(rem) = row.strip_prefix('@') {
        let (plugin, rem) = rem.split_once('\0').ok_or(Error::Msg("Plugin missing"))?;
        let (name, rem) = rem
            .split_once('\0')
            .ok_or(Error::Msg("Plugin name missing"))?;
        let (plugin_idx, plugin) = plugins
            .iter_mut()
            .find_position(|v| v.plugin() == plugin && v.name() == name)
            .ok_or(Error::Msg("Plugin not loaded"))?;
        Ok(ParsedEntry::Plugin {
            plugin_idx,
            plugin,
            line: rem,
        })
    } else {
        match row_entry(row) {
            Ok(None) => Ok(ParsedEntry::None),
            Ok(Some(ent)) => Ok(ParsedEntry::Normal(ent)),
            Err(e) => Err(e),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn recover_entry(
    pb: &mut Option<ProgressBar<std::io::Stdout>>,
    ent: &Ent,
    dry: bool,
    dest: &Path,
    preserve_owner: bool,
    client: &mut reqwest::blocking::Client,
    config: &Config,
    secrets: &Secrets,
) -> Result<(), Error> {
    if ent.etype == EType::Root {
        return Ok(());
    }
    if let Some(pb) = pb {
        pb.message(&format!("{:?}: ", &ent.path));
    }
    let dpath = dest.join(
        ent.path
            .strip_prefix("/")
            .map_err(|_| Error::Msg("Path not absolute"))?,
    );
    match ent.etype {
        EType::Root => (),
        EType::Dir => {
            debug!("DIR {dpath:?}");
            if !dry {
                std::fs::create_dir_all(&dpath)?;
            }
            if let Some(pb) = pb {
                pb.add(ent.size);
            }
        }
        EType::Link => {
            debug!("LINK {dpath:?}");
            if !dry {
                std::os::unix::fs::symlink(ent.chunks.first().unwrap(), &dpath)?;
            }
            if let Some(pb) = pb {
                pb.add(ent.size);
            }
        }
        EType::File => {
            debug!("FILE {dpath:?}");
            if !dry {
                let mut file = std::fs::File::create(&dpath)?;
                for chunk in ent.chunks.iter() {
                    let res = get_chunk(client, config, secrets, chunk)?;
                    file.write_all(&res)?;
                    if let Some(pb) = pb {
                        pb.add(res.len() as u64);
                    }
                }
            } else if let Some(pb) = pb {
                pb.add(ent.size);
            }
        }
    }
    if !dry && ent.etype != EType::Link {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dpath, std::fs::Permissions::from_mode(ent.st_mode))?;
        if preserve_owner {
            nix::unistd::fchownat(
                nix::fcntl::AT_FDCWD,
                &dpath,
                Some(nix::unistd::Uid::from_raw(ent.uid)),
                Some(nix::unistd::Gid::from_raw(ent.gid)),
                nix::unistd::FchownatFlags::AT_SYMLINK_NOFOLLOW,
            )?;
        }
        nix::sys::stat::lutimes(
            &dpath,
            &nix::sys::time::TimeValLike::seconds(ent.mtime),
            &nix::sys::time::TimeValLike::seconds(ent.mtime),
        )?;
    }

    Ok(())
}

#[derive(Clone, Copy)]
pub struct Root<'l> {
    pub id: u64,
    pub host: &'l str,
    pub time: i64,
    pub hash: &'l str,
}

pub struct RootsIter<'l> {
    rows: std::str::Split<'l, &'l str>,
    filter: Option<&'l str>,
}

impl<'l> Iterator for RootsIter<'l> {
    type Item = Result<Root<'l>, Error>;

    fn next(&mut self) -> Option<Result<Root<'l>, Error>> {
        for row in self.rows.by_ref() {
            if row.is_empty() {
                continue;
            }
            let extract = || -> Result<Root<'l>, Error> {
                let mut ans = row.split('\0');
                let id: u64 = ans.next().ok_or(Error::Msg("Missing id"))?.parse()?;
                let host = ans.next().ok_or(Error::Msg("Missing host"))?;
                let time: i64 = ans.next().ok_or(Error::Msg("Missing time"))?.parse()?;
                let hash = ans.next().ok_or(Error::Msg("Missing hash"))?;
                Ok(Root {
                    id,
                    host,
                    time,
                    hash,
                })
            };
            match extract() {
                Err(e) => return Some(Err(e)),
                Ok(root) => {
                    if let Some(filter) = self.filter {
                        let root_time = match DateTime::from_timestamp(root.time, 0) {
                            Some(v) => v,
                            None => return Some(Err(Error::Msg("Invalid time"))),
                        };
                        if *filter != format!("{}", root.id)
                            && *filter != format!("{} {}", root.host, root_time,)
                            && *filter != *root.hash
                        {
                            continue;
                        }
                    }
                    return Some(Ok(root));
                }
            }
        }

        None
    }
}

pub struct Roots<'l> {
    text: String,
    filter: Option<&'l str>,
}

impl Roots<'_> {
    pub fn iter(&self) -> RootsIter<'_> {
        RootsIter {
            rows: self.text.split("\0\0"),
            filter: self.filter,
        }
    }
}

pub fn roots<'a: 'b, 'b>(
    config: &Config,
    secrets: &Secrets,
    client: &reqwest::blocking::Client,
    filter: Option<&'a str>,
) -> Result<Roots<'b>, Error> {
    let url = format!("{}/roots/{}", &config.server, hex::encode(secrets.bucket));
    let res = check_response(&mut || {
        client
            .get(&url[..])
            .timeout(Duration::from_secs(2 * 60))
            .basic_auth(&config.user, Some(&config.password))
            .send()
    })?;

    let text = res.text().expect("utf-8");
    Ok(Roots { filter, text })
}

enum OwnedEntry {
    Normal(Ent),
    Plugin { plugin_idx: usize, line: String },
}

struct Context<'a> {
    client: &'a mut reqwest::blocking::Client,
    config: &'a Config,
    secrets: &'a Secrets,
}

impl<'a> ReadContext for Context<'a> {
    fn get_chunk(&mut self, chunk: RStr, output: &mut RVec<u8>) -> PResult<()> {
        match get_chunk(self.client, self.config, self.secrets, chunk.as_str()) {
            Ok(e) => {
                output.clear();
                output.extend_from_slice(&e);
                ROk(())
            }
            Err(e) => RErr(RBoxError::new(e)),
        }
    }

    fn has_chunks(&mut self, chunks: RStr) -> PResult<bool> {
        for chunk in chunks.split(",") {
            let url = format!(
                "{}/chunks/{}/{}",
                &self.config.server,
                hex::encode(self.secrets.bucket),
                &chunk
            );
            let res = match self
                .client
                .head(&url[..])
                .basic_auth(&self.config.user, Some(&self.config.password))
                .send()
            {
                Ok(v) => v,
                Err(e) => return RErr(RBoxError::new(e)),
            };
            match res.status() {
                reqwest::StatusCode::OK => (),
                reqwest::StatusCode::NOT_FOUND => return ROk(false),
                code => return RErr(RBoxError::new(Error::HttpStatus(code))),
            }
        }
        ROk(true)
    }
}

fn full_validate(
    entries: &[(Root<'_>, OwnedEntry)],
    client: &mut reqwest::blocking::Client,
    config: &Config,
    secrets: &Secrets,
    plugins: &mut [PluginBox],
) -> Result<bool, Error> {
    let mut files: HashMap<&str, (usize, &PathBuf)> = HashMap::new();
    let mut bytes: u64 = 0;
    for (_, ent) in entries.iter() {
        match ent {
            OwnedEntry::Normal(ent) => {
                if ent.etype != EType::File {
                    continue;
                }
                for (idx, chunk) in ent.chunks.iter().enumerate() {
                    files.entry(chunk).or_insert((idx, &ent.path));
                }
                bytes += ent.size;
            }
            OwnedEntry::Plugin { plugin_idx, line } => {
                let ent = plugins[*plugin_idx]
                    .parse_ent(line.as_str().into())
                    .into_result()
                    .map_err(Error::Plugin)?;
                bytes += ent.size as u64;
            }
        }
    }

    let mut pb = if config.verbosity >= Level::Info {
        let mut pb = ProgressBar::new(bytes);
        pb.set_units(pbr::Units::Bytes);
        pb.set_max_refresh_rate(Some(Duration::from_millis(500)));
        Some(pb)
    } else {
        None
    };
    let mut bad_files: usize = 0;
    for (hash, (idx, path)) in files.iter() {
        if let Some(pb) = &mut pb {
            pb.message(&format!("{path:?}:{idx} "));
        }
        if hash == &"empty" {
            continue;
        }
        match get_chunk(client, config, secrets, hash) {
            Err(e) => {
                bad_files += 1;
                error!("Bad file chunk {hash} at path {path:?}:{idx} : {e:?}");
            }
            Ok(v) => {
                if let Some(pb) = &mut pb {
                    pb.add(v.len() as u64);
                }
            }
        }
    }

    let mut context = Context {
        client,
        config,
        secrets,
    };

    for (_, ent) in entries.iter() {
        let OwnedEntry::Plugin { plugin_idx, line } = ent else {
            continue;
        };
        let context = ReadContextRef::from_ptr(&mut context, TD_Opaque);
        match plugins[*plugin_idx].validate_ent(line.as_str().into(), true, context) {
            RErr(e) => {
                let ent = plugins[*plugin_idx]
                    .parse_ent(line.as_str().into())
                    .into_result()
                    .map_err(Error::Plugin)?;
                bad_files += 1;
                error!("Invalid {} {}: {:?}", ent.etype, ent.name, e);
            }
            ROk(_) => {
                if let Some(pb) = &mut pb {
                    let ent = plugins[*plugin_idx]
                        .parse_ent(line.as_str().into())
                        .into_result()
                        .map_err(Error::Plugin)?;
                    pb.add(ent.size as u64);
                }
            }
        }
    }

    if let Some(pb) = &mut pb {
        pb.finish();
    }
    if bad_files != 0 {
        error!("{} of {} file chunks are bad", bad_files, files.len());
        Ok(false)
    } else {
        Ok(true)
    }
}

fn partial_validate(
    entries: &[(Root<'_>, OwnedEntry)],
    client: &mut reqwest::blocking::Client,
    config: &Config,
    secrets: &Secrets,
    plugins: &mut [PluginBox],
) -> Result<bool, Error> {
    info!("Fetching chunk list",);
    let url = format!(
        "{}/chunks/{}?validate=validate",
        &config.server,
        hex::encode(secrets.bucket)
    );
    let content = check_response(&mut || {
        client
            .get(&url)
            .basic_auth(&config.user, Some(&config.password))
            .send()
    })?
    .text()?;

    let mut existing: HashMap<&str, (i64, i64)> = HashMap::new();
    for row in content.split('\n') {
        if row.is_empty() {
            continue;
        }
        let mut row = row.split(' ');
        let chunk = row.next().ok_or(Error::Msg("Missing churk"))?;
        let size: i64 = row.next().ok_or(Error::Msg("Missing size"))?.parse()?;
        let content_size: i64 = row
            .next()
            .ok_or(Error::Msg("Missing content size"))?
            .parse()?;
        existing.insert(chunk, (size, content_size));
    }
    let mut ok = true;
    info!("Checking entries");
    for (_, ent) in entries {
        match ent {
            OwnedEntry::Normal(ent) => {
                if ent.etype != EType::File {
                    continue;
                }
                let mut ent_size: i64 = 0;
                for chunk in &ent.chunks {
                    let chunk: &str = chunk;
                    if chunk == "empty" {
                        continue;
                    }
                    match existing.get(chunk) {
                        Some((size, content_size)) => {
                            if size != content_size {
                                error!(
                                    "Chunk {} of entry {:?}, should have size {} but had size {}",
                                    chunk, ent.path, size, content_size
                                );
                                ok = false;
                            }
                            ent_size += size - 12;
                        }
                        None => {
                            error!("Missing chunk {} of entry {:?}", chunk, ent.path);
                            ok = false;
                        }
                    };
                }
                if ent.size as i64 != ent_size {
                    error!(
                        "Entry {:?}, should have size {} but had size {}",
                        ent.path, ent.size, ent_size
                    );
                }
            }
            OwnedEntry::Plugin { plugin_idx, line } => {
                let plugin = &mut plugins[*plugin_idx];
                let mut context = Context {
                    client,
                    config,
                    secrets,
                };
                let context = ReadContextRef::from_ptr(&mut context, TD_Opaque);
                if let RErr(e) = plugin.validate_ent(line.as_str().into(), false, context) {
                    let ent = plugin
                        .parse_ent(line.as_str().into())
                        .into_result()
                        .map_err(Error::Plugin)?;
                    error!("Validation of {} {} failed: {:?}", ent.etype, ent.name, e);
                    ok = false;
                }
            }
        }
    }
    Ok(ok)
}

pub fn disk_usage(
    config: Config,
    secrets: Secrets,
    plugins: &mut [PluginBox],
) -> Result<(), Error> {
    let mut client = reqwest::blocking::Client::new();
    let root_visit = roots(&config, &secrets, &client, None)?;
    let mut root_vec = Vec::new();
    for root in root_visit.iter() {
        root_vec.push(root?);
    }
    let mut total_size: u64 = 0;
    let mut seen = HashSet::new();
    info!(
        "{:<20} {:<20} {:>10} {:>10} {:>10}",
        "Host", "Time", "Usage", "Size", "Sum"
    );

    for root in root_vec.iter().rev() {
        let v = match get_root(&mut client, &config, &secrets, root.hash) {
            Err(e) => {
                error!("Bad root {}: {:?}", root.hash, e);
                continue;
            }
            Ok(v) => v,
        };
        let mut size: u64 = v.len() as u64;
        let old_total_size = total_size;
        total_size += v.len() as u64;

        for row in v.split("\0\0") {
            match parse_entry(row, plugins) {
                Ok(ParsedEntry::None) => {}
                Ok(ParsedEntry::Plugin { plugin, line, .. }) => {
                    match plugin.parse_ent(line.into()) {
                        ROk(v) => {
                            for chunk in v.chunks.split(',') {
                                if seen.insert(chunk.to_string()) {
                                    total_size += size;
                                }
                            }
                        }
                        RErr(e) => error!("Bad row '{row}`: {e:?}"),
                    }
                }
                Ok(ParsedEntry::Normal(ent)) => {
                    size += ent.size;
                    let mut remaining = ent.size;
                    for chunk in ent.chunks {
                        let chunk_size = u64::min(remaining, 64 * 1024 * 1024);
                        if seen.insert(chunk) {
                            total_size += chunk_size;
                        }
                        remaining -= chunk_size;
                    }
                }
                Err(e) => error!("Bad row '{row}`: {e:?}"),
            }
        }
        let time_str = std::format!(
            "{}",
            DateTime::from_timestamp(root.time, 0).ok_or(Error::Msg("Invalid time"))?
        );
        let usage_str = std::format!("{}", Size::from(total_size - old_total_size));
        let size_str = std::format!("{}", Size::from(size));
        let sum_str = std::format!("{}", Size::from(total_size));
        info!(
            "{:<20} {:<20} {:>10} {:>10} {:>10}",
            root.host, time_str, usage_str, size_str, sum_str
        );
    }
    Ok(())
}

pub fn list_root(
    root: &str,
    config: Config,
    secrets: Secrets,
    plugins: &mut [PluginBox],
) -> Result<(), Error> {
    let mut client = reqwest::blocking::Client::new();
    info!("{:4} {:<70} {:>10}", "Type", "Path", "Size",);
    for root in roots(&config, &secrets, &client, Some(root))?.iter() {
        let root = root?;
        let v = match get_root(&mut client, &config, &secrets, root.hash) {
            Err(e) => {
                error!("Bad root {}: {:?}", root.hash, e);
                continue;
            }
            Ok(v) => v,
        };
        for row in v.split("\0\0") {
            match parse_entry(row, plugins) {
                Ok(ParsedEntry::None) => {}
                Ok(ParsedEntry::Plugin { plugin, line, .. }) => {
                    match plugin.parse_ent(line.into()) {
                        ROk(ParsedEnt {
                            etype, name, size, ..
                        }) => {
                            let size = Size::from(size as u64);
                            info!("{:4} {:<70} {:>10}", etype, name, size);
                        }
                        RErr(e) => {
                            error!("Bad row '{row}`: {e:?}");
                        }
                    }
                }
                Ok(ParsedEntry::Normal(ent)) => {
                    let etype = format!("{}", ent.etype);
                    let size = Size::from(ent.size);
                    info!(
                        "{:4} {:<70} {:>10}",
                        etype,
                        ent.path.to_str().unwrap(),
                        size
                    );
                }
                Err(e) => error!("Bad row '{row}`: {e:?}"),
            }
        }
    }
    Ok(())
}

fn find_entries2<
    'a,
    Handler: FnMut(Root<'a>, ParsedEntry),
    Filter: for<'b> FnMut(&Root<'b>) -> Result<bool, Error>,
>(
    client: &mut reqwest::blocking::Client,
    config: &Config,
    secrets: &Secrets,
    roots: &'a Roots<'a>,
    plugins: &mut [PluginBox],
    mut filter_root: Filter,
    mut handle_entry: Handler,
) -> Result<(bool, bool), Error> {
    let mut root_found = false;
    let mut ok = true;
    for root in roots.iter() {
        let root = root?;
        root_found = true;
        if !filter_root(&root)? {
            continue;
        }
        info!(
            "Visiting root {} {}",
            root.host,
            DateTime::from_timestamp(root.time, 0).ok_or(Error::Msg("Invalid time"))?
        );

        let v = match get_root(client, config, secrets, root.hash) {
            Err(e) => {
                error!("Bad root {}: {:?}", root.hash, e);
                ok = false;
                continue;
            }
            Ok(v) => v,
        };

        handle_entry(
            root,
            ParsedEntry::Normal(Ent {
                path: PathBuf::new(),
                etype: EType::Root,
                size: 0,
                st_mode: 0,
                uid: 0,
                gid: 0,
                mtime: 0,
                chunks: vec![root.hash.to_string()],
            }),
        );

        for row in v.split("\0\0") {
            match parse_entry(row, plugins) {
                Ok(ent) => {
                    handle_entry(root, ent);
                }
                Err(e) => {
                    ok = false;
                    error!("Bad row '{row}`: {e:?}");
                }
            }
        }
    }
    Ok((root_found, ok))
}

fn find_entries<
    Handler: FnMut(ParsedEntry),
    Filter: for<'a> FnMut(&Root<'a>) -> Result<bool, Error>,
>(
    config: &Config,
    secrets: &Secrets,
    only_root: Option<&str>,
    plugins: &mut [PluginBox],
    filter_root: Filter,
    mut handle_entry: Handler,
) -> Result<(bool, bool), Error> {
    let mut client = reqwest::blocking::Client::new();
    let roots = roots(config, secrets, &client, only_root)?;
    find_entries2(
        &mut client,
        config,
        secrets,
        &roots,
        plugins,
        filter_root,
        |_, e| handle_entry(e),
    )
}

pub fn run_validate(
    config: Config,
    secrets: Secrets,
    full: bool,
    plugins: &mut [PluginBox],
) -> Result<bool, Error> {
    let mut client = reqwest::blocking::Client::new();
    let roots = roots(&config, &secrets, &client, None)?;

    let mut entries = Vec::new();
    let (_, mut ok) = find_entries2(
        &mut client,
        &config,
        &secrets,
        &roots,
        plugins,
        |_| Ok(true),
        |root, ent| match ent {
            ParsedEntry::None => (),
            ParsedEntry::Normal(ent) => entries.push((root, OwnedEntry::Normal(ent))),
            ParsedEntry::Plugin {
                plugin_idx, line, ..
            } => entries.push((
                root,
                OwnedEntry::Plugin {
                    plugin_idx,
                    line: line.to_string(),
                },
            )),
        },
    )?;
    if full {
        ok = full_validate(&entries, &mut client, &config, &secrets, plugins)? && ok;
    } else {
        ok = partial_validate(&entries, &mut client, &config, &secrets, plugins)? && ok;
    }
    Ok(ok)
}

pub fn run_restore(
    config: Config,
    secrets: Secrets,
    args: RestoreCommand,
    plugins: &mut [PluginBox],
) -> Result<bool, Error> {
    let mut entries: Vec<OwnedEntry> = Vec::new();

    let (root_found, ok) = find_entries(
        &config,
        &secrets,
        Some(args.root.as_ref()),
        plugins,
        |_| Ok(true),
        |ent| match ent {
            ParsedEntry::None => (),
            ParsedEntry::Normal(ent) => {
                if ent.path.starts_with(&args.pattern)
                    || (args.pattern.starts_with(&ent.path) && ent.etype == EType::Dir)
                {
                    entries.push(OwnedEntry::Normal(ent));
                }
            }
            ParsedEntry::Plugin {
                plugin_idx,
                plugin,
                line,
            } => {
                if let Some(pattern) = args.pattern.as_os_str().to_str()
                    && let ROk(true) = plugin.ent_matches_pattern(line.into(), pattern.into())
                {
                    entries.push(OwnedEntry::Plugin {
                        plugin_idx,
                        line: line.to_string(),
                    });
                }
            }
        },
    )?;

    if !root_found {
        return Err(Error::Msg("Root not found"));
    }
    let mut bytes = 0;
    for ent in &entries {
        bytes += match ent {
            OwnedEntry::Normal(ent) => ent.size,
            OwnedEntry::Plugin { plugin_idx, line } => {
                plugins[*plugin_idx]
                    .parse_ent(line.as_str().into())
                    .into_result()
                    .map_err(Error::Plugin)?
                    .size as u64
            }
        }
    }
    let mut pb = if config.verbosity >= Level::Info {
        let mut pb = ProgressBar::new(bytes);
        pb.set_max_refresh_rate(Some(Duration::from_millis(500)));
        pb.set_units(pbr::Units::Bytes);
        Some(pb)
    } else {
        None
    };

    let mut client = reqwest::blocking::Client::new();

    for ent in entries {
        match ent {
            OwnedEntry::Normal(ent) => {
                if let Err(e) = recover_entry(
                    &mut pb,
                    &ent,
                    args.dry,
                    &args.dest,
                    args.preserve_owner,
                    &mut client,
                    &config,
                    &secrets,
                ) {
                    error!("Unable to recover entry {:?}: {:?}", ent.path, e);
                    return Err(e);
                }
            }
            OwnedEntry::Plugin { plugin_idx, line } => {
                if let Some(dest) = args.dest.to_str() {
                    let mut context = Context {
                        client: &mut client,
                        config: &config,
                        secrets: &secrets,
                    };
                    let context = ReadContextRef::from_ptr(&mut context, TD_Opaque);
                    let plugin = &mut plugins[plugin_idx];
                    if let RErr(e) = plugin.recover_ent(
                        line.as_str().into(),
                        dest.into(),
                        args.dry,
                        args.preserve_owner,
                        context,
                    ) {
                        if let ROk(ent) = plugin.parse_ent(line.as_str().into()) {
                            error!(
                                "Unable to recover entry {} {}: {:?}",
                                ent.etype, ent.name, e
                            );
                        }
                        return Err(Error::Plugin(e));
                    }
                    if let Some(pb) = &mut pb
                        && let ROk(ent) = plugin.parse_ent(line.as_str().into())
                    {
                        pb.add(ent.size as u64);
                    }
                }
            }
        }
    }
    Ok(ok)
}

pub fn run_cat(
    config: Config,
    secrets: Secrets,
    root: String,
    path: PathBuf,
    plugins: &mut [PluginBox],
) -> Result<bool, Error> {
    let mut entries: Vec<Ent> = Vec::new();

    let (root_found, ok) = find_entries(
        &config,
        &secrets,
        Some(root.as_ref()),
        plugins,
        |_| Ok(true),
        |ent| match ent {
            ParsedEntry::None => (),
            ParsedEntry::Normal(ent) => {
                if ent.path == path {
                    entries.push(ent);
                }
            }
            ParsedEntry::Plugin { .. } => (),
        },
    )?;

    if !root_found {
        return Err(Error::Msg("Root not found"));
    }
    let mut it = entries.iter();
    let ent = match it.next() {
        None => return Err(Error::Msg("Path not found")),
        Some(ent) => ent,
    };
    match ent.etype {
        EType::File => {}
        EType::Root | EType::Dir | EType::Link => {
            panic!("Expected file but got {}", ent.etype);
            //return Err(Error::Msg("Expected file but got some other type"));
        }
    };
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();

    let mut client = reqwest::blocking::Client::new();

    for chunk in ent.chunks.iter() {
        let res = get_chunk(&mut client, &config, &secrets, chunk)?;
        handle.write_all(&res)?;
    }
    Ok(ok)
}

pub fn run_prune(
    config: Config,
    secrets: Secrets,
    dry: bool,
    age: Option<u32>,
    exponential: bool,
    plugins: &mut [PluginBox],
) -> Result<bool, Error> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs() as i64;

    let client = reqwest::blocking::Client::new();

    let mut used: HashSet<String> = HashSet::new();

    info!("Fetching chunk list");
    let url = format!("{}/chunks/{}", &config.server, hex::encode(secrets.bucket));
    let content = check_response(&mut || {
        client
            .get(&url[..])
            .timeout(Duration::from_secs(10 * 60))
            .basic_auth(&config.user, Some(&config.password))
            .send()
    })?
    .text()?;

    let mut last_host_root_time = HashMap::new();

    let (_, ok) = find_entries(
        &config,
        &secrets,
        None,
        plugins,
        |root| {
            let remove = if exponential {
                // We visit roots in increasing time order
                // Keep roots one for the last 12 days, the last 12 weeks
                // the last 12 months, and every half year for each host
                let keep = if let Some(lt) = last_host_root_time.get(root.host) {
                    const GRACE: i64 = 60 * 60 * 12;
                    if root.time + 60 * 60 * 24 * 12 >= now {
                        // Keep all roots less than 12 dayes old
                        true
                    } else if root.time + 60 * 60 * 24 * 7 * 12 >= now {
                        root.time >= lt + 60 * 60 * 24 * 7 - GRACE
                    } else if root.time + 60 * 60 * 24 * 366 >= now {
                        root.time >= lt + 60 * 60 * 24 * 31 - GRACE
                    } else {
                        root.time >= lt + 60 * 60 * 24 * 182 - GRACE
                    }
                } else {
                    // Keep the first root for the host
                    true
                };
                if keep {
                    last_host_root_time.insert(root.host.to_string(), root.time);
                }
                !keep
            } else if let Some(age) = age {
                root.time + 60 * 60 * 24 * i64::from(age) < now
            } else {
                false
            };

            if remove {
                info!(
                    "Removing root {} {}",
                    root.host,
                    DateTime::from_timestamp(root.time, 0).ok_or(Error::Msg("Invalid time"))?
                );
                if !dry {
                    let url = format!(
                        "{}/roots/{}/{}",
                        &config.server,
                        hex::encode(secrets.bucket),
                        root.id
                    );
                    check_response(&mut || {
                        client
                            .delete(&url[..])
                            .timeout(Duration::from_secs(5 * 60))
                            .basic_auth(&config.user, Some(&config.password))
                            .send()
                    })?;
                }
                Ok(false)
            } else {
                Ok(true)
            }
        },
        |ent| match ent {
            ParsedEntry::None => {}
            ParsedEntry::Normal(ent) => {
                if ent.etype == EType::Link || ent.etype == EType::Dir {
                    return;
                }
                for chunk in ent.chunks.iter() {
                    used.insert(chunk.to_owned());
                }
            }
            ParsedEntry::Plugin { plugin, line, .. } => {
                match plugin.parse_ent(line.into()).map_err(Error::Plugin) {
                    ROk(v) => {
                        for chunk in v.chunks.split(',') {
                            used.insert(chunk.to_string());
                        }
                    }
                    RErr(e) => {
                        error!("Error visiting plugin entry: {e:?}");
                    }
                }
            }
        },
    )?;

    let mut total = 0;
    let mut removed_size = 0;
    let mut remove = Vec::new();
    for row in content.split('\n') {
        if row.is_empty() {
            continue;
        }
        let mut row = row.split(' ');
        let chunk = row.next().ok_or(Error::Msg("Missing churk"))?;
        let size: u64 = row.next().ok_or(Error::Msg("Missing size"))?.parse()?;
        total += 1;
        if used.contains(chunk) {
            continue;
        }
        removed_size += size;
        remove.push((chunk, size));
    }

    info!("Removing {} of {} chunks", remove.len(), total);
    if dry {
        return Ok(ok);
    }

    let mut pb = if config.verbosity >= Level::Info {
        let mut pb = ProgressBar::new(removed_size);
        pb.set_max_refresh_rate(Some(Duration::from_millis(500)));
        pb.set_units(pbr::Units::Bytes);
        Some(pb)
    } else {
        None
    };

    use itertools::Itertools;

    for group in &remove.iter().enumerate().chunks(2048) {
        let mut data = String::new();

        let mut last_idx = 0;
        let mut sum_size = 0;
        for (idx, (chunk, size)) in group {
            last_idx = idx;
            sum_size += size;
            if !data.is_empty() {
                data.push('\0');
            }
            data.push_str(chunk);
        }
        if let Some(pb) = &mut pb {
            pb.message(&format!("Chunk {} / {}: ", last_idx, remove.len()));
        }
        let url = format!("{}/chunks/{}", &config.server, hex::encode(secrets.bucket));

        match check_response(&mut || {
            client
                .delete(&url[..])
                .timeout(Duration::from_secs(5 * 60))
                .basic_auth(&config.user, Some(&config.password))
                .body(data.clone())
                .send()
        }) {
            Ok(_) => (),
            Err(Error::HttpStatus(reqwest::StatusCode::NOT_FOUND)) => (),
            Err(e) => return Err(e),
        };

        if let Some(pb) = &mut pb {
            pb.add(sum_size);
        }
    }

    if let Some(pb) = &mut pb {
        pb.finish();
    }
    Ok(ok)
}
