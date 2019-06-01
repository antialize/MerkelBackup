use chrono::NaiveDateTime;
use crypto::blake2b::Blake2b;
use crypto::digest::Digest;
use crypto::symmetriccipher::SynchronousStreamCipher;
use pbr::ProgressBar;
use shared::{check_response, Config, EType, Error, Secrets};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;
use std::time::SystemTime;

fn get_chunk(
    client: &mut reqwest::Client,
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
        hex::encode(&secrets.bucket),
        &hash
    );

    let mut res = check_response(
        client
            .get(&url[..])
            .basic_auth(&config.user, Some(&config.password))
            .send()?,
    )?;

    let len = res.content_length().unwrap_or(0);
    let mut encrypted = Vec::with_capacity(len as usize);
    let len = res.read_to_end(&mut encrypted)?;
    if len < 12 {
        return Err(Error::Msg("Missing nonce"));
    }

    let mut content = Vec::with_capacity(encrypted.len());
    content.resize(encrypted.len() - 12, 0);
    crypto::chacha20::ChaCha20::new(&secrets.key, &encrypted[..12])
        .process(&encrypted[12..], &mut content);

    let mut hasher = Blake2b::new(256 / 8);
    hasher.input(&secrets.seed);
    hasher.input(&content);

    if hasher.result_str() != hash {
        return Err(Error::InvalidHash());
    }

    return Ok(content);
}

fn get_chunk_utf8(
    client: &mut reqwest::Client,
    config: &Config,
    secrets: &Secrets,
    hash: &str,
) -> Result<String, Error> {
    Ok(String::from_utf8(get_chunk(
        client, config, secrets, hash,
    )?)?)
}

pub enum Mode {
    Validate {
        full: bool,
    },
    Prune {
        dry: bool,
        age: Option<u32>,
    },
    Restore {
        root: String,
        pattern: PathBuf,
        dest: PathBuf,
        dry: bool,
        preserve_owner: bool,
    },
}

struct Ent {
    etype: EType,
    path: std::path::PathBuf,
    size: u64,
    st_mode: u32,
    uid: u32,
    gid: u32,
    atime: i64,
    mtime: i64,
    chunks: Vec<String>,
}

fn row_ent(path: &PathBuf, row: &str, mode: &Mode) -> Result<Option<Ent>, Error> {
    if row.is_empty() {
        return Ok(None);
    }

    let mut ans = row.split('\0');
    let name = ans.next().ok_or(Error::Msg("Missing name"))?;
    let etype: EType = ans.next().ok_or(Error::Msg("Missing type"))?.parse()?;
    let size: u64 = ans.next().ok_or(Error::Msg("Missing size"))?.parse()?;
    let reference = ans.next().ok_or(Error::Msg("Missing reference"))?;
    let st_mode: u32 = ans.next().ok_or(Error::Msg("Missing mode"))?.parse()?;
    let uid: u32 = ans.next().ok_or(Error::Msg("Missing uid"))?.parse()?;
    let gid: u32 = ans.next().ok_or(Error::Msg("Missing gid"))?.parse()?;
    let mtime: i64 = ans.next().ok_or(Error::Msg("Missing mtime"))?.parse()?;
    let atime: i64 = ans.next().ok_or(Error::Msg("Missing atime"))?.parse()?;
    let _ctime: i64 = ans.next().ok_or(Error::Msg("Missing ctime"))?.parse()?;

    let path = path.join(name);
    if let Mode::Restore {
        dry: _,
        dest: _,
        pattern,
        root: _,
        preserve_owner: _,
    } = &mode
    {
        if !(path.starts_with(pattern) || (pattern.starts_with(&path) && etype == EType::Dir)) {
            debug!("Skip {:?}", path);
            return Ok(None);
        }
    };

    return Ok(Some(Ent {
        path,
        etype,
        size,
        st_mode,
        uid,
        gid,
        mtime,
        atime,
        chunks: reference.split(",").map(|s| s.to_string()).collect(),
    }));
}

fn recover_entry(
    pb: &mut ProgressBar<std::io::Stdout>,
    ent: &Ent,
    dry: bool,
    dest: &PathBuf,
    preserve_owner: bool,
    client: &mut reqwest::Client,
    config: &Config,
    secrets: &Secrets,
) -> Result<(), Error> {
    pb.message(&format!("{:?}: ", &ent.path));
    let dpath = dest.join(
        ent.path
            .strip_prefix("/")
            .map_err(|_| Error::Msg("Path not absolute"))?,
    );
    match ent.etype {
        EType::Dir => {
            debug!("DIR {:?}", dpath);
            if !dry {
                std::fs::create_dir_all(&dpath)?;
            }
            pb.add(ent.size);
        }
        EType::Link => {
            debug!("LINK {:?}", dpath);
            if !dry {
                std::os::unix::fs::symlink(ent.chunks.first().unwrap(), &dpath)?;
            }
            pb.add(ent.size);
        }
        EType::File => {
            debug!("FILE {:?}", dpath);
            if !dry {
                let mut file = std::fs::File::create(&dpath)?;
                for chunk in ent.chunks.iter() {
                    let res = get_chunk(client, &config, &secrets, &chunk)?;
                    file.write(&res)?;
                    pb.add(res.len() as u64);
                }
            } else {
                pb.add(ent.size);
            }
        }
    }
    if !dry && ent.etype != EType::Link {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dpath, std::fs::Permissions::from_mode(ent.st_mode))?;
        if preserve_owner {
            nix::unistd::fchownat(
                None,
                &dpath,
                Some(nix::unistd::Uid::from_raw(ent.uid)),
                Some(nix::unistd::Gid::from_raw(ent.gid)),
                nix::unistd::FchownatFlags::NoFollowSymlink,
            )?;
        }
        filetime::set_file_times(
            &dpath,
            filetime::FileTime::from_unix_time(ent.atime, 0),
            filetime::FileTime::from_unix_time(ent.mtime, 0),
        )?;
    }

    return Ok(());
}

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
        while let Some(row) = self.rows.next() {
            if row.is_empty() {
                continue;
            }
            let extract = || -> Result<Root<'l>, Error> {
                let mut ans = row.split('\0');
                let id: u64 = ans.next().ok_or(Error::Msg("Missing id"))?.parse()?;
                let host = ans.next().ok_or(Error::Msg("Missing host"))?;
                let time: i64 = ans.next().ok_or(Error::Msg("Missing time"))?.parse()?;
                let hash = ans.next().ok_or(Error::Msg("Missing hash"))?;
                return Ok(Root {
                    id,
                    host,
                    time,
                    hash,
                });
            };
            match extract() {
                Err(e) => return Some(Err(e)),
                Ok(root) => {
                    if let Some(filter) = self.filter {
                        if *filter != format!("{}", root.id)
                            && *filter
                                != format!(
                                    "{} {}",
                                    root.host,
                                    NaiveDateTime::from_timestamp(root.time, 0)
                                )
                            && *filter != *root.hash
                        {
                            continue;
                        }
                    }
                    return Some(Ok(root));
                }
            }
        }
        return None;
    }
}

pub struct Roots<'l> {
    text: String,
    filter: Option<&'l str>,
}

impl<'l> Roots<'l> {
    pub fn iter(&self) -> RootsIter {
        RootsIter {
            rows: self.text.split("\0\0"),
            filter: self.filter,
        }
    }
}

pub fn roots<'a: 'b, 'b>(
    config: &Config,
    secrets: &Secrets,
    client: &reqwest::Client,
    filter: Option<&'a str>,
) -> Result<Roots<'b>, Error> {
    let url = format!("{}/roots/{}", &config.server, hex::encode(&secrets.bucket));
    let mut res = check_response(
        client
            .get(&url[..])
            .basic_auth(&config.user, Some(&config.password))
            .send()?,
    )?;

    let text = res.text().expect("utf-8");
    return Ok(Roots { filter, text });
}

pub fn run(config: Config, secrets: Secrets, mode: Mode) -> Result<bool, Error> {
    let mut client = reqwest::Client::new();

    let mut entries: Vec<Ent> = Vec::new();
    let mut dirs: HashMap<String, std::path::PathBuf> = HashMap::new();
    let mut dir_stack: Vec<(std::path::PathBuf, String)> = Vec::new();
    let mut bad_dirs: usize = 0;

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs() as i64;

    let mut root_found = false;

    let root: Option<&str> = {
        if let Mode::Restore {
            dry: _,
            dest: _,
            pattern: _,
            root,
            preserve_owner: _,
        } = &mode
        {
            Some(root)
        } else {
            None
        }
    };

    let mut ok = true;

    for root in roots(&config, &secrets, &client, root)?.iter() {
        let root = root?;
        root_found = true;
        if let Mode::Prune { dry, age } = &mode {
            if let Some(age) = age {
                if root.time + 60 * 60 * 24 * (*age as i64) < now {
                    info!(
                        "Removing root {} {}",
                        root.host,
                        NaiveDateTime::from_timestamp(root.time, 0)
                    );
                    if !dry {
                        let url = format!(
                            "{}/roots/{}/{}",
                            &config.server,
                            hex::encode(&secrets.bucket),
                            root.id
                        );
                        check_response(
                            client
                                .delete(&url[..])
                                .basic_auth(&config.user, Some(&config.password))
                                .send()?,
                        )?;
                    }
                    continue;
                }
            }
        }
        dir_stack.push((std::path::PathBuf::new(), root.hash.to_string()));
        info!(
            "Visiting root {} {}",
            root.host,
            NaiveDateTime::from_timestamp(root.time, 0)
        );
        while let Some((path, hash)) = dir_stack.pop() {
            match dirs.entry(hash.clone()) {
                Entry::Occupied(_) => continue,
                Entry::Vacant(e) => e.insert(path.clone()),
            };

            debug!("  Dir {:?}", path);

            let v = match get_chunk_utf8(&mut client, &config, &secrets, &hash) {
                Err(e) => {
                    bad_dirs += 1;
                    error!("Bad dir {} at path {:?}: {:?}", hash, path, e);
                    continue;
                }
                Ok(v) => v,
            };

            for row in v.split("\0\0") {
                match row_ent(&path, row, &mode) {
                    Ok(None) => {}
                    Ok(Some(ent)) => {
                        if ent.etype == EType::Dir {
                            dir_stack
                                .push((ent.path.clone(), ent.chunks.first().unwrap().to_string()));
                        }
                        entries.push(ent);
                    }
                    Err(e) => {
                        bad_dirs += 1;
                        error!(
                            "Bad row '{}` in dir {} at path {:?}: {:?}",
                            row, hash, path, e
                        );
                    }
                }
            }
        }
    }

    if bad_dirs != 0 {
        error!("{} of {} dirs are bad", bad_dirs, dirs.len());
        ok = false;
    }

    match &mode {
        Mode::Validate { full } => {
            if *full {
                let mut files: HashMap<&str, (usize, &PathBuf)> = HashMap::new();
                let mut bytes: u64 = 0;
                for ent in entries.iter() {
                    if ent.etype != EType::File {
                        continue;
                    }
                    for (idx, chunk) in ent.chunks.iter().enumerate() {
                        files.entry(&chunk).or_insert((idx, &ent.path));
                    }
                    bytes += ent.size;
                }
                let mut pb = ProgressBar::new(bytes);
                pb.set_units(pbr::Units::Bytes);
                pb.set_max_refresh_rate(Some(Duration::from_millis(500)));
                let mut bad_files: usize = 0;
                for (hash, (idx, path)) in files.iter() {
                    pb.message(&format!("{:?}:{} ", path, idx));
                    if hash == &"empty" {
                        continue;
                    }
                    match get_chunk(&mut client, &config, &secrets, &hash) {
                        Err(e) => {
                            bad_files += 1;
                            error!(
                                "Bad file chunk {} at path {:?}:{} : {:?}",
                                hash, path, idx, e
                            );
                        }
                        Ok(v) => {
                            pb.add(v.len() as u64);
                        }
                    }
                }
                if bad_files != 0 {
                    error!("{} of {} file chunks are bad", bad_files, files.len());
                    ok = false;
                }
            }
        }
        Mode::Prune { dry, age: _ } => {
            let url = format!("{}/chunks/{}", &config.server, hex::encode(&secrets.bucket));

            let mut content = check_response(
                client
                    .get(&url[..])
                    .basic_auth(&config.user, Some(&config.password))
                    .send()?,
            )?
            .text()?;

            let mut used: HashSet<&str> = HashSet::new();
            for dir in dirs.keys() {
                used.insert(dir);
            }
            for ent in entries.iter() {
                if ent.etype == EType::Link {
                    continue;
                }
                for chunk in ent.chunks.iter() {
                    used.insert(chunk);
                }
            }

            let mut total = 0;
            let mut removed_size = 0;
            let mut remove = Vec::new();
            for row in content.split("\n") {
                if row.is_empty() {
                    continue;
                }
                let mut row = row.split(" ");
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
            if *dry {
                return Ok(ok);
            }

            let mut pb = ProgressBar::new(removed_size);
            pb.set_max_refresh_rate(Some(Duration::from_millis(500)));
            pb.set_units(pbr::Units::Bytes);
            for (idx, (chunk, size)) in remove.iter().enumerate() {
                pb.message(&format!("Chunk {} / {}: ", idx + 1, remove.len()));

                let url = format!(
                    "{}/chunks/{}/{}",
                    &config.server,
                    hex::encode(&secrets.bucket),
                    chunk
                );

                check_response(
                    client
                        .delete(&url[..])
                        .basic_auth(&config.user, Some(&config.password))
                        .send()?,
                )?;

                pb.add(*size);
            }
            pb.finish();
        }
        Mode::Restore {
            dry,
            dest,
            pattern: _,
            root: _,
            preserve_owner,
        } => {
            if !root_found {
                return Err(Error::Msg("Root not found"));
            }
            let bytes = entries.iter().map(|e| e.size).sum();
            let mut pb = ProgressBar::new(bytes);
            pb.set_max_refresh_rate(Some(Duration::from_millis(500)));
            pb.set_units(pbr::Units::Bytes);
            for ent in entries {
                if let Err(e) = recover_entry(
                    &mut pb,
                    &ent,
                    *dry,
                    &dest,
                    *preserve_owner,
                    &mut client,
                    &config,
                    &secrets,
                ) {
                    error!("Unable to recover entry {:?}: {:?}", ent.path, e);
                    return Err(e);
                }
            }
        }
    }
    Ok(ok)
}
