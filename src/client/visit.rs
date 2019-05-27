use chrono::NaiveDateTime;
use crypto::blake2b::Blake2b;
use crypto::digest::Digest;
use crypto::symmetriccipher::SynchronousStreamCipher;
use pbr::ProgressBar;
use shared::{check_response, Config, Error, Secrets};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::io::Read;
use std::time::Duration;
use std::time::SystemTime;

fn get_chunk(
    client: &mut reqwest::Client,
    config: &Config,
    secrets: &Secrets,
    hash: &str,
) -> Result<Vec<u8>, Error> {
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
    res.read_to_end(&mut encrypted)?;

    let mut content = Vec::with_capacity(encrypted.len());
    content.resize(encrypted.len(), 0);
    crypto::chacha20::ChaCha20::new(&secrets.key, &secrets.iv[0..12])
        .process(&encrypted, &mut content);

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
    },
    Restore {
        root: String,
        pattern: String,
        dest: String,
        dry: bool,
    },
}

pub fn run(config: Config, secrets: Secrets, mode: Mode) -> Result<(), Error> {
    let mut client = reqwest::Client::new();

    let url = format!("{}/roots/{}", &config.server, hex::encode(&secrets.bucket));

    let mut res = check_response(
        client
            .get(&url[..])
            .basic_auth(&config.user, Some(&config.password))
            .send()?,
    )?;

    let mut files: HashMap<String, (usize, String)> = HashMap::new();
    let mut dirs: HashMap<String, String> = HashMap::new();
    let mut dir_stack: Vec<(String, String)> = Vec::new();
    let mut bad_dirs: usize = 0;

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs() as i64;

    let mut bytes: u64 = 0;

    let mut root_found = false;

    for row in res.text().expect("utf-8").split("\0\0") {
        if row.is_empty() || root_found {
            continue;
        }
        let ans: Vec<&str> = row.split('\0').collect();
        let id = ans.get(0).ok_or(Error::MissingRow())?.parse::<u64>()?;
        let host = ans.get(1).expect("Missing host");
        let time = ans.get(2).ok_or(Error::MissingRow())?.parse::<i64>()?;
        let hash = ans.get(3).ok_or(Error::MissingRow())?;
        let root = format!("{}_{}", host, NaiveDateTime::from_timestamp(time, 0));
        dir_stack.push(("".to_string(), hash.to_string()));

        match &mode {
            Mode::Validate { full: _ } => (),
            Mode::Restore {
                dry: _,
                dest: _,
                pattern: p,
                root,
            } => {
                if *root != format!("{}", id)
                    && *root != format!("{} {}", host, NaiveDateTime::from_timestamp(time, 0))
                    && root != hash
                {
                    continue;
                }
                root_found = true;
            }
            Mode::Prune { dry } => {
                if time + 60*60/*60*60*24*90*/ < now {
                    info!(
                        "Removing root {} {}",
                        host,
                        NaiveDateTime::from_timestamp(time, 0)
                    );
                    if !dry {
                        let url = format!(
                            "{}/roots/{}/{}",
                            &config.server,
                            hex::encode(&secrets.bucket),
                            id
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
        };
        info!(
            "Visiting root {} {}",
            host,
            NaiveDateTime::from_timestamp(time, 0)
        );
        while let Some((path, hash)) = dir_stack.pop() {
            match dirs.entry(hash.clone()) {
                Entry::Occupied(_) => continue,
                Entry::Vacant(e) => e.insert(path.clone()),
            };

            debug!("  Dir {}", path);

            let v = match get_chunk_utf8(&mut client, &config, &secrets, &hash) {
                Err(e) => {
                    bad_dirs += 1;
                    error!("Bad dir {} at path {}: {:?}", hash, path, e);
                    continue;
                }
                Ok(v) => v,
            };

            for row in v.split("\0\0") {
                if row.is_empty() {
                    continue;
                }
                if let Err(e) = (|| -> Result<(), Error> {
                    let mut ans = row.split('\0');
                    let name = ans.next().ok_or(Error::Msg("Missing name"))?;
                    let type_ = ans.next().ok_or(Error::Msg("Missing type"))?;
                    let size: u64 = ans.next().ok_or(Error::Msg("Missing size"))?.parse()?;
                    let reference = ans.next().ok_or(Error::Msg("Missing reference"))?;
                    let path = format!("{}/{}", &path, &name);

                    if let Mode::Restore {
                        dry,
                        dest,
                        pattern,
                        root: _,
                    } = &mode
                    {
                        if !(path.starts_with(pattern)
                            || (pattern.starts_with(&path) && type_ != "dir"))
                        {
                            return Ok(());
                        }
                        let dpath = format!("{}/{}", dest, path);
                        match type_ {
                            "dir" => {
                                debug!("mkdir {}", dpath);
                                if !dry {
                                    std::fs::create_dir_all(dpath)?;
                                }
                            }
                            "file" => (),
                            "link" => (), //TODO create symlink
                            _ => return Err(Error::Msg("Unknown type")),
                        }
                    }

                    match type_ {
                        "dir" => dir_stack.push((path, reference.to_string())),
                        "file" => {
                            for (idx, hash) in reference.split(",").enumerate() {
                                files.entry(hash.to_string()).or_insert((idx, path.clone()));
                            }
                            bytes += size;
                        }
                        "link" => (),
                        _ => return Err(Error::Msg("Unknown type")),
                    }
                    return Ok(());
                })() {
                    bad_dirs += 1;
                    error!(
                        "Bad row '{}` in dir {} at path {}: {:?}",
                        row, hash, path, e
                    );
                }
            }
        }
    }

    error!("{} of {} dirs are bad", bad_dirs, dirs.len());

    match mode {
        Mode::Validate { full } => {
            if full {
                let mut pb = ProgressBar::new(bytes);
                pb.set_units(pbr::Units::Bytes);
                pb.set_max_refresh_rate(Some(Duration::from_millis(500)));
                let mut bad_files: usize = 0;
                for (hash, (idx, path)) in files.iter() {
                    pb.message(&format!("{}:{} ", path, idx));
                    if hash == "empty" {
                        continue;
                    }
                    match get_chunk(&mut client, &config, &secrets, &hash) {
                        Err(e) => {
                            bad_files += 1;
                            error!("Bad file chunk {} at path {}:{} : {:?}", hash, path, idx, e);
                        }
                        Ok(v) => {
                            pb.add(v.len() as u64);
                        }
                    }
                }
                error!("{} of {} file chunks are bad", bad_files, files.len());
            }
        }
        Mode::Prune { dry } => {
            let url = format!("{}/chunks/{}", &config.server, hex::encode(&secrets.bucket));

            let mut content = check_response(
                client
                    .get(&url[..])
                    .basic_auth(&config.user, Some(&config.password))
                    .send()?,
            )?
            .text()?;

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
                if files.contains_key(chunk) {
                    continue;
                }
                if dirs.contains_key(chunk) {
                    continue;
                }
                removed_size += size;
                remove.push((chunk, size));
            }

            info!("Removing {} of {} chunks", remove.len(), total);
            if dry {
                return Ok(());
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
            pattern,
            root,
        } => {}
    }
    Ok(())
}
