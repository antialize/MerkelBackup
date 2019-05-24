use chrono::NaiveDateTime;
use crypto::blake2b::Blake2b;
use crypto::digest::Digest;
use crypto::symmetriccipher::SynchronousStreamCipher;
use shared::{Config, Secrets};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::io::Read;

enum Error {
    Chunk(&'static str),
}

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

    let mut res = client
        .get(&url[..])
        .basic_auth(&config.user, Some(&config.password))
        .send()
        .map_err(|_| Error::Chunk("Failed to send request"))?;

    if res.status() != reqwest::StatusCode::OK {
        return Err(Error::Chunk("Invalid status code"));
    }

    let len = res.content_length().unwrap_or(0);
    let mut encrypted = Vec::with_capacity(len as usize);
    res.read_to_end(&mut encrypted)
        .map_err(|_| Error::Chunk("Failed to read responce"))?;

    let mut content = Vec::with_capacity(encrypted.len());
    content.resize(encrypted.len(), 0);
    crypto::chacha20::ChaCha20::new(&secrets.key, &secrets.iv[0..12])
        .process(&encrypted, &mut content);

    let mut hasher = Blake2b::new(256 / 8);
    hasher.input(&secrets.seed);
    hasher.input(&content);

    if hasher.result_str() != hash {
        return Err(Error::Chunk("Invalid hash"));
    }

    return Ok(content);
}

fn get_chunk_utf8(
    client: &mut reqwest::Client,
    config: &Config,
    secrets: &Secrets,
    hash: &str,
) -> Result<String, Error> {
    String::from_utf8(get_chunk(client, config, secrets, hash)?)
        .map_err(|_| Error::Chunk("Not utf8"))
}

pub fn run(config: Config, secrets: Secrets, full: bool) {
    let mut client = reqwest::Client::new();

    let url = format!("{}/roots/{}", &config.server, hex::encode(&secrets.bucket));

    let mut res = client
        .get(&url[..])
        .basic_auth(&config.user, Some(&config.password))
        .send()
        .expect("Send failed");

    if res.status() != reqwest::StatusCode::OK {
        panic!("Unable to get roots")
    }

    let mut files: HashMap<String, (usize, String)> = HashMap::new();
    let mut dirs: HashMap<String, String> = HashMap::new();
    let mut dir_stack: Vec<(String, String)> = Vec::new();
    let mut bad_dirs: usize = 0;

    for row in res.text().expect("utf-8").split("\0\0") {
        if row.is_empty() {
            continue;
        }
        let ans: Vec<&str> = row.split('\0').collect();
        let _id = ans
            .get(0)
            .expect("Missing id")
            .parse::<u64>()
            .expect("Bad id");
        let host = ans.get(1).expect("Missing host");
        let time = ans
            .get(2)
            .expect("Missing time")
            .parse::<i64>()
            .expect("Bad time");
        let hash = ans.get(3).expect("Missing hash");
        dir_stack.push((
            format!("{}_{}", host, NaiveDateTime::from_timestamp(time, 0)),
            hash.to_string(),
        ));
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
                Err(Error::Chunk(msg)) => {
                    bad_dirs += 1;
                    error!("Bad dir {} at path {}: {}", hash, path, msg);
                    continue;
                }
                Ok(v) => v,
            };

            for row in v.split("\0\0") {
                if row.is_empty() {
                    continue;
                }
                if let Err(Error::Chunk(msg)) = (|| -> Result<(), Error> {
                    let ans: Vec<&str> = row.split('\0').collect();
                    let name = ans.get(0).ok_or(Error::Chunk("Missing name"))?;
                    let typ = ans.get(1).ok_or(Error::Chunk("Missing type"))?;
                    let reference = ans.get(2).ok_or(Error::Chunk("Missing reference"))?;
                    let path = format!("{}/{}", &path, &name);
                    match typ {
                        &"dir" => dir_stack.push((path, reference.to_string())),
                        &"file" => {
                            for (idx, hash) in reference.split(",").enumerate() {
                                files.entry(hash.to_string()).or_insert((idx, path.clone()));
                            }
                        }
                        &"link" => (),
                        _ => return Err(Error::Chunk("Unknown type")),
                    }
                    return Ok(());
                })() {
                    bad_dirs += 1;
                    error!("Bad row '{}` in dir {} at path {}: {}", row, hash, path, msg);
                }
            }
        }
    }

    error!("{} of {} dirs are bad", bad_dirs, dirs.len());

    //if ! full {return;}
    let mut bad_files: usize = 0;
    for (hash, (idx, path)) in files.iter() {
        debug!("  File {}:{} : {}", path, idx, hash);
        if hash == "empty" {
            continue;
        }
        if let Err(Error::Chunk(msg)) = get_chunk(&mut client, &config, &secrets, &hash) {
            bad_files += 1;
            error!("Bad file chunk {} at path {}:{} : {}", hash, path, idx, msg);
        }
    }

    error!("{} of {} file chunks are bad", bad_files, files.len());
}
