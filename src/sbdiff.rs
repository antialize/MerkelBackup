use clap::{App, Arg};
use std::fs::File;
use std::io::Read;
use std::io::{Seek, SeekFrom, Write};

const BLOCKSIZE: usize = 1024 * 1024;

fn main() -> Result<(), std::io::Error> {
    let matches = App::new("sbdiff")
        .version("0.1")
        .about("Create a binary diff going from file1 to file two")
        .author("Jakob Truelsen <jakob@scalgo.com>")
        .arg(
            Arg::with_name("source")
                .takes_value(true)
                .required(true)
                .help("Path to source file"),
        )
        .arg(
            Arg::with_name("target")
                .takes_value(true)
                .required(true)
                .help("Path to target file"),
        )
        .arg(
            Arg::with_name("patch")
                .takes_value(true)
                .required(true)
                .help("Path to patch turning source to target"),
        )
        .get_matches();

    let mut source = File::open(matches.value_of("source").unwrap())?;
    let mut target = File::open(matches.value_of("target").unwrap())?;
    let mut patch = File::create(matches.value_of("patch").unwrap())?;

    let mut header: [u8; 8 + 8 + 8 + 8 + 32] = [0; 8 + 8 + 8 + 8 + 32];
    patch.write_all(&header)?;

    let mut encoder = zstd::stream::write::Encoder::new(&mut patch, 3)?;
    let mut source_buffer = Vec::new();
    let mut target_buffer = Vec::new();
    source_buffer.resize(BLOCKSIZE, 0);
    target_buffer.resize(BLOCKSIZE, 0);

    let mut target_hasher = blake3::Hasher::new();

    let mut source_size: u64 = 0;
    let mut target_size: u64 = 0;
    loop {
        let mut source_used = 0;
        while source_used != source_buffer.len() {
            let r = source.read(&mut source_buffer[source_used..])?;
            if r == 0 {
                break;
            }
            source_used += r;
        }
        source_size += source_used as u64;

        let mut target_used = 0;
        while target_used != target_buffer.len() {
            let r = target.read(&mut target_buffer[target_used..])?;
            if r == 0 {
                break;
            }
            target_used += r;
        }
        target_hasher.update(&target_buffer[..target_used]);
        target_size += target_used as u64;

        if source_used == 0 && target_used == 0 {
            break;
        }

        let w = usize::max(source_used, target_used);
        source_buffer[source_used..w].fill(0);
        target_buffer[target_used..w].fill(0);

        for (s, t) in source_buffer[..w].iter_mut().zip(target_buffer[..w].iter()) {
            *s ^= t;
        }
        encoder.write(&source_buffer[..w])?;
    }
    encoder.finish()?;

    let hash = target_hasher.finalize();
    patch.seek(SeekFrom::Start(0))?;

    {
        let mut header_writer = &mut header[..];
        header_writer.write_all(&0x27883c14255b919du64.to_le_bytes())?;
        header_writer.write_all(&1u64.to_le_bytes())?;
        header_writer.write_all(&source_size.to_le_bytes())?;
        header_writer.write_all(&target_size.to_le_bytes())?;
        header_writer.write_all(hash.as_bytes())?;
    }

    patch.write_all(&header)?;
    Ok(())
}
