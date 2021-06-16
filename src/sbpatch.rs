use clap::{App, Arg};
use std::fs::File;
use std::io::Read;
use std::io::Write;

const BLOCKSIZE: usize = 1024 * 1024;

fn main() -> Result<(), std::io::Error> {
    let matches = App::new("sbdiff")
        .version("0.1")
        .about("Apply binary patch to source")
        .author("Jakob Truelsen <jakob@scalgo.com>")
        .arg(
            Arg::with_name("source")
                .takes_value(true)
                .required(true)
                .help("Path to source file"),
        )
        .arg(
            Arg::with_name("patch")
                .takes_value(true)
                .required(true)
                .help("Path to patch turning source to target"),
        )
        .arg(
            Arg::with_name("target")
                .takes_value(true)
                .required(true)
                .help("Path to target file"),
        )
        .arg(
            Arg::with_name("reverse")
                .long("reverse")
                .short("-r")
                .help("apply patch in reverse"),
        )
        .get_matches();

    let mut source = File::open(matches.value_of("source").unwrap())?;
    let mut patch = File::open(matches.value_of("patch").unwrap())?;
    let mut target = File::create(matches.value_of("target").unwrap())?;
    let reverse = matches.is_present("reverse");

    let mut expected_source_size;
    let mut target_size;

    let mut expected_hash: [u8; 32] = [0; 32];
    {
        let mut header: [u8; 8 + 8 + 8 + 8 + 32] = [0; 8 + 8 + 8 + 8 + 32];
        patch.read_exact(&mut header)?;
        let mut header = &header[..];

        let mut num: [u8; 8] = [0; 8];

        header.read_exact(&mut num)?;
        if u64::from_le_bytes(num) != 0x27883c14255b919du64 {
            eprintln!("Invalid magic {}", u64::from_le_bytes(num));
            std::process::exit(1);
        }

        header.read_exact(&mut num)?;
        if u64::from_le_bytes(num) != 1 {
            eprintln!("Invalid version {}", u64::from_le_bytes(num));
            std::process::exit(1);
        }

        header.read_exact(&mut num)?;
        expected_source_size = u64::from_le_bytes(num) as usize;

        header.read_exact(&mut num)?;
        target_size = u64::from_le_bytes(num) as usize;

        header.read_exact(&mut expected_hash[..])?;
    }

    if reverse {
        std::mem::swap(&mut expected_source_size, &mut target_size);
    }

    let mut decoder = zstd::stream::read::Decoder::new(patch)?;
    let mut source_buffer = Vec::new();
    let mut patch_buffer = Vec::new();
    source_buffer.resize(BLOCKSIZE, 0);
    patch_buffer.resize(BLOCKSIZE, 0);

    let mut hasher = blake3::Hasher::new();
    let mut source_size: usize = 0;

    while target_size != 0 {
        let mut source_used = 0;
        while source_used != source_buffer.len() {
            let r = source.read(&mut source_buffer[source_used..])?;
            if r == 0 {
                break;
            }
            source_used += r;
        }
        source_size += source_used;

        if reverse {
            hasher.update(&source_buffer[..source_used]);
        }

        let mut patch_used = 0;
        while patch_used != patch_buffer.len() {
            let r = decoder.read(&mut patch_buffer[patch_used..])?;
            if r == 0 {
                break;
            }
            patch_used += r;
        }

        if patch_used < source_used {
            eprintln!("patch is smaller than source");
            std::process::exit(1);
        }

        if patch_used == 0 {
            eprintln!("missing data");
            std::process::exit(1);
        }
        source_buffer[source_used..patch_used].fill(0);

        for (s, t) in source_buffer[..patch_used]
            .iter_mut()
            .zip(patch_buffer[..patch_used].iter())
        {
            *s ^= t;
        }
        let os = usize::min(target_size, patch_used);
        if !reverse {
            hasher.update(&source_buffer[..os]);
        }
        target.write_all(&source_buffer[..os])?;
        target_size -= os;
    }

    if expected_source_size != source_size {
        eprintln!("wrong source size");
        std::process::exit(1);
    }

    if hasher.finalize().as_bytes() != &expected_hash {
        eprintln!("wrong hash");
        std::process::exit(1);
    }

    Ok(())
}
