//! ShakeUpWrap, Rust front-end.
//!
//! Same on-disk format as the C `parallel_pipe_suw` branch (32-byte salt header,
//! 4 MiB independent chunks, AAD = salt || index || final), but the crypto comes
//! from XKCP via FFI and the parallelism is expressed with Rayon. Compared with
//! the hand-rolled C pthread pipeline (mutex + 3 condvars + slot ring + ordered
//! writer), the parallel core here is a single `par_iter().map().collect()` whose
//! ordering and data-race freedom are guaranteed by the compiler.

mod xkcp;

use rayon::prelude::*;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::process::exit;

use xkcp::DWrap;

const CHUNK: usize = 4 * 1024 * 1024;
const TAGLEN: usize = 64;
const KEY_SIZE: usize = 64;
const CAPACITY: u32 = 512;
const RHO: u32 = (1600 - CAPACITY - 64) / 8; // 128
const SALT_SIZE: usize = 32;
const AAD_SIZE: usize = 48;
const FINAL_FALSE: u8 = 0;
const FINAL_TRUE: u8 = 1;

fn make_aad(salt: &[u8], index: u64, final_flag: u8) -> [u8; AAD_SIZE] {
    let mut aad = [0u8; AAD_SIZE];
    aad[..SALT_SIZE].copy_from_slice(salt);
    aad[SALT_SIZE..SALT_SIZE + 8].copy_from_slice(&index.to_le_bytes());
    aad[SALT_SIZE + 8] = final_flag;
    aad
}

fn random_bytes(buf: &mut [u8]) -> io::Result<()> {
    let mut f = std::fs::File::open("/dev/urandom")?;
    f.read_exact(buf)
}

struct Args {
    encrypt: bool,
    decrypt: bool,
    key: Option<String>,
    output: Option<String>,
}

fn usage() {
    eprintln!(
        "Usage:\n  shakeupwrap-rs -e -k KEYFILE [-o OUTFILE]\n  shakeupwrap-rs -d -k KEYFILE [-o OUTFILE]\n\nInput is read from stdin; output goes to stdout unless -o is given."
    );
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args { encrypt: false, decrypt: false, key: None, output: None };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-e" | "--encrypt" => a.encrypt = true,
            "-d" | "--decrypt" => a.decrypt = true,
            "-k" | "--key" => a.key = Some(it.next().ok_or("-k requires an argument")?),
            "-o" | "--output" => a.output = Some(it.next().ok_or("-o requires an argument")?),
            "-h" | "--help" => {
                usage();
                exit(0);
            }
            other if other.starts_with('-') => {
                return Err(format!("Unknown option: {other}"));
            }
            other => return Err(format!("Unexpected positional argument: {other}")),
        }
    }
    if a.encrypt && a.decrypt {
        return Err("Invalid mode: specify exactly one of -e or -d".into());
    }
    if !a.encrypt && !a.decrypt {
        return Err("Missing required mode: specify -e or -d".into());
    }
    if a.key.is_none() {
        return Err("Missing required key path: -k KEYFILE".into());
    }
    Ok(a)
}

fn open_output(path: &Option<String>) -> Result<Box<dyn Write>, String> {
    match path {
        Some(p) => {
            // Refuse to overwrite an existing output, like the C tool.
            let f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(p)
                .map_err(|e| {
                    if e.kind() == io::ErrorKind::AlreadyExists {
                        "Output file already exists".to_string()
                    } else {
                        format!("cannot open output: {e}")
                    }
                })?;
            Ok(Box::new(io::BufWriter::new(f)))
        }
        None => Ok(Box::new(io::BufWriter::new(io::stdout()))),
    }
}

fn create_key(path: &str) -> Result<[u8; KEY_SIZE], String> {
    let mut key = [0u8; KEY_SIZE];
    random_bytes(&mut key).map_err(|e| format!("entropy failure: {e}"))?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                "Key file already exists".to_string()
            } else {
                format!("cannot create key file: {e}")
            }
        })?;
    f.write_all(&key).map_err(|e| format!("key write failed: {e}"))?;
    Ok(key)
}

fn read_key(path: &str) -> Result<[u8; KEY_SIZE], String> {
    let data = std::fs::read(path).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            "Key file does not exist".to_string()
        } else {
            format!("cannot read key file: {e}")
        }
    })?;
    if data.len() != KEY_SIZE {
        return Err("Invalid key file size".into());
    }
    let mut key = [0u8; KEY_SIZE];
    key.copy_from_slice(&data);
    Ok(key)
}

fn encrypt(args: &Args) -> Result<(), String> {
    let key_path = args.key.as_ref().unwrap();

    // Reject an existing key before reading any input.
    if std::path::Path::new(key_path).exists() {
        return Err("Key file already exists".into());
    }

    let mut input = Vec::new();
    io::stdin()
        .read_to_end(&mut input)
        .map_err(|e| format!("input read failed: {e}"))?;

    // Open the output before creating the key, so an existing output fails
    // without leaving a fresh key behind.
    let mut out = open_output(&args.output)?;

    let key = create_key(key_path)?;
    let base = DWrap::new(&key, TAGLEN as u32, RHO, CAPACITY);

    let mut salt = [0u8; SALT_SIZE];
    random_bytes(&mut salt).map_err(|e| format!("entropy failure: {e}"))?;

    // Split into independent chunks; the empty input is one empty final chunk.
    let chunks: Vec<&[u8]> = if input.is_empty() {
        vec![&input[..]]
    } else {
        input.chunks(CHUNK).collect()
    };
    let n = chunks.len();

    // The parallel core: one data-race-free, order-preserving expression.
    let cts: Vec<Vec<u8>> = chunks
        .par_iter()
        .enumerate()
        .map(|(i, p)| {
            let mut inst = base.clone();
            let final_flag = if i == n - 1 { FINAL_TRUE } else { FINAL_FALSE };
            let aad = make_aad(&salt, i as u64, final_flag);
            let mut out = vec![0u8; p.len() + TAGLEN];
            inst.wrap(&mut out, &aad, p);
            out
        })
        .collect();

    out.write_all(&salt).map_err(|e| format!("output write failed: {e}"))?;
    for ct in &cts {
        out.write_all(ct).map_err(|e| format!("output write failed: {e}"))?;
    }
    out.flush().map_err(|e| format!("output flush failed: {e}"))?;
    Ok(())
}

fn decrypt(args: &Args) -> Result<(), String> {
    let key_path = args.key.as_ref().unwrap();
    let key = read_key(key_path)?;
    let base = DWrap::new(&key, TAGLEN as u32, RHO, CAPACITY);

    let mut input = Vec::new();
    io::stdin()
        .read_to_end(&mut input)
        .map_err(|e| format!("input read failed: {e}"))?;

    if input.len() < SALT_SIZE {
        return Err("Invalid ciphertext".into());
    }
    let mut salt = [0u8; SALT_SIZE];
    salt.copy_from_slice(&input[..SALT_SIZE]);
    let ct = &input[SALT_SIZE..];

    if ct.is_empty() {
        return Err("Invalid ciphertext".into());
    }

    let enc_chunk = CHUNK + TAGLEN;
    let full = ct.len() / enc_chunk;
    let rem = ct.len() % enc_chunk;
    let (nchunks, last_len) = if rem == 0 {
        (full, enc_chunk)
    } else {
        (full + 1, rem)
    };

    if last_len < TAGLEN {
        return Err("Invalid ciphertext".into());
    }
    // An empty final chunk (tag only) is valid only for empty plaintext.
    if last_len == TAGLEN && nchunks != 1 {
        return Err("Invalid ciphertext".into());
    }

    // Parallel decrypt+verify; order preserved by the collect.
    let results: Vec<Result<Vec<u8>, ()>> = (0..nchunks)
        .into_par_iter()
        .map(|i| {
            let off = i * enc_chunk;
            let len = if i == nchunks - 1 { last_len } else { enc_chunk };
            let c = &ct[off..off + len];
            let final_flag = if i == nchunks - 1 { FINAL_TRUE } else { FINAL_FALSE };
            let aad = make_aad(&salt, i as u64, final_flag);
            let mut out = vec![0u8; len - TAGLEN];
            let mut inst = base.clone();
            if inst.unwrap(&mut out, &aad, c) {
                Ok(out)
            } else {
                Err(())
            }
        })
        .collect();

    if results.iter().any(|r| r.is_err()) {
        return Err("Authentication failed".into());
    }

    let mut out = open_output(&args.output)?;
    for r in &results {
        out.write_all(r.as_ref().unwrap())
            .map_err(|e| format!("output write failed: {e}"))?;
    }
    out.flush().map_err(|e| format!("output flush failed: {e}"))?;
    Ok(())
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Error: {e}");
            usage();
            exit(2);
        }
    };

    let res = if args.encrypt { encrypt(&args) } else { decrypt(&args) };

    if let Err(e) = res {
        eprintln!("Error: {e}");
        exit(1);
    }
}
