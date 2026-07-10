//! `aegis` — command-line launcher for the wrapped Soteria Aegis keys.
//!
//! A small, dependency-light CLI so you can actually *use* the
//! protected `AegisKey` vault from the terminal:
//!
//! ```text
//! aegis init   -p <pass> -o <vault.aegis>              # create a vault + key slot
//! aegis add    -p <pass> -f <vault> -n <newpass>       # add a multi-user slot
//! aegis seal   -p <pass> -f <vault> -i <in> -o <out>   # encrypt a file (K_enc)
//! aegis open   -p <pass> -f <vault> -i <in> -o <out>   # decrypt a file
//! aegis verify -p <pass> -f <vault>                    # verify key-injection
//! ```
//!
//! The on-disk vault file is: `AEGIS` magic || u8 version ||
//! header_salt[32] || KeySlotTable bytes (the `SOTK` format with its
//! BLAKE3 keyed-HMAC header). Keys never touch the filesystem in
//! plaintext — only the AEAD-wrapped master is stored.

use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::Write;
use std::process;

use soteria_aegis::{AegisAlgoTag, AegisVault, Domain};

const MAGIC: &[u8; 5] = b"AEGIS";
const VERSION: u8 = 1;
/// Public demo salt for the master-key Argon2id derivation. In
/// production this should be random per vault; the per-slot salts
/// inside each key slot are already random.
const MASTER_SALT: &[u8] = b"aegis-cli-salt-v1";
const MEM_KIB: u32 = 32 * 1024;
const ITERS: u32 = 2;
const AAD: &[u8] = b"aegis-cli";

fn fail(msg: &str) -> ! {
    eprintln!("aegis: error: {msg}");
    process::exit(1);
}

/// Tiny flag parser: `<cmd> -key value -key value ...`
fn parse_args(argv: &[String]) -> (String, HashMap<String, String>) {
    if argv.len() < 2 {
        print_help();
        process::exit(1);
    }
    let cmd = argv[1].clone();
    let mut map = HashMap::new();
    let mut i = 2;
    while i < argv.len() {
        let a = &argv[i];
        if let Some(key) = a.strip_prefix('-') {
            let val = argv.get(i + 1).cloned().unwrap_or_default();
            map.insert(key.to_string(), val);
            i += 2;
        } else {
            i += 1;
        }
    }
    (cmd, map)
}

fn req<'a>(m: &'a HashMap<String, String>, k: &str) -> &'a str {
    m.get(k)
        .map(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| fail(&format!("missing -{k}")))
}

fn print_help() {
    eprintln!(
        "aegis - wrapped Soteria Aegis keys\n\
         usage:\n  \
         aegis init   -p <pass> -o <vault.aegis>\n  \
         aegis add    -p <pass> -f <vault> -n <newpass>\n  \
         aegis seal   -p <pass> -f <vault> -i <in>  -o <out>\n  \
         aegis open   -p <pass> -f <vault> -i <in>  -o <out>\n  \
         aegis verify -p <pass> -f <vault>"
    );
}

/// Load a vault file -> (slot-table bytes, header_salt).
fn read_vault(path: &str) -> (Vec<u8>, [u8; 32]) {
    let buf = fs::read(path).unwrap_or_else(|e| fail(&format!("cannot read {path}: {e}")));
    if buf.len() < 5 + 1 + 32 {
        fail("vault file is too short / corrupt");
    }
    if &buf[..5] != MAGIC {
        fail("not an aegis vault file");
    }
    if buf[5] != VERSION {
        fail("unsupported vault version");
    }
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&buf[6..38]);
    (buf[38..].to_vec(), salt)
}

/// Write a vault file from slot-table bytes + header salt.
fn write_vault(path: &str, slot_bytes: &[u8], salt: &[u8; 32]) {
    let mut out = Vec::with_capacity(38 + slot_bytes.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(salt);
    out.extend_from_slice(slot_bytes);
    fs::write(path, out).unwrap_or_else(|e| fail(&format!("cannot write {path}: {e}")));
}

/// Open (unlock) a vault file into a live `AegisVault`.
fn open_vault(path: &str, pass: &str) -> AegisVault {
    let (slot_bytes, salt) = read_vault(path);
    let mut v = AegisVault::unlock(b"ignored", MASTER_SALT, MEM_KIB, ITERS).unwrap();
    v.open_from_slots(&slot_bytes, &salt, pass.as_bytes())
        .unwrap_or_else(|e| fail(&format!("cannot open vault (wrong passphrase?): {e}")));
    v
}

fn main() {
    let argv: Vec<String> = env::args().collect();
    let (cmd, args) = parse_args(&argv);

    match cmd.as_str() {
        "init" => {
            let pass = req(&args, "p").to_string();
            let out = req(&args, "o").to_string();
            let mut v = AegisVault::unlock(pass.as_bytes(), MASTER_SALT, MEM_KIB, ITERS)
                .unwrap_or_else(|e| fail(&format!("key derivation failed: {e}")));
            v.seal_slots(pass.as_bytes())
                .unwrap_or_else(|e| fail(&format!("seal failed: {e}")));
            let bytes = v.slots_to_bytes().expect("slot bytes");
            let salt = v.slots_header_salt().expect("header salt");
            write_vault(&out, &bytes, &salt);
            println!("aegis: created vault '{out}' (1 key slot, master AEAD-wrapped).");
        }
        "add" => {
            let pass = req(&args, "p").to_string();
            let newp = req(&args, "n").to_string();
            let file = req(&args, "f").to_string();
            let mut v = open_vault(&file, &pass);
            let idx = v
                .add_slot(newp.as_bytes())
                .unwrap_or_else(|e| fail(&format!("add slot failed: {e}")));
            let bytes = v.slots_to_bytes().expect("slot bytes");
            let salt = v.slots_header_salt().expect("header salt");
            write_vault(&file, &bytes, &salt);
            println!("aegis: added user slot #{idx} to '{file}'.");
        }
        "seal" => {
            let pass = req(&args, "p").to_string();
            let file = req(&args, "f").to_string();
            let inp = req(&args, "i").to_string();
            let outp = req(&args, "o").to_string();
            let v = open_vault(&file, &pass);
            let data = fs::read(&inp).unwrap_or_else(|e| fail(&format!("cannot read {inp}: {e}")));
            let (nonce, ct) = v
                .encrypt(Domain::Enc, &data, AAD, AegisAlgoTag::XChaCha20Poly1305)
                .unwrap_or_else(|e| fail(&format!("encrypt failed: {e}")));
            // Blob: algo(0=XChaCha) || nonce_len || nonce || ct
            let mut blob = Vec::with_capacity(2 + nonce.len() + ct.len());
            blob.push(0u8);
            blob.push(nonce.len() as u8);
            blob.extend_from_slice(&nonce);
            blob.extend_from_slice(&ct);
            fs::write(&outp, blob).unwrap_or_else(|e| fail(&format!("cannot write {outp}: {e}")));
            println!("aegis: sealed '{inp}' -> '{outp}' ({} bytes ciphertext).", ct.len());
        }
        "open" => {
            let pass = req(&args, "p").to_string();
            let file = req(&args, "f").to_string();
            let inp = req(&args, "i").to_string();
            let outp = req(&args, "o").to_string();
            let v = open_vault(&file, &pass);
            let blob = fs::read(&inp).unwrap_or_else(|e| fail(&format!("cannot read {inp}: {e}")));
            if blob.len() < 2 {
                fail("ciphertext blob too short");
            }
            let nlen = blob[1] as usize;
            if blob.len() < 2 + nlen {
                fail("ciphertext blob corrupt");
            }
            let nonce = &blob[2..2 + nlen];
            let ct = &blob[2 + nlen..];
            let pt = v
                .decrypt(Domain::Enc, nonce, ct, AAD, AegisAlgoTag::XChaCha20Poly1305)
                .unwrap_or_else(|e| fail(&format!("decrypt failed (bad key/passphrase?): {e}")));
            fs::write(&outp, pt).unwrap_or_else(|e| fail(&format!("cannot write {outp}: {e}")));
            println!("aegis: opened '{inp}' -> '{outp}'.");
        }
        "verify" => {
            let pass = req(&args, "p").to_string();
            let file = req(&args, "f").to_string();
            let v = open_vault(&file, &pass);
            if v.verify_volume() {
                println!("aegis: OK — master key correctly injected & verified.");
            } else {
                fail("volume key-check did not verify");
            }
        }
        other => {
            eprintln!("aegis: unknown command '{other}'");
            print_help();
            process::exit(1);
        }
    }

    let _ = std::io::stdout().flush();
}
