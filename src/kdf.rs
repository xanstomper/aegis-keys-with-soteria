//! Key-derivation functions — Soteria Aegis TCB surface.
//!
//! This mirrors `soteria-fs/rust-core/src/crypto_engine/kdf.rs`:
//!
//! * [`argon2id_root`] derives the 256-bit **master key** from a
//!   passphrase using Argon2id (RFC 9106).
//! * [`hkdf_sha256`] performs HKDF-SHA-256 (RFC 5869) expansion used
//!   for domain separation and sub-key derivation.
//!
//! Every intermediate is held in a `Zeroizing` buffer and the master
//! is returned wrapped as an [`AegisKey`].

use crate::{error::AegisError, AegisKey};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Master-key length in bytes (256 bits).
pub const MASTER_LEN: usize = 32;

/// Derive the 256-bit master key from a passphrase via Argon2id.
///
/// `memory_kib` is the memory cost in KiB; `iterations` the time cost;
/// `parallelism` is fixed at 1 (matching the upstream TCB). The
/// resulting key is wrapped in an [`AegisKey`] (locked + zeroized).
pub fn argon2id_root(
    passphrase: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
) -> Result<AegisKey, AegisError> {
    let params = Params::new(memory_kib, iterations, 1, Some(MASTER_LEN))
        .map_err(|_| AegisError::Argon2)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; MASTER_LEN]);
    argon2
        .hash_password_into(passphrase, salt, out.as_mut())
        .map_err(|_| AegisError::Argon2)?;
    Ok(AegisKey::new(out.as_ref()))
}

/// HKDF-SHA-256 expand producing a fixed 32-byte output key material.
///
/// `salt` is the HKDF salt, `info` the domain-separation label. Both
/// are treated as public (they are not secret in the Soteria scheme).
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; 32], AegisError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).map_err(|_| AegisError::Hkdf)?;
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2id_deterministic() {
        let salt = [0x11u8; 16];
        let a = argon2id_root(b"correct horse", &salt, 64, 3).unwrap();
        let b = argon2id_root(b"correct horse", &salt, 64, 3).unwrap();
        assert!(a.ct_eq(&b));
    }

    #[test]
    fn argon2id_sensitive_to_passphrase() {
        let salt = [0x22u8; 16];
        let a = argon2id_root(b"alpha", &salt, 64, 3).unwrap();
        let b = argon2id_root(b"beta", &salt, 64, 3).unwrap();
        assert!(!a.ct_eq(&b));
    }

    #[test]
    fn hkdf_distinct_info_distinct_output() {
        let ikm = [0x33u8; 32];
        let x = hkdf_sha256(&ikm, b"salt", b"info-A").unwrap();
        let y = hkdf_sha256(&ikm, b"salt", b"info-B").unwrap();
        assert_ne!(x, y);
        let x2 = hkdf_sha256(&ikm, b"salt", b"info-A").unwrap();
        assert_eq!(x, x2);
    }
}
