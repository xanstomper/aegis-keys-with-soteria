//! Authenticated encryption — Soteria Aegis AEAD surface.
//!
//! Wraps the two AEAD primitives used by `soteria-fs`:
//! * `XChaCha20-Poly1305` (RFC 8439) — default bulk cipher, 24-byte
//!   random nonce.
//! * `AES-256-GCM` (FIPS SP 800-38D) — used for key-slot wrapping.
//!
//! Random nonces are drawn from the OS CSPRNG (`OsRng`). The key is
//! held in a `Zeroizing` buffer so it is wiped on drop.

use crate::error::{AegisError, Result};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

/// AEAD algorithm selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadAlgo {
    /// AES-256-GCM with a 12-byte nonce.
    Aes256Gcm,
    /// XChaCha20-Poly1305 with a 24-byte nonce (default).
    XChaCha20Poly1305,
}

/// A ready-to-use AEAD cipher bound to a 256-bit key.
pub struct AeadCipher {
    algo: AeadAlgo,
    key: Zeroizing<[u8; 32]>,
}

impl AeadCipher {
    /// Bind a cipher to a 32-byte key. The key is copied into a
    /// zeroizing buffer and never persisted elsewhere.
    pub fn new(algo: AeadAlgo, key: &[u8; 32]) -> Self {
        Self {
            algo,
            key: Zeroizing::new(*key),
        }
    }

    /// Seal `plaintext` with `aad`, returning `(nonce, ciphertext)`.
    /// The ciphertext includes the AEAD authentication tag.
    pub fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        match self.algo {
            AeadAlgo::Aes256Gcm => {
                let mut nonce = [0u8; 12];
                OsRng.fill_bytes(&mut nonce);
                let cipher = Aes256Gcm::new_from_slice(self.key.as_ref())
                    .map_err(|_| AegisError::AeadSeal)?;
                let ct = cipher
                    .encrypt(
                        AesNonce::from_slice(&nonce),
                        Payload { msg: plaintext, aad },
                    )
                    .map_err(|_| AegisError::AeadSeal)?;
                Ok((nonce.to_vec(), ct))
            }
            AeadAlgo::XChaCha20Poly1305 => {
                let mut nonce = [0u8; 24];
                OsRng.fill_bytes(&mut nonce);
                let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_ref())
                    .map_err(|_| AegisError::AeadSeal)?;
                let ct = cipher
                    .encrypt(
                        XNonce::from_slice(&nonce),
                        Payload { msg: plaintext, aad },
                    )
                    .map_err(|_| AegisError::AeadSeal)?;
                Ok((nonce.to_vec(), ct))
            }
        }
    }

    /// Open `ciphertext` authenticated against `aad` using `nonce`.
    /// Returns the plaintext, or [`AegisError::AeadOpen`] on any
    /// authentication failure (tampering or wrong key).
    pub fn open(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        match self.algo {
            AeadAlgo::Aes256Gcm => {
                if nonce.len() != 12 {
                    return Err(AegisError::AeadOpen);
                }
                let cipher = Aes256Gcm::new_from_slice(self.key.as_ref())
                    .map_err(|_| AegisError::AeadOpen)?;
                cipher
                    .decrypt(
                        AesNonce::from_slice(nonce),
                        Payload {
                            msg: ciphertext,
                            aad,
                        },
                    )
                    .map_err(|_| AegisError::AeadOpen)
            }
            AeadAlgo::XChaCha20Poly1305 => {
                if nonce.len() != 24 {
                    return Err(AegisError::AeadOpen);
                }
                let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_ref())
                    .map_err(|_| AegisError::AeadOpen)?;
                cipher
                    .decrypt(
                        XNonce::from_slice(nonce),
                        Payload {
                            msg: ciphertext,
                            aad,
                        },
                    )
                    .map_err(|_| AegisError::AeadOpen)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(algo: AeadAlgo) {
        let key = [0x07u8; 32];
        let cipher = AeadCipher::new(algo, &key);
        let pt = b"top secret payload";
        let aad = b"block:17";
        let (nonce, ct) = cipher.seal(pt, aad).unwrap();
        let back = cipher.open(&nonce, &ct, aad).unwrap();
        assert_eq!(back, pt);
        // Tampered AAD must fail authentication.
        assert!(cipher.open(&nonce, &ct, b"block:18").is_err());
        // Tampered ciphertext must fail authentication.
        let mut ct2 = ct.clone();
        ct2[0] ^= 0x01;
        assert!(cipher.open(&nonce, &ct2, aad).is_err());
    }

    #[test]
    fn xchacha_roundtrip() {
        roundtrip(AeadAlgo::XChaCha20Poly1305);
    }

    #[test]
    fn aes_gcm_roundtrip() {
        roundtrip(AeadAlgo::Aes256Gcm);
    }
}
