//! Soteria Aegis — error type.
//!
//! Errors are intentionally opaque: none of them echo key material,
//! passphrases, salts, or nonces back to the caller (defence against
//! accidental secret leakage through error logs).

use thiserror::Error;

/// Errors produced by the Soteria Aegis key-management layer.
#[derive(Error, Debug)]
pub enum AegisError {
    /// Argon2id key derivation failed (e.g. invalid parameters).
    #[error("Argon2id key derivation failed")]
    Argon2,

    /// HKDF expansion produced an error (unsupported length, etc.).
    #[error("HKDF key derivation failed")]
    Hkdf,

    /// AEAD seal (encrypt) failed.
    #[error("AEAD seal failed")]
    AeadSeal,

    /// AEAD open (decrypt) failed — this is the auth-tag-mismatch path
    /// and is the *expected* outcome on a wrong key or tampered data.
    #[error("AEAD open failed (authentication tag mismatch)")]
    AeadOpen,

    /// A key of an unexpected length was supplied.
    #[error("invalid key length: expected {expected}, got {got}")]
    KeyLength { expected: usize, got: usize },

    /// A key slot could not be opened with the supplied passphrase.
    #[error("key slot unseal failed (wrong passphrase or corrupt slot)")]
    SlotUnseal,

    /// No enabled slot could be opened with any tried passphrase.
    #[error("no enabled key slot could be unsealed")]
    NoSlotUnsealed,

    /// Attempted to revoke the last remaining enabled slot.
    #[error("cannot revoke the last enabled key slot")]
    LastSlotRevocation,

    /// The slot table is full.
    #[error("key slot table is full (max {0} slots)")]
    SlotTableFull(usize),

    /// The slot-table header failed its BLAKE3 keyed-HMAC check.
    #[error("slot-table header integrity check failed (HMAC mismatch)")]
    HeaderIntegrity,

    /// The decrypted master key did not match the volume's expected
    /// key-check value (key-injection verification failed).
    #[error("decrypted master key does not match the volume verifier")]
    VolumeMismatch,

    /// (De)serialization of a slot table failed.
    #[error("slot-table serialization error")]
    Serialization,
}

pub type Result<T> = std::result::Result<T, AegisError>;
