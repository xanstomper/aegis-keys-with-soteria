//! Soteria Aegis key hierarchy — domain-separated keys.
//!
//! This is the faithful Rust re-implementation of
//! `soteria-fs/rust-core/src/key_hierarchy/mod.rs`. The single
//! difference that matters here: **every domain key is an
//! [`AegisKey`]**, i.e. locked + zeroized memory that can never be
//! printed. That is the "wrap everything into Aegis keys" guarantee.
//!
//! ## Derivation
//!
//! ```text
//! passphrase --Argon2id--> K_master (32B, AegisKey)
//! K_master --HKDF-SHA256(master_salt, K_DOMAIN)--> K_<domain>
//! ```
//!
//! Each domain uses a distinct, *immutable* `info` label so the keys
//! are cryptographically independent (compromise of one domain key
//! does not compromise the others). Changing a label is a breaking
//! on-disk-format change, so they are versioned (`v1`).

use crate::kdf::hkdf_sha256;
use crate::{AegisKey, Result};

/// HKDF salt used when expanding the master into domain keys.
pub const MASTER_SALT: &[u8] = b"soteria-kh-v1/master-salt";
/// HKDF salt used for per-file / per-block sub-keys.
pub const SUBKEY_SALT: &[u8] = b"soteria-kh-v1/subkey-salt";

/// Domain-separation `info` labels (immutable; breaking to change).
pub mod info {
    /// Bulk data-encryption key (AEAD).
    pub const K_ENC: &[u8] = b"soteria-kh-v1/k-enc/aead-bulk";
    /// Per-block authentication (MAC) key.
    pub const K_AUTH: &[u8] = b"soteria-kh-v1/k-auth/block-mac";
    /// Metadata encryption key (names, inodes, journal).
    pub const K_META: &[u8] = b"soteria-kh-v1/k-meta/metadata";
    /// Erasure-coding shard encryption key.
    pub const K_SHARD: &[u8] = b"soteria-kh-v1/k-shard/erasure-coding";
    /// FDE XTS sector key.
    pub const K_XTS: &[u8] = b"soteria-kh-v1/k-xts/fde-sector";
    /// File-handle / inode identity key.
    pub const K_HANDLE: &[u8] = b"soteria-kh-v1/k-handle/identity";
}

/// Identifies a key-hierarchy domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Domain {
    Enc,
    Auth,
    Meta,
    Shard,
    Xts,
    Handle,
}

impl Domain {
    /// The immutable HKDF `info` label for this domain.
    pub fn info_tag(self) -> &'static [u8] {
        match self {
            Domain::Enc => info::K_ENC,
            Domain::Auth => info::K_AUTH,
            Domain::Meta => info::K_META,
            Domain::Shard => info::K_SHARD,
            Domain::Xts => info::K_XTS,
            Domain::Handle => info::K_HANDLE,
        }
    }
}

/// The full key hierarchy. Every domain key is a protected [`AegisKey`].
pub struct KeyHierarchy {
    k_enc: AegisKey,
    k_auth: AegisKey,
    k_meta: AegisKey,
    k_shard: AegisKey,
    k_xts: AegisKey,
    k_handle: AegisKey,
}

#[inline]
fn derive(master: &[u8], tag: &[u8]) -> Result<AegisKey> {
    let raw = hkdf_sha256(master, MASTER_SALT, tag)?;
    Ok(AegisKey::new(&raw))
}

impl KeyHierarchy {
    /// Derive the entire hierarchy from a 256-bit master key.
    pub fn from_master(master: &[u8]) -> Result<Self> {
        Ok(Self {
            k_enc: derive(master, info::K_ENC)?,
            k_auth: derive(master, info::K_AUTH)?,
            k_meta: derive(master, info::K_META)?,
            k_shard: derive(master, info::K_SHARD)?,
            k_xts: derive(master, info::K_XTS)?,
            k_handle: derive(master, info::K_HANDLE)?,
        })
    }

    /// Legacy compatibility: a hierarchy where every domain key equals
    /// the master (no HKDF separation). Provided so volumes created
    /// before the hierarchy refactor can still be opened.
    pub fn legacy_single_key(master: &[u8; 32]) -> Self {
        Self {
            k_enc: AegisKey::new32(master),
            k_auth: AegisKey::new32(master),
            k_meta: AegisKey::new32(master),
            k_shard: AegisKey::new32(master),
            k_xts: AegisKey::new32(master),
            k_handle: AegisKey::new32(master),
        }
    }

    /// Borrow a domain key (protected).
    pub fn domain(&self, d: Domain) -> &AegisKey {
        match d {
            Domain::Enc => &self.k_enc,
            Domain::Auth => &self.k_auth,
            Domain::Meta => &self.k_meta,
            Domain::Shard => &self.k_shard,
            Domain::Xts => &self.k_xts,
            Domain::Handle => &self.k_handle,
        }
    }

    /// Derive a per-file / per-block sub-key from a domain key.
    ///
    /// `context` binds the sub-key to a specific object (e.g. a file
    /// path or block index), so distinct contexts yield distinct keys
    /// without re-running the master derivation.
    pub fn subkey(domain: &AegisKey, context: &[u8]) -> Result<AegisKey> {
        let raw = hkdf_sha256(domain.expose(), SUBKEY_SALT, context)?;
        Ok(AegisKey::new(&raw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separates_domains() {
        let master = [0x42u8; 32];
        let h = KeyHierarchy::from_master(&master).unwrap();
        let enc = h.domain(Domain::Enc).expose().to_vec();
        let auth = h.domain(Domain::Auth).expose().to_vec();
        let meta = h.domain(Domain::Meta).expose().to_vec();
        let shard = h.domain(Domain::Shard).expose().to_vec();
        let xts = h.domain(Domain::Xts).expose().to_vec();
        let handle = h.domain(Domain::Handle).expose().to_vec();
        let set = std::collections::HashSet::from([
            enc.clone(),
            auth.clone(),
            meta.clone(),
            shard.clone(),
            xts.clone(),
            handle.clone(),
        ]);
        assert_eq!(set.len(), 6, "domain keys must be cryptographically independent");
    }

    #[test]
    fn deterministic() {
        let master = [7u8; 32];
        let a = KeyHierarchy::from_master(&master).unwrap();
        let b = KeyHierarchy::from_master(&master).unwrap();
        assert!(a.domain(Domain::Enc).ct_eq(b.domain(Domain::Enc)));
        assert!(a.domain(Domain::Meta).ct_eq(b.domain(Domain::Meta)));
    }

    #[test]
    fn legacy_uses_master_directly() {
        let master = [9u8; 32];
        let h = KeyHierarchy::legacy_single_key(&master);
        assert!(h.domain(Domain::Enc).ct_eq(&AegisKey::new32(&master)));
        assert!(h.domain(Domain::Auth).ct_eq(&AegisKey::new32(&master)));
    }

    #[test]
    fn subkey_derivation() {
        let h = KeyHierarchy::from_master(&[1u8; 32]).unwrap();
        let k1 = KeyHierarchy::subkey(h.domain(Domain::Enc), b"file:foo").unwrap();
        let k2 = KeyHierarchy::subkey(h.domain(Domain::Enc), b"file:foo").unwrap();
        let k3 = KeyHierarchy::subkey(h.domain(Domain::Enc), b"file:bar").unwrap();
        assert!(k1.ct_eq(&k2));
        assert!(!k1.ct_eq(&k3));
    }

    #[test]
    fn info_tags_unique() {
        let tags = [
            Domain::Enc.info_tag(),
            Domain::Auth.info_tag(),
            Domain::Meta.info_tag(),
            Domain::Shard.info_tag(),
            Domain::Xts.info_tag(),
            Domain::Handle.info_tag(),
        ];
        let set: std::collections::HashSet<_> = tags.iter().collect();
        assert_eq!(set.len(), tags.len());
    }
}
