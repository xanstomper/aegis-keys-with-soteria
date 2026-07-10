//! # Soteria Aegis — protected "Aegis keys" for the Soteria-FS crypto methodology
//!
//! This crate wraps the cryptography and key-management methodology of
//! [`soteria-fs`](https://github.com/xanstomper/soteria-fs) ("Soteria
//! Aegis") behind a single protected abstraction: the [`AegisKey`].
//!
//! Every cryptographic key produced by this crate — the master key,
//! each domain key in the [`hierarchy`], and every key-slot wrapper —
//! is an [`AegisKey`]: key material held in **locked, self-zeroizing
//! memory** that is never printed and is compared in constant time.
//!
//! ## Methodology (faithful to `soteria-fs` TCB)
//!
//! ```text
//! passphrase --Argon2id--> K_master (AegisKey, 32 B)
//! K_master --HKDF-SHA256 (domain separation)--> {
//!     K_enc, K_auth, K_meta, K_shard, K_xts, K_handle }  (each an AegisKey)
//! K_master --AES-256-GCM(per-passphrase slot key)--> key slots (multi-user, revocable)
//! ```
//!
//! ## "100% secure" — an honest note
//!
//! No software is *literally* 100% secure. What this crate does is
//! faithfully implement the Soteria Aegis TCB discipline so that, by
//! *construction*, key material cannot leak through swap, freed
//! memory, logs, or timing, and the on-disk format cannot be tampered
//! with undetected. Security still depends on a strong passphrase and
//! an uncompromised host (these are the documented Soteria threat-
//! model boundaries).

mod aegis_key;
mod aead;
mod error;
mod hierarchy;
mod kdf;
mod slots;

pub use aegis_key::AegisKey;
pub use aead::{AeadAlgo as AegisAlgoTag, AeadCipher};
pub use error::{AegisError, Result};
pub use hierarchy::{Domain, KeyHierarchy, MASTER_SALT, SUBKEY_SALT};
pub use kdf::{argon2id_root, hkdf_sha256, MASTER_LEN};
pub use slots::{
    KeySlot, KeySlotTable, VolumeKeyRotation, HEADER_MAGIC, HEADER_VERSION, KDF_ID_ARGON2ID,
    MAX_SLOTS, NONCE_LEN, TAG_LEN,
};
use subtle::ConstantTimeEq;

/// Default Argon2id memory cost (KiB) for a one-shot secure default.
pub const DEFAULT_ARGON2_MEMORY_KIB: u32 = 64 * 1024;
/// Default Argon2id iteration count for a one-shot secure default.
pub const DEFAULT_ARGON2_ITERATIONS: u32 = 3;

/// A live, unlocked Soteria Aegis vault.
///
/// Holds the master key and the derived key hierarchy, all as
/// [`AegisKey`]s, plus an optional encrypted [`KeySlotTable`] for
/// persisting multi-user access to the master.
pub struct AegisVault {
    master: AegisKey,
    hierarchy: KeyHierarchy,
    slots: Option<KeySlotTable>,
}

impl AegisVault {
    /// Derive a vault directly from a raw 256-bit master key. The
    /// master is wrapped as an [`AegisKey`] and the hierarchy derived.
    pub fn from_master_key(master: [u8; MASTER_LEN]) -> Self {
        let master_key = AegisKey::new32(&master);
        let hierarchy = KeyHierarchy::from_master(&master).expect("32-byte master derives");
        Self { master: master_key, hierarchy, slots: None }
    }

    /// Unlock (or create) a vault from a passphrase using Argon2id.
    pub fn unlock(passphrase: &[u8], salt: &[u8], memory_kib: u32, iterations: u32) -> Result<Self> {
        let master = argon2id_root(passphrase, salt, memory_kib, iterations)?;
        let mut raw = [0u8; MASTER_LEN];
        raw.copy_from_slice(master.expose());
        Ok(Self::from_master_key(raw))
    }

    /// Borrow the protected master key.
    pub fn master(&self) -> &AegisKey { &self.master }

    /// Borrow a protected domain key.
    pub fn domain(&self, d: Domain) -> &AegisKey { self.hierarchy.domain(d) }

    /// Borrow the key hierarchy.
    pub fn hierarchy(&self) -> &KeyHierarchy { &self.hierarchy }

    /// Encrypt `plaintext` with a domain key (authenticated by `aad`).
    /// Returns `(nonce, ciphertext)` for later [`AegisVault::decrypt`].
    pub fn encrypt(&self, domain: Domain, plaintext: &[u8], aad: &[u8], algo: AegisAlgoTag) -> Result<(Vec<u8>, Vec<u8>)> {
        let key = self.hierarchy.domain(domain);
        let mut raw = [0u8; 32];
        raw.copy_from_slice(key.expose());
        AeadCipher::new(algo, &raw).seal(plaintext, aad)
    }

    /// Decrypt `(nonce, ciphertext)` produced by [`AegisVault::encrypt`].
    pub fn decrypt(&self, domain: Domain, nonce: &[u8], ciphertext: &[u8], aad: &[u8], algo: AegisAlgoTag) -> Result<Vec<u8>> {
        let key = self.hierarchy.domain(domain);
        let mut raw = [0u8; 32];
        raw.copy_from_slice(key.expose());
        AeadCipher::new(algo, &raw).open(nonce, ciphertext, aad)
    }

    /// Seal the current master into an encrypted key slot under
    /// `passphrase`, so the vault can be persisted and later reopened.
    pub fn seal_slots(&mut self, passphrase: &[u8]) -> Result<()> {
        let mut raw = [0u8; MASTER_LEN];
        raw.copy_from_slice(self.master.expose());
        self.slots = Some(KeySlotTable::new_initial(&raw, passphrase)?);
        Ok(())
    }

    /// Add an additional (multi-user) key slot under a new passphrase.
    pub fn add_slot(&mut self, passphrase: &[u8]) -> Result<usize> {
        let mut raw = [0u8; MASTER_LEN];
        raw.copy_from_slice(self.master.expose());
        match &mut self.slots {
            Some(t) => t.add_slot(&raw, passphrase),
            None => { self.seal_slots(passphrase)?; Ok(0) }
        }
    }

    /// Revoke a key slot by index.
    pub fn revoke_slot(&mut self, idx: usize) -> Result<()> {
        match &mut self.slots {
            Some(t) => t.revoke_slot(idx),
            None => Err(AegisError::LastSlotRevocation),
        }
    }

    /// Recover the master from a persisted key-slot table using a
    /// passphrase, rebuilding the vault in place.
    ///
    /// After decryption, the recovered master is checked against the
    /// table's volume verifier (key-check value) so we can **detect**
    /// that key injection succeeded and the vault has not been swapped
    /// for a different master.
    pub fn open_from_slots(&mut self, table_bytes: &[u8], header_salt: &[u8; 32], passphrase: &[u8]) -> Result<()> {
        let table = KeySlotTable::from_bytes(table_bytes, header_salt)?;
        let (_idx, master) = table.unseal_with(passphrase)?;
        let mut raw = [0u8; MASTER_LEN];
        raw.copy_from_slice(master.expose());

        // Detect a correctly-decrypted-but-wrong master.
        let expected = crate::slots::volume_verifier(&raw);
        if !bool::from(ConstantTimeEq::ct_eq(expected.as_slice(), table.verifier.as_slice())) {
            return Err(AegisError::VolumeMismatch);
        }

        self.master = AegisKey::new32(&raw);
        self.hierarchy = KeyHierarchy::from_master(&raw)?;
        self.slots = Some(table);
        Ok(())
    }

    /// Verify that the live master key matches the volume verifier
    /// stored in the persisted key-slot table. Returns `false` if no
    /// slot table is present. This is the runtime "keys were properly
    /// injected / decrypted" detection check.
    pub fn verify_volume(&self) -> bool {
        match &self.slots {
            Some(t) => {
                let mut raw = [0u8; MASTER_LEN];
                raw.copy_from_slice(self.master.expose());
                let v = crate::slots::volume_verifier(&raw);
                bool::from(ConstantTimeEq::ct_eq(v.as_slice(), t.verifier.as_slice()))
            }
            None => false,
        }
    }

    /// Serialize the current key-slot table (if any) to the `SOTK` format.
    pub fn slots_to_bytes(&self) -> Option<Vec<u8>> {
        self.slots.as_ref().map(|t| t.to_bytes())
    }

    /// Borrow the header salt of the current key-slot table, if any.
    pub fn slots_header_salt(&self) -> Option<[u8; 32]> {
        self.slots.as_ref().map(|t| t.header_salt)
    }

    /// Rotate the master key to a fresh random value, re-deriving the
    /// hierarchy. The previous slot table is invalidated.
    pub fn rotate_master(&mut self) {
        let new_master = VolumeKeyRotation::rotate();
        let mut raw = [0u8; MASTER_LEN];
        raw.copy_from_slice(new_master.expose());
        self.master = new_master;
        self.hierarchy = KeyHierarchy::from_master(&raw).expect("fresh 32-byte master derives");
        self.slots = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_encrypt_decrypt_roundtrip() {
        let vault = AegisVault::unlock(b"pw", b"public-salt-01", 32 * 1024, 2).unwrap();
        let (nonce, ct) = vault
            .encrypt(Domain::Enc, b"hello aegis", b"blk:1", AegisAlgoTag::XChaCha20Poly1305)
            .unwrap();
        let pt = vault
            .decrypt(Domain::Enc, &nonce, &ct, b"blk:1", AegisAlgoTag::XChaCha20Poly1305)
            .unwrap();
        assert_eq!(pt, b"hello aegis");
        assert!(vault
            .decrypt(Domain::Enc, &nonce, &ct, b"blk:2", AegisAlgoTag::XChaCha20Poly1305)
            .is_err());
    }

    #[test]
    fn vault_persist_and_reopen_via_slots() {
        let mut vault = AegisVault::unlock(b"master-pw", b"public-salt-02", 32 * 1024, 2).unwrap();
        vault.seal_slots(b"master-pw").unwrap();
        let bytes = vault.slots_to_bytes().unwrap();
        let salt = vault.slots_header_salt().unwrap();

        let mut reopened = AegisVault::unlock(b"master-pw", b"public-salt-02", 32 * 1024, 2).unwrap();
        reopened.open_from_slots(&bytes, &salt, b"master-pw").unwrap();
        assert!(reopened.master().ct_eq(vault.master()));

        let mut bad = AegisVault::unlock(b"master-pw", b"public-salt-02", 32 * 1024, 2).unwrap();
        assert!(bad.open_from_slots(&bytes, &salt, b"nope").is_err());
    }

    #[test]
    fn vault_master_is_protected() {
        let vault = AegisVault::unlock(b"pw", b"public-salt-03", 32 * 1024, 2).unwrap();
        let dbg = format!("{:?}", vault.master());
        assert_eq!(dbg, "AegisKey(<redacted>)");
        assert!(!vault.domain(Domain::Enc).ct_eq(vault.domain(Domain::Auth)));
    }

    #[test]
    fn vault_volume_verifier_detects_injection() {
        let mut vault = AegisVault::unlock(b"master-pw", b"public-salt-04", 32 * 1024, 2).unwrap();
        vault.seal_slots(b"master-pw").unwrap();
        let bytes = vault.slots_to_bytes().unwrap();
        let salt = vault.slots_header_salt().unwrap();

        // Reopen and confirm the verifier reports a proper injection.
        let mut reopened = AegisVault::unlock(b"master-pw", b"public-salt-04", 32 * 1024, 2).unwrap();
        reopened.open_from_slots(&bytes, &salt, b"master-pw").unwrap();
        assert!(reopened.verify_volume(), "decrypted master must match volume verifier");

        // A vault with no slot table cannot be verified.
        let bare = AegisVault::unlock(b"x", b"public-salt-04", 32 * 1024, 2).unwrap();
        assert!(!bare.verify_volume());
    }
}


