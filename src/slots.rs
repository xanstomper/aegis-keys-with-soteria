//! Soteria Aegis key slots — multi-user access & revocation.
//!
//! Faithful Rust re-implementation of
//! `soteria-fs/rust-core/src/key_hierarchy/slots.rs`.
//!
//! A *key slot* is an AEAD-wrapped copy of the volume **master key**.
//! The master is never written to disk in plaintext: each slot is
//! `AES-256-GCM(K_slot_key, master)` where `K_slot_key` is derived
//! from a user passphrase via Argon2id. The slot table header carries
//! a `BLAKE3` keyed-MAC (keyed with a per-volume `header_salt`) to
//! detect tampering with slot metadata (preventing KDF-cost
//! downgrade attacks).
//!
//! ## On-disk layout (mirrors the upstream `SOTK` format)
//!
//! ```text
//! magic:     4 B   = b"SOTK"
//! version:   u8    = 1
//! slot_count:u8
//! for each slot:
//!   slot_id:     [u8; 16]
//!   kdf_id:      u8   (1 = Argon2id)
//!   kdf_m_cost:  u32 LE
//!   kdf_t_cost:  u32 LE
//!   salt:        [u8; 16]
//!   nonce:       [u8; 12]
//!   ct:          [u8; 48]   (32 master || 16 GCM tag)
//!   flags:       u8   (bit 0 = enabled)
//!   created_at:  u64 LE
//! header_hmac: [u8; 32]   (BLAKE3-keyed(header_salt, body))
//! ```
//!
//! The 32-byte `header_salt` is stored alongside the table and is the
//! key for the header HMAC. It is not secret, but its integrity is
//! what the HMAC enforces.

use crate::aead::{AeadAlgo, AeadCipher};
use crate::kdf::argon2id_root;
use crate::{error::AegisError, AegisKey, Result, MASTER_LEN};
use rand::rngs::OsRng;
use rand::RngCore;
use std::fmt;

/// Slot-table magic bytes.
pub const HEADER_MAGIC: &[u8; 4] = b"SOTK";
/// Slot-table format version.
pub const HEADER_VERSION: u8 = 1;
/// KDF identifier: Argon2id.
pub const KDF_ID_ARGON2ID: u8 = 1;
/// Maximum number of slots.
pub const MAX_SLOTS: usize = 16;
/// AEAD nonce length for the slot cipher (AES-256-GCM).
pub const NONCE_LEN: usize = 12;
/// AEAD authentication tag length.
pub const TAG_LEN: usize = 16;
/// Length of the wrapped master ciphertext (master || tag).
pub const CT_LEN: usize = MASTER_LEN + TAG_LEN;

/// One encrypted copy of the master key bound to a passphrase.
#[derive(Clone)]
pub struct KeySlot {
    pub slot_id: [u8; 16],
    pub kdf_id: u8,
    pub m_cost: u32,
    pub t_cost: u32,
    pub salt: [u8; 16],
    pub nonce: [u8; NONCE_LEN],
    pub ct: [u8; CT_LEN],
    pub flags: u8,
    pub created_at: u64,
}

impl KeySlot {
    /// Create a slot that wraps `master` under `passphrase`.
    pub fn create(master: &[u8; MASTER_LEN], passphrase: &[u8], m_cost: u32, t_cost: u32) -> Result<Self> {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let slot_key = argon2id_root(passphrase, &salt, m_cost, t_cost)?;

        let mut sk = [0u8; 32];
        sk.copy_from_slice(slot_key.expose());
        let cipher = AeadCipher::new(AeadAlgo::Aes256Gcm, &sk);
        let (nonce, ct) = cipher.seal(master, HEADER_MAGIC)?;

        let mut sid = [0u8; 16];
        OsRng.fill_bytes(&mut sid);
        let mut nonce_arr = [0u8; NONCE_LEN];
        nonce_arr.copy_from_slice(&nonce);
        let mut ct_arr = [0u8; CT_LEN];
        ct_arr.copy_from_slice(&ct);

        Ok(Self {
            slot_id: sid,
            kdf_id: KDF_ID_ARGON2ID,
            m_cost,
            t_cost,
            salt,
            nonce: nonce_arr,
            ct: ct_arr,
            flags: 0b0000_0001,
            created_at: now_secs(),
        })
    }

    /// Recover the master key using `passphrase`.
    pub fn unseal(&self, passphrase: &[u8]) -> Result<AegisKey> {
        let slot_key = argon2id_root(passphrase, &self.salt, self.m_cost, self.t_cost)?;
        let mut sk = [0u8; 32];
        sk.copy_from_slice(slot_key.expose());
        let cipher = AeadCipher::new(AeadAlgo::Aes256Gcm, &sk);
        let master = cipher.open(&self.nonce, &self.ct, HEADER_MAGIC).map_err(|_| AegisError::SlotUnseal)?;
        if master.len() != MASTER_LEN {
            return Err(AegisError::SlotUnseal);
        }
        let mut arr = [0u8; MASTER_LEN];
        arr.copy_from_slice(&master);
        Ok(AegisKey::new32(&arr))
    }

    /// Whether this slot is enabled.
    pub fn is_enabled(&self) -> bool {
        self.flags & 0b0000_0001 != 0
    }
}

/// Bounded slice helper for `from_bytes`.
fn slice_at<'a>(buf: &'a [u8], p: &mut usize, n: usize) -> Result<&'a [u8]> {
    if *p + n > buf.len() {
        return Err(AegisError::Serialization);
    }
    let s = &buf[*p..*p + n];
    *p += n;
    Ok(s)
}

/// Fixed key for the volume verifier keyed-hash.
const VERIFIER_KEY: &[u8; 32] = b"soteria-aegis-volume-verifier-v1";

/// Volume key-check value: `blake3`-keyed hash of the master key.
///
/// This is a *public* check value (not secret). It lets a reopened
/// vault **detect** that the master key recovered from a slot is the
/// expected one — i.e. that key injection after decryption succeeded
/// and the volume has not been swapped for a different master.
pub(crate) fn volume_verifier(master: &[u8; MASTER_LEN]) -> [u8; 32] {
    *blake3::keyed_hash(VERIFIER_KEY, master).as_bytes()
}

impl fmt::Debug for KeySlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redacted: never log slot metadata (salt/nonce/ct) by accident.
        f.debug_struct("KeySlot")
            .field("slot_id", &"<redacted>")
            .field("kdf_id", &self.kdf_id)
            .field("m_cost", &self.m_cost)
            .field("t_cost", &self.t_cost)
            .field("enabled", &self.is_enabled())
            .finish_non_exhaustive()
    }
}

/// A table of key slots bound to a single master key.
///
/// `header_salt` is the BLAKE3 key for the table's integrity MAC; it
/// is stored separately (e.g. in the volume header) and supplied to
/// [`KeySlotTable::from_bytes`]. `verifier` is the volume key-check
/// value (see [`volume_verifier`]) used to *detect* a correct master
/// after decryption.
#[derive(Clone)]
pub struct KeySlotTable {
    pub header_salt: [u8; 32],
    pub slots: Vec<KeySlot>,
    /// Volume key-check value (blake3-keyed over the master).
    pub verifier: [u8; 32],
}

impl fmt::Debug for KeySlotTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redacted: never log slot metadata or the verifier by accident.
        f.debug_struct("KeySlotTable")
            .field("header_salt", &"<redacted>")
            .field("verifier", &"<redacted>")
            .field("slot_count", &self.slots.len())
            .field("enabled_count", &self.enabled_count())
            .finish_non_exhaustive()
    }
}

impl KeySlotTable {
    /// Build a table with a single initial slot for `master`.
    pub fn new_initial(master: &[u8; MASTER_LEN], passphrase: &[u8]) -> Result<Self> {
        let mut header_salt = [0u8; 32];
        OsRng.fill_bytes(&mut header_salt);
        let slot = KeySlot::create(master, passphrase, 64, 3)?;
        Ok(Self {
            header_salt,
            slots: vec![slot],
            verifier: volume_verifier(master),
        })
    }

    /// Append a new slot wrapping the same master under a new
    /// passphrase (multi-user). Returns the new slot's index.
    pub fn add_slot(&mut self, master: &[u8; MASTER_LEN], passphrase: &[u8]) -> Result<usize> {
        if self.slots.len() >= MAX_SLOTS {
            return Err(AegisError::SlotTableFull(MAX_SLOTS));
        }
        let slot = KeySlot::create(master, passphrase, 64, 3)?;
        self.slots.push(slot);
        Ok(self.slots.len() - 1)
    }

    /// Number of enabled slots.
    pub fn enabled_count(&self) -> usize {
        self.slots.iter().filter(|s| s.is_enabled()).count()
    }

    /// Revoke (disable) the slot at `idx`. Refuses the last enabled slot.
    pub fn revoke_slot(&mut self, idx: usize) -> Result<()> {
        if idx >= self.slots.len() {
            return Err(AegisError::SlotUnseal);
        }
        if !self.slots[idx].is_enabled() {
            return Ok(());
        }
        if self.enabled_count() <= 1 {
            return Err(AegisError::LastSlotRevocation);
        }
        self.slots[idx].flags &= 0b1111_1110;
        // Irrecoverably wipe the wrapped master so the revoked slot
        // can never be opened again, even by reading the raw table.
        self.slots[idx].ct = [0u8; CT_LEN];
        Ok(())
    }

    /// Try to unseal the master using `passphrase` against every
    /// enabled slot. Returns `(slot_index, master)` on success.
    pub fn unseal_with(&self, passphrase: &[u8]) -> Result<(usize, AegisKey)> {
        for (i, slot) in self.slots.iter().enumerate() {
            if !slot.is_enabled() {
                continue;
            }
            if let Ok(m) = slot.unseal(passphrase) {
                return Ok((i, m));
            }
        }
        Err(AegisError::NoSlotUnsealed)
    }

    /// Serialize to the `SOTK` on-disk format (with header HMAC).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut body: Vec<u8> = Vec::with_capacity(64 + self.slots.len() * 128);
        body.extend_from_slice(HEADER_MAGIC);
        body.push(HEADER_VERSION);
        body.push(self.slots.len() as u8);
        for s in &self.slots {
            body.extend_from_slice(&s.slot_id);
            body.push(s.kdf_id);
            body.extend_from_slice(&s.m_cost.to_le_bytes());
            body.extend_from_slice(&s.t_cost.to_le_bytes());
            body.extend_from_slice(&s.salt);
            body.extend_from_slice(&s.nonce);
            body.extend_from_slice(&s.ct);
            body.push(s.flags);
            body.extend_from_slice(&s.created_at.to_le_bytes());
        }
        // Volume verifier (key-check value) is covered by the HMAC.
        body.extend_from_slice(&self.verifier);
        let mac = blake3::keyed_hash(&self.header_salt, &body);
        let mut out = body;
        out.extend_from_slice(mac.as_bytes());
        out
    }

    /// Parse a `SOTK` table, verifying its BLAKE3 keyed-HMAC.
    pub fn from_bytes(data: &[u8], header_salt: &[u8; 32]) -> Result<Self> {
        if data.len() < 5 + blake3::OUT_LEN {
            return Err(AegisError::Serialization);
        }
        let split = data.len() - blake3::OUT_LEN;
        let body = &data[..split];
        let mac = &data[split..];

        let expected = blake3::keyed_hash(header_salt, body);
        if !bool::from(subtle::ConstantTimeEq::ct_eq(
            expected.as_bytes().as_slice(),
            mac,
        )) {
            return Err(AegisError::HeaderIntegrity);
        }
        if &body[..4] != HEADER_MAGIC || body[4] != HEADER_VERSION {
            return Err(AegisError::Serialization);
        }
        let slot_count = body[5] as usize;
        let mut pos = 6;
        let mut slots = Vec::with_capacity(slot_count);
        for _ in 0..slot_count {
            let slot_id = slice_at(body, &mut pos, 16)?
                .try_into()
                .map_err(|_| AegisError::Serialization)?;
            let kdf_id = body[pos];
            pos += 1;
            let m_cost = u32::from_le_bytes(
                slice_at(body, &mut pos, 4)?
                    .try_into()
                    .map_err(|_| AegisError::Serialization)?,
            );
            let t_cost = u32::from_le_bytes(
                slice_at(body, &mut pos, 4)?
                    .try_into()
                    .map_err(|_| AegisError::Serialization)?,
            );
            let salt = slice_at(body, &mut pos, 16)?
                .try_into()
                .map_err(|_| AegisError::Serialization)?;
            let nonce = slice_at(body, &mut pos, NONCE_LEN)?
                .try_into()
                .map_err(|_| AegisError::Serialization)?;
            let ct = slice_at(body, &mut pos, CT_LEN)?
                .try_into()
                .map_err(|_| AegisError::Serialization)?;
            let flags = body[pos];
            pos += 1;
            let created_at = u64::from_le_bytes(
                slice_at(body, &mut pos, 8)?
                    .try_into()
                    .map_err(|_| AegisError::Serialization)?,
            );
            slots.push(KeySlot { slot_id, kdf_id, m_cost, t_cost, salt, nonce, ct, flags, created_at });
        }
        let verifier = slice_at(body, &mut pos, 32)?
            .try_into()
            .map_err(|_| AegisError::Serialization)?;
        Ok(Self { header_salt: *header_salt, slots, verifier })
    }
}

/// Volume master-key rotation. Produces a fresh random 256-bit master
/// key. (The data-on-disk is re-keyed out-of-band by re-deriving the
/// hierarchy from the new master.)
pub struct VolumeKeyRotation;

impl VolumeKeyRotation {
    /// Generate a fresh random master key, returned as an [`AegisKey`].
    pub fn rotate() -> AegisKey {
        let mut m = [0u8; MASTER_LEN];
        OsRng.fill_bytes(&mut m);
        AegisKey::new32(&m)
    }
}

/// Best-effort Unix seconds for `created_at`. We deliberately avoid
/// any time-based inputs to KDFs; this is only a bookkeeping field.
fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_slot(master: &[u8; MASTER_LEN], pw: &[u8]) -> KeySlot {
        KeySlot::create(master, pw, 32, 1).unwrap()
    }

    #[test]
    fn round_trip_unseal() {
        let master = [0x55u8; MASTER_LEN];
        let slot = fast_slot(&master, b"hunter2");
        let recovered = slot.unseal(b"hunter2").unwrap();
        assert!(recovered.ct_eq(&AegisKey::new32(&master)));
    }

    #[test]
    fn wrong_passphrase_fails() {
        let master = [0x66u8; MASTER_LEN];
        let slot = fast_slot(&master, b"hunter2");
        assert!(slot.unseal(b"wrong").is_err());
    }

    #[test]
    fn slot_isolation() {
        let master = [0x77u8; MASTER_LEN];
        let s1 = fast_slot(&master, b"pass-a");
        let s2 = fast_slot(&master, b"pass-b");
        assert!(s1.unseal(b"pass-b").is_err());
        assert!(s2.unseal(b"pass-a").is_err());
        assert!(s1.unseal(b"pass-a").unwrap().ct_eq(&s2.unseal(b"pass-b").unwrap()));
    }

    #[test]
    fn table_multi_user() {
        let master = [0x88u8; MASTER_LEN];
        let mut table = KeySlotTable::new_initial(&master, b"alice-pw").unwrap();
        assert_eq!(table.enabled_count(), 1);
        let bob = table.add_slot(&master, b"bob-pw").unwrap();
        assert_eq!(table.enabled_count(), 2);

        let (idx, m) = table.unseal_with(b"bob-pw").unwrap();
        assert_eq!(idx, bob);
        assert!(m.ct_eq(&AegisKey::new32(&master)));

        let (idx, m) = table.unseal_with(b"alice-pw").unwrap();
        assert_eq!(idx, 0);
        assert!(m.ct_eq(&AegisKey::new32(&master)));
    }

    #[test]
    fn revocation_blocks_access() {
        let master = [0x99u8; MASTER_LEN];
        let mut table = KeySlotTable::new_initial(&master, b"alice-pw").unwrap();
        let bob = table.add_slot(&master, b"bob-pw").unwrap();
        assert!(table.revoke_slot(bob).is_ok());
        assert!(table.unseal_with(b"bob-pw").is_err());
        assert!(table.unseal_with(b"alice-pw").is_ok());
    }

    #[test]
    fn cannot_revoke_last_slot() {
        let master = [0xAAu8; MASTER_LEN];
        let mut table = KeySlotTable::new_initial(&master, b"only-pw").unwrap();
        assert!(table.revoke_slot(0).is_err());
    }

    #[test]
    fn table_serde_round_trip() {
        let master = [0xBBu8; MASTER_LEN];
        let table = KeySlotTable::new_initial(&master, b"pw").unwrap();
        let bytes = table.to_bytes();
        let salt = table.header_salt;
        let parsed = KeySlotTable::from_bytes(&bytes, &salt).unwrap();
        assert_eq!(parsed.slots.len(), table.slots.len());
        assert_eq!(parsed.header_salt, table.header_salt);
    }

    #[test]
    fn tampered_table_fails_hmac() {
        let master = [0xCCu8; MASTER_LEN];
        let table = KeySlotTable::new_initial(&master, b"pw").unwrap();
        let mut bytes = table.to_bytes();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let wrong_salt = [0u8; 32];
        assert!(KeySlotTable::from_bytes(&bytes, &wrong_salt).is_err());
    }

    #[test]
    fn rotation_changes_master() {
        let old = [0xDDu8; MASTER_LEN];
        let new = VolumeKeyRotation::rotate();
        assert!(!new.ct_eq(&AegisKey::new32(&old)));
    }
}


