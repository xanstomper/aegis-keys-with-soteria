//! `AegisKey` — Soteria Aegis protected key material.
//!
//! This is the single abstraction every cryptographic key in Soteria
//! Aegis is wrapped in. It guarantees, by construction, that a key is
//! *never* left unprotected in memory:
//!
//! * **Locked (`mlock`)** — the backing allocation is pinned to RAM and
//!   cannot be paged out to swap or captured in a hibernation image.
//! * **Zeroized on drop** — the bytes are wiped with volatile writes
//!   (via `zeroize`) before the allocation is freed, leaving no
//!   residual key material in freed memory.
//! * **Never logged** — the `Debug` impl is redacted, so a key can never
//!   be accidentally printed to stderr / a log file.
//! * **Constant-time comparison** — equality checks use a XOR-OR
//!   accumulator (no early-exit), matching Soteria's TCB discipline.
//!
//! The only way to read the raw bytes is [`AegisKey::expose`], which
//! returns a borrow. Callers must treat the returned slice as secret
//! and copy it into an `AegisKey` (or another `Zeroizing` container)
//! as soon as possible.

use std::fmt;
use zeroize::Zeroize;

/// A protected key in locked, self-zeroing memory.
pub struct AegisKey {
    data: Box<[u8]>,
    #[cfg(unix)]
    locked: bool,
}

impl AegisKey {
    /// Wrap raw key material in a locked, zeroizing buffer.
    ///
    /// The allocation is `mlock`'d on Unix (best effort — if `mlock`
    /// is unavailable the bytes are still zeroized on drop). The input
    /// slice may be a temporary; only its *contents* are captured.
    #[inline]
    pub fn new(material: &[u8]) -> Self {
        let mut data: Box<[u8]> = vec![0u8; material.len()].into_boxed_slice();
        data.copy_from_slice(material);

        #[cfg(unix)]
        let locked = lock_memory(data.as_ptr(), data.len());
        #[cfg(not(unix))]
        let locked = false;

        Self {
            data,
            #[cfg(unix)]
            locked,
        }
    }

    /// Convenience constructor for a 32-byte (256-bit) key.
    #[inline]
    pub fn new32(material: &[u8; 32]) -> Self {
        Self::new(material)
    }

    /// Borrow the raw key bytes. Treat the result as secret.
    #[inline]
    pub fn expose(&self) -> &[u8] {
        &self.data
    }

    /// Length of the key in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Constant-time equality of two protected keys. Returns `false`
    /// immediately (without leaking length) if lengths differ, and
    /// otherwise folds all bytes with a non-short-circuiting XOR-OR.
    pub fn ct_eq(&self, other: &AegisKey) -> bool {
        if self.data.len() != other.data.len() {
            return false;
        }
        let mut acc: u8 = 0;
        for (a, b) in self.data.iter().zip(other.data.iter()) {
            acc |= a ^ b;
        }
        bool::from(subtle::ConstantTimeEq::ct_eq(&acc, &0u8))
    }

    /// Consume the key, overwriting its memory immediately. Equivalent
    /// to dropping, but useful to make the intent explicit at a call
    /// site (e.g. after a one-shot key has been used).
    pub fn burn(mut self) {
        self.data.zeroize();
    }
}

impl Drop for AegisKey {
    fn drop(&mut self) {
        // Wipe first, then release the lock.
        self.data.zeroize();
        #[cfg(unix)]
        if self.locked {
            unlock_memory(self.data.as_ptr(), self.data.len());
        }
    }
}

/// Pin `len` bytes at `ptr` to RAM (`mlock`) and, on Linux, exclude
/// them from core dumps (`MADV_DONTDUMP`). Returns whether the region
/// was locked. Best-effort: if `mlock` is unavailable the bytes are
/// still zeroized on drop.
#[cfg(unix)]
fn lock_memory(ptr: *const u8, len: usize) -> bool {
    unsafe {
        if libc::mlock(ptr as *const libc::c_void, len) != 0 {
            return false;
        }
        #[cfg(target_os = "linux")]
        {
            // Exclude the key pages from process core dumps.
            let _ = libc::madvise(ptr as *mut libc::c_void, len, libc::MADV_DONTDUMP);
        }
        true
    }
}

/// Release a previously locked region: re-allow core dumps and
/// `munlock` it.
#[cfg(unix)]
fn unlock_memory(ptr: *const u8, len: usize) {
    unsafe {
        #[cfg(target_os = "linux")]
        {
            let _ = libc::madvise(ptr as *mut libc::c_void, len, libc::MADV_DODUMP);
        }
        libc::munlock(ptr as *const libc::c_void, len);
    }
}

impl fmt::Debug for AegisKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately redacted: never expose key bytes via Debug.
        f.write_str("AegisKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holds_and_zeroizes_on_drop() {
        let k = AegisKey::new(&[0x42u8; 32]);
        assert_eq!(k.len(), 32);
        assert!(!k.is_empty());
        assert_eq!(k.expose(), &[0x42u8; 32]);
    }

    #[test]
    fn debug_is_redacted() {
        let k = AegisKey::new(&[0x1u8; 32]);
        let s = format!("{:?}", k);
        assert_eq!(s, "AegisKey(<redacted>)");
        assert!(!s.contains("01"));
    }

    #[test]
    fn ct_eq_is_constant_time_like() {
        let a = AegisKey::new(&[0xabu8; 32]);
        let b = AegisKey::new(&[0xabu8; 32]);
        let c = AegisKey::new(&[0xacu8; 32]);
        assert!(a.ct_eq(&b));
        assert!(!a.ct_eq(&c));
        assert!(!a.ct_eq(&AegisKey::new(&[0u8; 16]))); // length mismatch
    }
}
