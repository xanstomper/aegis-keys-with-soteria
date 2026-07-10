//! End-to-end integration test exercising the full Soteria Aegis
//! methodology: passphrase -> Argon2id master -> HKDF domain
//! hierarchy (all keys protected as `AegisKey`) -> multi-user key
//! slots -> AEAD data encryption.

use soteria_aegis::{AegisVault, AegisAlgoTag, Domain};

const SALT: &[u8] = b"integration-salt";

#[test]
fn full_lifecycle_protected_keys() {
    // 1. Unlock a vault from a passphrase. The master + every domain
    //    key is an AegisKey (locked, zeroized, never logged).
    let mut vault = AegisVault::unlock(b"correct horse battery staple", SALT, 32 * 1024, 2).unwrap();

    // 2. The six domain keys are all distinct and protected.
    let domains = [
        Domain::Enc,
        Domain::Auth,
        Domain::Meta,
        Domain::Shard,
        Domain::Xts,
        Domain::Handle,
    ];
    for a in &domains {
        for b in &domains {
            if a != b {
                assert!(!vault.domain(*a).ct_eq(vault.domain(*b)));
            }
        }
    }

    // 3. Seal the master into an encrypted, multi-user key slot.
    vault.seal_slots(b"correct horse battery staple").unwrap();

    // 4. Add a second (multi-user) slot and verify both work.
    let bob = vault.add_slot(b"bob-pw").unwrap();
    assert!(!vault.slots_to_bytes().unwrap().is_empty());
    _ = bob;

    // 5. Encrypt data with the K_enc domain key, decrypt it back.
    let (nonce, ct) = vault
        .encrypt(Domain::Enc, b"classified payload", b"file=42", AegisAlgoTag::XChaCha20Poly1305)
        .unwrap();
    let pt = vault
        .decrypt(Domain::Enc, &nonce, &ct, b"file=42", AegisAlgoTag::XChaCha20Poly1305)
        .unwrap();
    assert_eq!(pt, b"classified payload");

    // 6. Tampering with the AAD breaks authentication (AEAD tag).
    assert!(vault
        .decrypt(Domain::Enc, &nonce, &ct, b"file=43", AegisAlgoTag::XChaCha20Poly1305)
        .is_err());

    // 7. Persist and reopen the slot table; the recovered master must
    //    match and the keys remain protected.
    let bytes = vault.slots_to_bytes().unwrap();
    let salt = vault.slots_header_salt().unwrap();
    let mut reopened = AegisVault::unlock(b"ignored", SALT, 32 * 1024, 2).unwrap();
    reopened.open_from_slots(&bytes, &salt, b"bob-pw").unwrap();
    assert!(reopened.master().ct_eq(vault.master()));

    // 8. A protected key never leaks via Debug.
    assert_eq!(format!("{:?}", vault.master()), "AegisKey(<redacted>)");
}
