//! Quick launch demo: unlock -> seal slots -> encrypt/decrypt ->
//! persist -> reopen (with key-injection verification).

use soteria_aegis::{AegisVault, AegisAlgoTag, Domain};

fn main() {
    println!("== Soteria Aegis :: quick launch ==");

    // 1. Unlock a vault from a passphrase. Every key is an AegisKey.
    let mut vault = AegisVault::unlock(
        b"correct horse battery staple",
        b"public-launch-salt",
        32 * 1024,
        2,
    )
    .expect("unlock");

    // 2. Seal the master into an encrypted, multi-user key slot.
    vault.seal_slots(b"correct horse battery staple").expect("seal");
    let _bob = vault.add_slot(b"bob-pw").expect("add slot");

    // 3. Encrypt with the K_enc domain key.
    let (nonce, ct) = vault
        .encrypt(Domain::Enc, b"classified payload", b"file=1", AegisAlgoTag::XChaCha20Poly1305)
        .expect("encrypt");
    let pt = vault
        .decrypt(Domain::Enc, &nonce, &ct, b"file=1", AegisAlgoTag::XChaCha20Poly1305)
        .expect("decrypt");
    assert_eq!(pt, b"classified payload");
    println!("[ok] encrypt/decrypt round-trip ({} bytes ciphertext)", ct.len());

    // 4. Persist + reopen, verifying proper key injection.
    let bytes = vault.slots_to_bytes().expect("serialize");
    let salt = vault.slots_header_salt().expect("header salt");
    let mut reopened = AegisVault::unlock(b"ignored", b"public-launch-salt", 32 * 1024, 2).unwrap();
    reopened.open_from_slots(&bytes, &salt, b"bob-pw").expect("reopen");
    assert!(reopened.verify_volume(), "key injection must verify");
    println!("[ok] reopened via 'bob-pw' and verified volume key-check");

    // 5. Confirm the master key never leaks via Debug.
    assert_eq!(format!("{:?}", vault.master()), "AegisKey(<redacted>)");
    println!("[ok] master key is protected (redacted Debug)");

    println!("== Aegis online. ==\nRepository: https://github.com/xanstomper/aegis-keys-with-soteria");
}
