# Soteria Aegis — `soteria-aegis`

> Wrapping the **Soteria Aegis** cryptography & key-management
> methodology into protected **Aegis keys** so every key is safe by
> construction.

This crate is a faithful Rust re-implementation of the crypto/key
methodology from
[`soteria-fs`](https://github.com/xanstomper/soteria-fs) ("Soteria
Aegis"), wrapped behind a single protected abstraction:
**`AegisKey`**.

The single guarantee this crate adds on top of Soteria's TCB: **every
cryptographic key it produces is an `AegisKey`** — key material held in
locked, self-zeroizing memory that can never be printed and is compared
in constant time. That is what "wrap all keys into Aegis keys" means
here.

## What is protected (the methodology)

```
passphrase --Argon2id--> K_master (256-bit, AegisKey)
K_master --HKDF-SHA256 (domain separation)--> {
    K_enc, K_auth, K_meta, K_shard, K_xts, K_handle }   (each an AegisKey)
K_master --AES-256-GCM (per-passphrase slot key)--> key slots
                                                        (multi-user, revocable)
```

| Layer | Primitive | Protection |
|---|---|---|
| Master key | Argon2id (RFC 9106) | `AegisKey` (locked + zeroized) |
| Key hierarchy | HKDF-SHA-256 (RFC 5869), domain-separated | each domain key is an `AegisKey` |
| Bulk cipher | XChaCha20-Poly1305 (RFC 8439) / AES-256-GCM | AEAD auth + random nonce |
| Key slots | AES-256-GCM wrap + BLAKE3 keyed-MAC header | tamper-evident, multi-user |
| Memory | `mlock` + `zeroize` on drop | no swap/hibernation leakage |
| Comparison | `subtle` constant-time | no timing side-channel |

## The `AegisKey` guarantee

* **Locked** (`mlock`) — cannot be paged to swap or captured in a
  hibernation image.
* **Zeroized on drop** — volatile wipe before free; no residual key.
* **Never logged** — `Debug` is redacted (`AegisKey(<redacted>)`).
* **Constant-time `ct_eq`** — non-short-circuiting comparison.

## Usage

```rust
use soteria_aegis::{AegisVault, Domain, AegisAlgoTag};

let mut vault = AegisVault::unlock(
    b"correct horse battery staple",
    b"public-salt-1234",
    64 * 1024, // Argon2id memory cost (KiB)
    3,         // iterations
).unwrap();

// Persist a multi-user, encrypted key slot.
vault.seal_slots(b"correct horse battery staple").unwrap();
vault.add_slot(b"bob-pw").unwrap();

// Encrypt with the bulk (K_enc) domain key.
let (nonce, ct) = vault
    .encrypt(Domain::Enc, b"secret", b"aad", AegisAlgoTag::XChaCha20Poly1305)
    .unwrap();
let pt = vault
    .decrypt(Domain::Enc, &nonce, &ct, b"aad", AegisAlgoTag::XChaCha20Poly1305)
    .unwrap();
assert_eq!(pt, b"secret");
```

Reopen later from the persisted slot table:

```rust
let bytes = vault.slots_to_bytes().unwrap();
let salt = vault.slots_header_salt().unwrap();
let mut reopened = AegisVault::unlock(b"x", b"public-salt-1234", 64 * 1024, 3).unwrap();
reopened.open_from_slots(&bytes, &salt, b"bob-pw").unwrap();
```

## "100% secure" — an honest note

No software is *literally* 100% secure. What this crate does is
faithfully implement the Soteria Aegis TCB discipline so that, by
*construction*, key material cannot leak through swap, freed memory,
logs, or timing, and the on-disk format cannot be tampered with
undetected. Security still depends on a strong passphrase and an
uncompromised host (the documented Soteria threat-model boundaries: it
does not defend against a compromised OS, side channels on the host,
or a weak passphrase).

## Build & test

```bash
cargo build
cargo test --lib      # TCB unit tests
cargo test            # + integration test
cargo clippy --all-targets -- -D warnings
```

## Layout

* `src/aegis_key.rs` — the protected `AegisKey` container.
* `src/kdf.rs` — Argon2id master derivation + HKDF-SHA-256.
* `src/aead.rs` — XChaCha20-Poly1305 / AES-256-GCM.
* `src/hierarchy.rs` — domain-separated key hierarchy (all `AegisKey`).
* `src/slots.rs` — AEAD key slots + BLAKE3 header HMAC + rotation.
* `src/lib.rs` — `AegisVault` high-level API tying it together.

## License

Dual-licensed under MIT or Apache-2.0 (same as `soteria-fs`).
