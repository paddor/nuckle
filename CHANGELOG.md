# Changelog

## 0.3.0 — 2026-04-20

### Added

- `Nuckle::Internals::Chacha20` — pure-Ruby ChaCha20 stream cipher (DJB's
  8-byte-nonce variant). Validated against RFC 8439 § 2.3.2 block-function
  test vector.
- `Nuckle::Internals::Blake3` — pure-Ruby BLAKE3 with unkeyed hash, keyed
  hash, `derive_key`, streaming `Hasher`, and variable-length output (XOF).
  Cross-validated against the `blake3-rb` gem.
- `Nuckle::Chacha20Blake3::Cipher` — authenticated encryption AEAD,
  wire-compatible with the [`chacha20-blake3`](https://github.com/skerkour/chacha20-blake3)
  Rust crate. Supports attached and detached encrypt/decrypt with optional
  AAD. Cross-validated against the `chacha20blake3` sibling gem.

## 0.2.1 — 2026-04-07

### Changed

- YARD documentation on all public methods and classes.
- Code style: expand `else X` one-liners, two blank lines between methods
  and constants.

## 0.2.0 — 2026-04-06

### Added

- `PrivateKey#diffie_hellman` — raw X25519 scalar multiplication against a
  peer's public key, returning a 32-byte shared secret without further key
  derivation.

## 0.1.1 — 2025-04-04

- Add gem release tasks, update README.

## 0.1.0 — 2025-04-04

- Initial release.
