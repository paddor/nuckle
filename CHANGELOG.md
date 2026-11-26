# Changelog

## [Unreleased]

### Fixed

- `Box.new` and `PrivateKey#diffie_hellman` raise `CryptoError` for
  low-order public keys (all-zero X25519 output), like libsodium.
  `RbNaCl::Box` raises the same error on first use instead of in `new`.
- `Box.new`, `PublicKey.new`, `PrivateKey.new` and
  `PrivateKey#diffie_hellman` raise `TypeError` (was `ArgumentError`, or
  nothing) for a key of the wrong type: swapped key objects, `nil`, or
  anything without `#to_str`. Before, `PublicKey.new(private_key)` and
  `PrivateKey.new(12345678901234567890123456789012)` worked, and objects
  with `#to_str` failed. RbNaCl also raises `TypeError` for non-strings,
  but takes swapped key objects.
- `Util.verify`, `verify16/32/64` (and so MAC/tag checks and
  `PublicKey#==`) XOR-fold all bytes instead of using `String#==`, which
  stops at the first differing byte. The docs no longer call them
  constant-time.
- `PrivateKey`, `SecretBox`, `Box` and `Chacha20Blake3::Cipher` no longer
  show key bytes in `#inspect` or `pp` output.
- `PrivateKey#to_s`/`#to_bytes` and `PublicKey#to_s`/`#to_bytes` return
  frozen strings. Before, mutating the returned string changed the key.
- `Internals::Blake3.hash` with no arguments falls back to `Object#hash`.
  Before, using the module as a Hash key or in `#uniq` raised
  `ArgumentError`.

### Added

- `Util.zero?`: checks a string for all zero bytes, with no early exit.
- `LengthError < ArgumentError`, raised for wrong-size keys, nonces and
  tags, like `RbNaCl::LengthError`. Code that rescues `ArgumentError`
  still works.

### Changed

- `SECURITY.md`: drop the claims about nonce handling, replay detection
  and CurveZMQ. Nuckle has none of that code; it lives in protocol-zmtp.
  Cover ChaCha20 and BLAKE3.

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
