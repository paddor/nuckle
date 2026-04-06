# Changelog

## Unreleased

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
