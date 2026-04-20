# 🤜 Nuckle

[![Gem Version](https://img.shields.io/gem/v/nuckle)](https://rubygems.org/gems/nuckle)
[![CI](https://github.com/paddor/nuckle/actions/workflows/ci.yml/badge.svg)](https://github.com/paddor/nuckle/actions/workflows/ci.yml)

NaCl for Knuckleheads — pure Ruby crypto primitives, no libsodium required.

## Is it any good?

No. See [SECURITY.md](SECURITY.md).

## ⚠️ Don't use this

Ruby's bignum arithmetic is not constant-time, so private keys leak
through timing side channels. Use
[rbnacl](https://github.com/RubyCrypto/rbnacl) for anything that matters.

## 🤷 Why does this exist?

- Zero-dependency development and CI environments
- Seeing how well Ruby's YJIT performs at crypto ("just for fun")
- Educational purposes
- Environments where installing libsodium is impractical

## Primitives

| Primitive | What it does |
|-----------|-------------|
| **Curve25519** | Elliptic-curve Diffie-Hellman (key agreement) |
| **XSalsa20** | Extended-nonce stream cipher (includes HSalsa20, Salsa20) |
| **ChaCha20** | Stream cipher (DJB's 8-byte-nonce variant) |
| **Poly1305** | One-time message authenticator |
| **BLAKE3** | Cryptographic hash — unkeyed, keyed, `derive_key`, XOF |
| **Box** | Public-key authenticated encryption (Curve25519-XSalsa20-Poly1305) |
| **SecretBox** | Symmetric authenticated encryption (XSalsa20-Poly1305) |
| **ChaCha20-BLAKE3** | Authenticated encryption AEAD, wire-compatible with [skerkour/chacha20-blake3](https://github.com/skerkour/chacha20-blake3) |

## Usage

```ruby
require "nuckle"

# Generate a keypair
sk = Nuckle::PrivateKey.generate
pk = sk.public_key

# Public-key encryption
alice = Nuckle::PrivateKey.generate
bob   = Nuckle::PrivateKey.generate
nonce = Nuckle::Random.random_bytes(24)

box = Nuckle::Box.new(bob.public_key, alice)
ciphertext = box.encrypt(nonce, "hello")

box2 = Nuckle::Box.new(alice.public_key, bob)
plaintext = box2.decrypt(nonce, ciphertext)
# => "hello"

# Symmetric encryption
key   = Nuckle::Random.random_bytes(32)
nonce = Nuckle::Random.random_bytes(24)
box   = Nuckle::SecretBox.new(key)

ciphertext = box.encrypt(nonce, "hello")
plaintext  = box.decrypt(nonce, ciphertext)
```

## API Compatibility

The API mirrors [rbnacl](https://github.com/RubyCrypto/rbnacl).
If you know what you're doing:

```ruby
RbNaCl = Nuckle
```

## Verification

All primitives are tested against rbnacl/libsodium test vectors
(NaCl distribution, RFC 7748, RFC 8439) and cross-validated to
produce byte-identical output.

## License

ISC
