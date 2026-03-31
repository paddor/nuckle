# Nuckle

Pure Ruby implementation of the NaCl crypto primitives. No C extensions,
no FFI, no libsodium. Just Ruby.

## Is it any good?

No.

## Why does this exist?

- Zero-dependency development and CI environments
- Seeing how well Ruby's YJIT performs at crypto ("just for fun")
- Educational purposes
- Environments where installing libsodium is impractical

**This is not a good idea for production.** Ruby's bignum arithmetic
is not constant-time at the hardware level, making it vulnerable to
side-channel timing attacks. Use [rbnacl](https://github.com/RubyCrypto/rbnacl)
for anything that matters.

A best-effort constant-time string comparison is included (XOR
accumulator), but YJIT or the Ruby runtime may not preserve timing
invariance.

## Primitives

| Primitive | What it does |
|-----------|-------------|
| **Curve25519** | Elliptic-curve Diffie-Hellman (key agreement) |
| **XSalsa20** | Extended-nonce stream cipher (includes HSalsa20, Salsa20) |
| **Poly1305** | One-time message authenticator |
| **Box** | Public-key authenticated encryption (Curve25519-XSalsa20-Poly1305) |
| **SecretBox** | Symmetric authenticated encryption (XSalsa20-Poly1305) |

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
