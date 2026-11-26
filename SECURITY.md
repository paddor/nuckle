# Security

Nuckle is a pure Ruby NaCl implementation. The algorithms are correct
(tested byte-for-byte against libsodium), but the implementation is
**not suitable for production use against adversaries who can measure
timing**.

## Timing side channels

Ruby's `Integer` operations are not constant-time. GMP's bignum
multiply/mod take different amounts of time depending on operand values
(branch on leading zeros, different code paths for different sizes).

- **Curve25519 scalarmult** leaks bits of the private key through
  timing. The Montgomery ladder is algorithmically constant-time (no
  secret-dependent branches), but every `(a * b) % P` takes variable
  time depending on the magnitudes of `a` and `b`.
- **Poly1305 MAC** computation time depends on message content and
  key material.
- **XSalsa20** is the least vulnerable — Fixnum arithmetic on 32-bit
  words that YJIT compiles to native ops — but the interpreter's
  dispatch overhead may still vary without YJIT.

A network attacker measuring handshake timing across many connections
could extract the server's permanent private key. This is the same
class of attack that broke early OpenSSL RSA implementations and is
well-demonstrated against ECDH.

String comparisons (MAC verification, vouch checks) use Ruby's native
`String#==`, which short-circuits on the first differing byte. This is
an honest choice: pretending to be constant-time when everything else
leaks would be worse than being upfront about it.

## No memory protection

libsodium calls `mlock()` to prevent key material from hitting swap,
and `sodium_memzero()` to wipe keys after use. Nuckle does neither:

- Private keys live as regular Ruby `String` objects on the GC heap
- They get copied during GC compaction
- They persist in memory after the object is collected (until
  overwritten)
- They can end up in swap, core dumps, or process memory snapshots

## Low-order points

`Box.new` and `PrivateKey#diffie_hellman` raise `CryptoError` when the
X25519 result is all zero, as libsodium's `crypto_scalarmult` does.
This catches every low-order public key, including non-canonical
encodings and encodings with the top bit set. RbNaCl raises the same
error, but `RbNaCl::Box` only raises it on the first encrypt or
decrypt.

`Nuckle::Internals::Curve25519.scalarmult` does not check. Code that
calls it directly must reject an all-zero result itself.

## Ruby runtime attack surface

- **GC observability** — an attacker sharing the process could observe
  GC timing correlated with key operations
- **ObjectSpace** — `ObjectSpace.each_object(String)` can enumerate
  key material in the same process
- **No stack clearing** — local variables holding key fragments persist
  on the Ruby stack/heap

## What is fine

- The algorithms are correct (cross-validated against rbnacl/libsodium)
- Nonce handling and replay detection are sound
- The CurveZMQ handshake protocol follows RFC 26 faithfully
- Poly1305 one-time-key derivation is correct

## Recommendation

Use nuckle for testing, CI, development, education, and benchmarking.
Use [rbnacl](https://github.com/RubyCrypto/rbnacl) for anything that
faces real adversaries.
