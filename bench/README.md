# Nuckle Benchmarks

## Results

Ruby 4.0.2, YJIT ON, x86_64-linux.

### vs rbnacl (libsodium)

| Primitive | nuckle | rbnacl | ratio |
|---|---|---|---|
| SecretBox encrypt 1 KB | 4,675/s (214 µs) | 355,075/s (2.8 µs) | 76x slower |
| SecretBox decrypt 1 KB | 4,345/s (230 µs) | 347,435/s (2.9 µs) | 80x slower |
| Box encrypt 1 KB | 4,721/s (212 µs) | 373,530/s (2.7 µs) | 79x slower |
| Poly1305 MAC 1 KB | 12,730/s (79 µs) | 734,822/s (1.4 µs) | 58x slower |
| Curve25519 scalarmult | 616/s (1.62 ms) | 27,961/s (36 µs) | 45x slower |
| Keypair generation | 578/s (1.73 ms) | 28,187/s (35 µs) | 49x slower |

### YJIT effect

| Primitive | no YJIT | YJIT | speedup |
|---|---|---|---|
| SecretBox encrypt 1 KB | 874/s | 4,675/s | 5.3x |
| Poly1305 MAC 1 KB | 8,617/s | 12,730/s | 1.5x |
| XSalsa20 XOR 1 KB | 1,039/s | 8,343/s | 8.0x |
| Curve25519 scalarmult | 458/s | 616/s | 1.3x |

Salsa20 (and therefore SecretBox) benefits enormously from YJIT — the
inner loop is pure integer arithmetic on 32-bit values, exactly the
kind of code YJIT compiles well.

Curve25519 barely benefits because it's dominated by Ruby bignum
(arbitrary-precision integer) operations which are already in C.

## Running

```
cd nuckle
ruby bench/primitives.rb          # without YJIT
ruby --yjit bench/primitives.rb   # with YJIT
```
