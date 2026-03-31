# frozen_string_literal: true

# Usage:
#   ruby bench/primitives.rb          # without YJIT
#   ruby --yjit bench/primitives.rb   # with YJIT

require "bundler/setup"
require "benchmark/ips"
require "nuckle"
require "rbnacl"

YJIT = defined?(RubyVM::YJIT) && RubyVM::YJIT.enabled?
puts "Ruby #{RUBY_VERSION} | YJIT: #{YJIT ? "ON" : "OFF"}"
puts

MSG_1K = Nuckle::Random.random_bytes(1024)
NONCE  = Nuckle::Random.random_bytes(24)
KEY32  = Nuckle::Random.random_bytes(32)

# Pre-built keys
N_SK = Nuckle::PrivateKey.generate
N_PK = N_SK.public_key
R_SK = RbNaCl::PrivateKey.new(N_SK.to_s)
R_PK = R_SK.public_key

# Pre-built boxes
N_SBOX = Nuckle::SecretBox.new(KEY32)
R_SBOX = RbNaCl::SecretBox.new(KEY32)
N_BOX  = Nuckle::Box.new(N_PK, N_SK)
R_BOX  = RbNaCl::Box.new(R_PK, R_SK)

CT_SBOX = N_SBOX.encrypt(NONCE, MSG_1K)
CT_BOX  = N_BOX.encrypt(NONCE, MSG_1K)

# --- Benchmarks ---

Benchmark.ips do |x|
  x.config(warmup: 1, time: 3)

  puts "── SecretBox encrypt (1 KB) ──"
  x.report("nuckle") { N_SBOX.encrypt(NONCE, MSG_1K) }
  x.report("rbnacl") { R_SBOX.encrypt(NONCE, MSG_1K) }
  x.compare!
end

Benchmark.ips do |x|
  x.config(warmup: 1, time: 3)

  puts "\n── SecretBox decrypt (1 KB) ──"
  x.report("nuckle") { N_SBOX.decrypt(NONCE, CT_SBOX) }
  x.report("rbnacl") { R_SBOX.decrypt(NONCE, CT_SBOX) }
  x.compare!
end

Benchmark.ips do |x|
  x.config(warmup: 1, time: 3)

  puts "\n── Box encrypt (1 KB, pre-built) ──"
  x.report("nuckle") { N_BOX.encrypt(NONCE, MSG_1K) }
  x.report("rbnacl") { R_BOX.encrypt(NONCE, MSG_1K) }
  x.compare!
end

Benchmark.ips do |x|
  x.config(warmup: 1, time: 3)

  puts "\n── Poly1305 MAC (1 KB) ──"
  x.report("nuckle") { Nuckle::Internals::Poly1305.mac(KEY32, MSG_1K) }
  x.report("rbnacl") { RbNaCl::OneTimeAuth.new(KEY32).auth(MSG_1K) }
  x.compare!
end

Benchmark.ips do |x|
  x.config(warmup: 1, time: 3)

  puts "\n── XSalsa20 XOR (1 KB) ──"
  x.report("nuckle") { Nuckle::Internals::Salsa20.xsalsa20_xor(KEY32, NONCE, MSG_1K) }
  # rbnacl doesn't expose raw XSalsa20, so skip
  x.compare!
end

Benchmark.ips do |x|
  x.config(warmup: 1, time: 3)

  puts "\n── Curve25519 scalarmult ──"
  sk_bytes = N_SK.to_s
  pk_bytes = N_PK.to_s
  x.report("nuckle") { Nuckle::Internals::Curve25519.scalarmult(sk_bytes, pk_bytes) }
  x.report("rbnacl") { RbNaCl::GroupElements::Curve25519.new(pk_bytes).mult(sk_bytes) }
  x.compare!
end

Benchmark.ips do |x|
  x.config(warmup: 1, time: 3)

  puts "\n── Keypair generation (private → public) ──"
  sk_bytes = N_SK.to_s
  x.report("nuckle") { Nuckle::PrivateKey.new(sk_bytes).public_key }
  x.report("rbnacl") { RbNaCl::PrivateKey.new(sk_bytes).public_key }
  x.compare!
end
