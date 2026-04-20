# frozen_string_literal: true

# Usage:
#   ruby bench/primitives.rb          # without YJIT
#   ruby --yjit bench/primitives.rb   # with YJIT

require "bundler/setup"
require "benchmark/ips"
require "nuckle"
require "rbnacl"
require "digest/blake3"
require "chacha20blake3"

YJIT = defined?(RubyVM::YJIT) && RubyVM::YJIT.enabled?
puts "Ruby #{RUBY_VERSION} | YJIT: #{YJIT ? "ON" : "OFF"}"
puts

SIZES  = [256, 1024, 4096, 16_384].freeze
NONCE  = Nuckle::Random.random_bytes(24)
KEY32  = Nuckle::Random.random_bytes(32)
MSGS   = SIZES.each_with_object({}) { |n, h| h[n] = Nuckle::Random.random_bytes(n) }

def label(size)
  size >= 1024 ? "#{size / 1024}KB" : "#{size}B"
end

def compare(title, &setup)
  puts "\n── #{title} ──"
  SIZES.each do |n|
    pure, native = setup.call(n, MSGS[n])
    Benchmark.ips do |x|
      x.config(warmup: 0.5, time: 1.5, quiet: native ? true : false)
      x.report(" nuckle #{label(n).rjust(5)}", &pure)
      if native
        x.report(" native #{label(n).rjust(5)}", &native)
        x.compare!
      end
    end
  end
end

# Pre-built keys and objects reused across iterations
N_SK   = Nuckle::PrivateKey.generate
N_PK   = N_SK.public_key
R_SK   = RbNaCl::PrivateKey.new(N_SK.to_s)
R_PK   = R_SK.public_key
N_SBOX = Nuckle::SecretBox.new(KEY32)
R_SBOX = RbNaCl::SecretBox.new(KEY32)
N_BOX  = Nuckle::Box.new(N_PK, N_SK)
R_BOX  = RbNaCl::Box.new(R_PK, R_SK)
N_CB3  = Nuckle::Chacha20Blake3::Cipher.new(KEY32)
R_CB3  = ChaCha20Blake3::Cipher.new(KEY32)
R_OTA  = RbNaCl::OneTimeAuth.new(KEY32)
NONCE8 = NONCE.byteslice(0, 8)

# ---------------------------------------------------------------------------
# Size-dependent primitives
# ---------------------------------------------------------------------------

compare("BLAKE3 hash") do |_, msg|
  [->{ Nuckle::Internals::Blake3.hash(msg) },
   ->{ Digest::Blake3.digest(msg) }]
end

compare("Poly1305 MAC") do |_, msg|
  [->{ Nuckle::Internals::Poly1305.mac(KEY32, msg) },
   ->{ R_OTA.auth(msg) }]
end

compare("XSalsa20 XOR (no rbnacl equivalent)") do |_, msg|
  [->{ Nuckle::Internals::Salsa20.xsalsa20_xor(KEY32, NONCE, msg) }, nil]
end

compare("ChaCha20 XOR (no rbnacl equivalent)") do |_, msg|
  [->{ Nuckle::Internals::Chacha20.xor(KEY32, NONCE8, msg) }, nil]
end

compare("SecretBox encrypt (XSalsa20-Poly1305)") do |_, msg|
  [->{ N_SBOX.encrypt(NONCE, msg) },
   ->{ R_SBOX.encrypt(NONCE, msg) }]
end

compare("Box encrypt (Curve25519-XSalsa20-Poly1305)") do |_, msg|
  [->{ N_BOX.encrypt(NONCE, msg) },
   ->{ R_BOX.encrypt(NONCE, msg) }]
end

compare("ChaCha20-BLAKE3 encrypt") do |_, msg|
  [->{ N_CB3.encrypt(NONCE, msg) },
   ->{ R_CB3.encrypt(NONCE, msg) }]
end

# ---------------------------------------------------------------------------
# Size-independent primitives
# ---------------------------------------------------------------------------

puts "\n── Curve25519 scalarmult ──"
Benchmark.ips do |x|
  x.config(warmup: 0.5, time: 1.5, quiet: true)
  sk_bytes = N_SK.to_s
  pk_bytes = N_PK.to_s
  x.report(" nuckle") { Nuckle::Internals::Curve25519.scalarmult(sk_bytes, pk_bytes) }
  x.report(" rbnacl") { RbNaCl::GroupElements::Curve25519.new(pk_bytes).mult(sk_bytes) }
  x.compare!
end

puts "\n── Keypair generation (private → public) ──"
Benchmark.ips do |x|
  x.config(warmup: 0.5, time: 1.5, quiet: true)
  sk_bytes = N_SK.to_s
  x.report(" nuckle") { Nuckle::PrivateKey.new(sk_bytes).public_key }
  x.report(" rbnacl") { RbNaCl::PrivateKey.new(sk_bytes).public_key }
  x.compare!
end
