# frozen_string_literal: true

# Pure Ruby NaCl-compatible cryptography library.
# Provides Curve25519 key agreement, XSalsa20-Poly1305 authenticated
# encryption (SecretBox), and public-key authenticated encryption (Box).

require_relative "nuckle/version"
require_relative "nuckle/crypto_error"
require_relative "nuckle/random"
require_relative "nuckle/util"
require_relative "nuckle/internals/curve25519"
require_relative "nuckle/internals/salsa20"
require_relative "nuckle/internals/chacha20"
require_relative "nuckle/internals/poly1305"
require_relative "nuckle/internals/blake3"
require_relative "nuckle/public_key"
require_relative "nuckle/private_key"
require_relative "nuckle/box"
require_relative "nuckle/secret_box"
require_relative "nuckle/chacha20_blake3"
