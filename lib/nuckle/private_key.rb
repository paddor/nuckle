# frozen_string_literal: true

module Nuckle
  # An X25519 (Curve25519) private key for Diffie-Hellman key agreement.
  class PrivateKey
    # Key length in bytes.
    BYTES = 32


    # Generates a new random private key.
    #
    # @return [PrivateKey]
    def self.generate
      new(Random.random_bytes(BYTES))
    end


    # @param key [String, PrivateKey] 32-byte raw private key (binary)
    # @raise [TypeError] if +key+ is neither a PrivateKey nor a String
    def initialize(key)
      key = key.to_s if key.is_a?(PrivateKey)
      raise TypeError, "private key must be a String or #{PrivateKey} (got #{key.class})" unless key.respond_to?(:to_str)

      key = key.to_str.b
      raise ArgumentError, "private key must be #{BYTES} bytes (got #{key.bytesize})" unless key.bytesize == BYTES

      @key = key
    end


    # Derives the corresponding public key via Curve25519 scalar base multiplication.
    #
    # @return [PublicKey]
    def public_key
      PublicKey.new(Internals::Curve25519.scalarmult_base(@key))
    end


    # Raw X25519 Diffie-Hellman: scalar multiply this secret key by a peer's
    # public key to produce a 32-byte shared secret.
    #
    # Unlike {Box}, this returns the raw DH output without further key
    # derivation (no HSalsa20). Callers are responsible for deriving
    # symmetric keys from the result (e.g. via HKDF or BLAKE3-derive-key).
    #
    # Like libsodium's crypto_scalarmult, it refuses low-order public keys:
    # those make the shared secret all zero.
    #
    # @param peer_public_key [PublicKey, String] peer's 32-byte public key
    # @return [String] 32-byte shared secret (binary)
    # @raise [CryptoError] if the shared secret is all zero
    # @raise [TypeError] if +peer_public_key+ is neither a PublicKey nor a String
    def diffie_hellman(peer_public_key)
      peer_public_key = PublicKey.new(peer_public_key) unless peer_public_key.is_a?(PublicKey)

      shared = Internals::Curve25519.scalarmult(@key, peer_public_key.to_s)
      raise CryptoError, "low-order public key (all-zero shared secret)" if Util.zero?(shared)

      shared
    end


    # @return [String] raw 32-byte key (binary)
    def to_bytes = @key
    # @return [String] raw 32-byte key (binary)
    def to_s     = @key


    # Hides the key bytes, so they stay out of logs and error output.
    #
    # @return [String]
    def inspect
      "#<#{self.class}>"
    end
  end
end
