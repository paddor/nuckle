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


    # @param key [String] 32-byte raw private key (binary)
    def initialize(key)
      key = key.to_s if key.respond_to?(:to_s) && !key.is_a?(String)
      key = key.b
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
    # @param peer_public_key [PublicKey, String] peer's 32-byte public key
    # @return [String] 32-byte shared secret (binary)
    def diffie_hellman(peer_public_key)
      pk = case peer_public_key
           when PublicKey
             peer_public_key.to_s
           when String
             peer_public_key.b
           else
             raise ArgumentError, "peer_public_key must be a PublicKey or String"
           end
      raise ArgumentError, "peer public key must be 32 bytes" unless pk.bytesize == BYTES

      Internals::Curve25519.scalarmult(@key, pk)
    end


    # @return [String] raw 32-byte key (binary)
    def to_bytes = @key
    # @return [String] raw 32-byte key (binary)
    def to_s     = @key
  end
end
