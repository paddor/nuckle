# frozen_string_literal: true

module Nuckle
  class PrivateKey
    BYTES = 32

    def self.generate
      new(Random.random_bytes(BYTES))
    end

    def initialize(key)
      key = key.to_s if key.respond_to?(:to_s) && !key.is_a?(String)
      key = key.b
      raise ArgumentError, "private key must be #{BYTES} bytes (got #{key.bytesize})" unless key.bytesize == BYTES

      @key = key
    end

    def public_key
      PublicKey.new(Internals::Curve25519.scalarmult_base(@key))
    end

    def to_bytes = @key
    def to_s     = @key
  end
end
