# frozen_string_literal: true

module Nuckle
  # An X25519 (Curve25519) public key.
  class PublicKey
    # Key length in bytes.
    BYTES = 32


    # @param key [String] 32-byte raw public key (binary)
    def initialize(key)
      key = key.to_s if key.respond_to?(:to_s) && !key.is_a?(String)
      key = key.b
      raise ArgumentError, "public key must be #{BYTES} bytes (got #{key.bytesize})" unless key.bytesize == BYTES

      @key = key
    end


    # @return [String] raw 32-byte key (binary)
    def to_bytes = @key
    # @return [String] raw 32-byte key (binary)
    def to_s     = @key

    # Constant-time equality comparison.
    #
    # @param other [PublicKey] key to compare
    # @return [Boolean]
    def ==(other)
      other.is_a?(PublicKey) && Util.verify32(@key, other.to_s)
    end
  end
end
