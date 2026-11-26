# frozen_string_literal: true

module Nuckle
  # An X25519 (Curve25519) public key.
  class PublicKey
    # Key length in bytes.
    BYTES = 32


    # @param key [String, PublicKey] 32-byte raw public key (binary)
    # @raise [TypeError] if +key+ is neither a PublicKey nor a String
    def initialize(key)
      key = key.to_s if key.is_a?(PublicKey)
      raise TypeError, "public key must be a String or #{PublicKey} (got #{key.class})" unless key.respond_to?(:to_str)

      key = key.to_str.b
      raise ArgumentError, "public key must be #{BYTES} bytes (got #{key.bytesize})" unless key.bytesize == BYTES

      @key = key
    end


    # @return [String] raw 32-byte key (binary)
    def to_bytes = @key
    # @return [String] raw 32-byte key (binary)
    def to_s     = @key

    # Equality without an early exit (see {Util.verify}).
    #
    # @param other [PublicKey] key to compare
    # @return [Boolean]
    def ==(other)
      other.is_a?(PublicKey) && Util.verify32(@key, other.to_s)
    end
  end
end
