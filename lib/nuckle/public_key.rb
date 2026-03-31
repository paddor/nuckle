# frozen_string_literal: true

module Nuckle
  class PublicKey
    BYTES = 32

    def initialize(key)
      key = key.to_s if key.respond_to?(:to_s) && !key.is_a?(String)
      key = key.b
      raise ArgumentError, "public key must be #{BYTES} bytes (got #{key.bytesize})" unless key.bytesize == BYTES

      @key = key
    end

    def to_bytes = @key
    def to_s     = @key

    def ==(other)
      other.is_a?(PublicKey) && Util.verify32(@key, other.to_s)
    end
  end
end
