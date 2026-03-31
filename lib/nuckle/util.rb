# frozen_string_literal: true

module Nuckle
  module Util
    # Compare two 16-byte strings.
    def self.verify16(a, b)
      verify(a, b, 16)
    end

    # Compare two 32-byte strings.
    def self.verify32(a, b)
      verify(a, b, 32)
    end

    # Compare two 64-byte strings.
    def self.verify64(a, b)
      verify(a, b, 64)
    end

    def self.verify(a, b, expected_size = nil)
      a = a.b if a.encoding != Encoding::BINARY
      b = b.b if b.encoding != Encoding::BINARY
      return false if expected_size && (a.bytesize != expected_size || b.bytesize != expected_size)

      a == b
    end
  end
end
