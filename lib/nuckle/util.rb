# frozen_string_literal: true

module Nuckle
  module Util
    # Constant-time comparison of two 16-byte strings.
    def self.verify16(a, b)
      verify(a, b, 16)
    end

    # Constant-time comparison of two 32-byte strings.
    def self.verify32(a, b)
      verify(a, b, 32)
    end

    # Constant-time comparison of two 64-byte strings.
    def self.verify64(a, b)
      verify(a, b, 64)
    end

    # Best-effort constant-time comparison. Ruby/YJIT may not preserve
    # timing invariance at the hardware level, but at least the algorithm
    # does not short-circuit.
    def self.verify(a, b, expected_size = nil)
      a = a.b if a.encoding != Encoding::BINARY
      b = b.b if b.encoding != Encoding::BINARY
      return false if expected_size && (a.bytesize != expected_size || b.bytesize != expected_size)
      return false if a.bytesize != b.bytesize

      result = 0
      a.bytesize.times { |i| result |= a.getbyte(i) ^ b.getbyte(i) }
      result.zero?
    end
  end
end
