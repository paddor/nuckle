# frozen_string_literal: true

module Nuckle
  # Comparison utilities for cryptographic data. They have no early exit,
  # but Ruby gives no constant-time guarantee (see SECURITY.md).
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


    # Compares two strings byte by byte. XORs every byte pair and ORs the
    # results, so unlike String#== it does not stop at the first
    # difference. Lengths are not treated as secret.
    #
    # @param a [String] first string
    # @param b [String] second string
    # @param expected_size [Integer, nil] required byte length, or nil to skip check
    # @return [Boolean]
    def self.verify(a, b, expected_size = nil)
      return false if expected_size && (a.bytesize != expected_size || b.bytesize != expected_size)
      return false unless a.bytesize == b.bytesize

      diff = 0
      a.bytesize.times { |i| diff |= a.getbyte(i) ^ b.getbyte(i) }
      diff.zero?
    end


    # Checks whether every byte is zero. ORs all bytes together, with no
    # early exit.
    #
    # @param bytes [String]
    # @return [Boolean]
    def self.zero?(bytes)
      acc = 0
      bytes.each_byte { |byte| acc |= byte }
      acc.zero?
    end
  end
end
