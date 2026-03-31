# frozen_string_literal: true

module Nuckle
  module Internals
    # Poly1305 one-time message authenticator.
    #
    # Reference: https://cr.yp.to/mac/poly1305-20050329.pdf
    #            RFC 8439 Section 2.5
    #
    module Poly1305
      P = (1 << 130) - 5

      # Clamp mask for r (clear specific bits per spec)
      R_CLAMP = 0x0ffffffc0ffffffc0ffffffc0fffffff

      MASK128 = (1 << 128) - 1

      module_function

      # Compute Poly1305 MAC.
      #
      # @param key [String] 32-byte one-time key (r || s)
      # @param message [String] message to authenticate
      # @return [String] 16-byte authentication tag
      #
      def mac(key, message)
        r = le_bytes_to_int(key, 0, 16) & R_CLAMP
        s = le_bytes_to_int(key, 16, 16)

        h   = 0
        msg = message.b
        len = msg.bytesize
        off = 0

        while off < len
          remaining = len - off
          take      = remaining < 16 ? remaining : 16
          block     = le_bytes_to_int(msg, off, take)

          # Add high bit (2^(8*take)) to mark block as non-zero-padded
          block |= 1 << (take * 8)

          h = ((h + block) * r) % P
          off += take
        end

        # Final: (h + s) mod 2^128
        tag = (h + s) & MASK128
        int_to_le_bytes(tag)
      end

      # Read little-endian integer from a string at offset, length bytes.
      def le_bytes_to_int(bytes, offset, length)
        if length == 16
          lo, hi = bytes.unpack("@#{offset}Q<2")
          lo | (hi << 64)
        else
          n = 0
          length.times { |i| n |= bytes.getbyte(offset + i) << (8 * i) }
          n
        end
      end

      # Write a 128-bit integer as 16 little-endian bytes.
      def int_to_le_bytes(n)
        [n & 0xFFFFFFFFFFFFFFFF, (n >> 64) & 0xFFFFFFFFFFFFFFFF].pack("Q<2")
      end
    end
  end
end
