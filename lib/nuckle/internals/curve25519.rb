# frozen_string_literal: true

module Nuckle
  module Internals
    # Curve25519 elliptic-curve Diffie-Hellman.
    #
    # Montgomery curve: y^2 = x^3 + 486662*x^2 + x over GF(2^255 - 19).
    # Uses the Montgomery ladder for scalar multiplication.
    #
    # Reference: RFC 7748
    #
    module Curve25519
      P      = (1 << 255) - 19
      A24    = 121666  # (486662 + 2) / 4
      BASE_U = 9

      MASK64 = 0xFFFFFFFFFFFFFFFF

      module_function

      # Scalar multiplication: compute scalar * point on Curve25519.
      #
      # @param scalar [String] 32-byte scalar (private key)
      # @param u_bytes [String] 32-byte u-coordinate (public key / base point)
      # @return [String] 32-byte result u-coordinate
      #
      def scalarmult(scalar, u_bytes)
        k = decode_scalar(scalar)
        u = decode_u(u_bytes)

        x_1 = u
        x_2 = 1
        z_2 = 0
        x_3 = u
        z_3 = 1

        swap = 0

        254.downto(0) do |t|
          k_t  = (k >> t) & 1
          swap ^= k_t
          # Constant-time conditional swap (XOR mask)
          mask   = -swap
          dummy  = (x_2 ^ x_3) & mask; x_2 ^= dummy; x_3 ^= dummy
          dummy  = (z_2 ^ z_3) & mask; z_2 ^= dummy; z_3 ^= dummy
          swap = k_t

          a  = (x_2 + z_2) % P
          aa = (a * a) % P
          b  = (x_2 - z_2) % P
          bb = (b * b) % P
          e  = (aa - bb) % P
          c  = (x_3 + z_3) % P
          d  = (x_3 - z_3) % P
          da = (d * a) % P
          cb = (c * b) % P

          sum = (da + cb) % P; x_3 = (sum * sum) % P
          dif = (da - cb) % P; z_3 = (x_1 * ((dif * dif) % P)) % P
          x_2 = (aa * bb) % P
          z_2 = (e * ((bb + A24 * e) % P)) % P
        end

        # Final cswap
        mask  = -swap
        dummy = (x_2 ^ x_3) & mask; x_2 ^= dummy
        dummy = (z_2 ^ z_3) & mask; z_2 ^= dummy

        result = (x_2 * z_2.pow(P - 2, P)) % P
        encode_u(result)
      end

      # Scalar multiplication with the standard base point (u=9).
      #
      # @param scalar [String] 32-byte scalar (private key)
      # @return [String] 32-byte public key
      #
      def scalarmult_base(scalar)
        scalarmult(scalar, "\x09".b + "\x00".b * 31)
      end

      # Decode a 32-byte scalar with clamping (per RFC 7748).
      def decode_scalar(s)
        buf = s.b.dup
        buf.setbyte(0,  buf.getbyte(0)  & 248)
        buf.setbyte(31, (buf.getbyte(31) & 127) | 64)
        w = buf.unpack("Q<4")
        w[0] | (w[1] << 64) | (w[2] << 128) | (w[3] << 192)
      end

      # Decode a u-coordinate from 32 bytes (little-endian, mask high bit).
      def decode_u(u_bytes)
        buf = u_bytes.b.dup
        buf.setbyte(31, buf.getbyte(31) & 0x7F)
        w = buf.unpack("Q<4")
        w[0] | (w[1] << 64) | (w[2] << 128) | (w[3] << 192)
      end

      # Encode a field element to 32 bytes (little-endian).
      def encode_u(u)
        [u & MASK64, (u >> 64) & MASK64, (u >> 128) & MASK64, (u >> 192) & MASK64].pack("Q<4")
      end
    end
  end
end
