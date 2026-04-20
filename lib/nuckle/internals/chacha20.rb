# frozen_string_literal: true

module Nuckle
  module Internals
    # ChaCha20 stream cipher (DJB's original 8-byte-nonce variant).
    #
    # State layout (16 x 32-bit little-endian words):
    #   [ 0.. 3] "expand 32-byte k" constants
    #   [ 4..11] 32-byte key
    #   [12..13] 64-bit block counter (low word first)
    #   [14..15] 8-byte nonce
    #
    # Quarter-round rotations: 16, 12, 8, 7.
    #
    # References:
    # - https://cr.yp.to/chacha/chacha-20080128.pdf (ChaCha family)
    # - RFC 8439 uses the 12-byte-nonce variant; this module implements the
    #   8-byte-nonce variant required by ChaCha20-BLAKE3.
    #
    module Chacha20
      MASK32    = 0xFFFFFFFF
      SIGMA     = "expand 32-byte k".b.freeze
      SIGMA_V4  = SIGMA.unpack("V4").freeze

      module_function

      # ChaCha20 block function: 20 rounds on 16 x 32-bit words.
      #
      # @param key [String] 32-byte key
      # @param nonce [String] 8-byte nonce
      # @param counter [Integer] 64-bit block counter
      # @return [String] 64-byte keystream block
      #
      def block(key, nonce, counter)
        k0, k1, k2, k3, k4, k5, k6, k7 = key.unpack("V8")
        n0, n1 = nonce.unpack("V2")
        s0, s1, s2, s3 = SIGMA_V4
        c0 = counter & MASK32
        c1 = (counter >> 32) & MASK32

        x0  = s0; x1  = s1; x2  = s2; x3  = s3
        x4  = k0; x5  = k1; x6  = k2; x7  = k3
        x8  = k4; x9  = k5; x10 = k6; x11 = k7
        x12 = c0; x13 = c1; x14 = n0; x15 = n1

        z0 = x0; z1 = x1; z2 = x2; z3 = x3
        z4 = x4; z5 = x5; z6 = x6; z7 = x7
        z8 = x8; z9 = x9; z10 = x10; z11 = x11
        z12 = x12; z13 = x13; z14 = x14; z15 = x15

        10.times do
          # Column round: QR(0,4,8,12), QR(1,5,9,13), QR(2,6,10,14), QR(3,7,11,15)
          z0  = (z0  + z4)  & MASK32; z12 ^= z0;  z12 = ((z12 << 16) | (z12 >> 16)) & MASK32
          z8  = (z8  + z12) & MASK32; z4  ^= z8;  z4  = ((z4  << 12) | (z4  >> 20)) & MASK32
          z0  = (z0  + z4)  & MASK32; z12 ^= z0;  z12 = ((z12 <<  8) | (z12 >> 24)) & MASK32
          z8  = (z8  + z12) & MASK32; z4  ^= z8;  z4  = ((z4  <<  7) | (z4  >> 25)) & MASK32

          z1  = (z1  + z5)  & MASK32; z13 ^= z1;  z13 = ((z13 << 16) | (z13 >> 16)) & MASK32
          z9  = (z9  + z13) & MASK32; z5  ^= z9;  z5  = ((z5  << 12) | (z5  >> 20)) & MASK32
          z1  = (z1  + z5)  & MASK32; z13 ^= z1;  z13 = ((z13 <<  8) | (z13 >> 24)) & MASK32
          z9  = (z9  + z13) & MASK32; z5  ^= z9;  z5  = ((z5  <<  7) | (z5  >> 25)) & MASK32

          z2  = (z2  + z6)  & MASK32; z14 ^= z2;  z14 = ((z14 << 16) | (z14 >> 16)) & MASK32
          z10 = (z10 + z14) & MASK32; z6  ^= z10; z6  = ((z6  << 12) | (z6  >> 20)) & MASK32
          z2  = (z2  + z6)  & MASK32; z14 ^= z2;  z14 = ((z14 <<  8) | (z14 >> 24)) & MASK32
          z10 = (z10 + z14) & MASK32; z6  ^= z10; z6  = ((z6  <<  7) | (z6  >> 25)) & MASK32

          z3  = (z3  + z7)  & MASK32; z15 ^= z3;  z15 = ((z15 << 16) | (z15 >> 16)) & MASK32
          z11 = (z11 + z15) & MASK32; z7  ^= z11; z7  = ((z7  << 12) | (z7  >> 20)) & MASK32
          z3  = (z3  + z7)  & MASK32; z15 ^= z3;  z15 = ((z15 <<  8) | (z15 >> 24)) & MASK32
          z11 = (z11 + z15) & MASK32; z7  ^= z11; z7  = ((z7  <<  7) | (z7  >> 25)) & MASK32

          # Diagonal round: QR(0,5,10,15), QR(1,6,11,12), QR(2,7,8,13), QR(3,4,9,14)
          z0  = (z0  + z5)  & MASK32; z15 ^= z0;  z15 = ((z15 << 16) | (z15 >> 16)) & MASK32
          z10 = (z10 + z15) & MASK32; z5  ^= z10; z5  = ((z5  << 12) | (z5  >> 20)) & MASK32
          z0  = (z0  + z5)  & MASK32; z15 ^= z0;  z15 = ((z15 <<  8) | (z15 >> 24)) & MASK32
          z10 = (z10 + z15) & MASK32; z5  ^= z10; z5  = ((z5  <<  7) | (z5  >> 25)) & MASK32

          z1  = (z1  + z6)  & MASK32; z12 ^= z1;  z12 = ((z12 << 16) | (z12 >> 16)) & MASK32
          z11 = (z11 + z12) & MASK32; z6  ^= z11; z6  = ((z6  << 12) | (z6  >> 20)) & MASK32
          z1  = (z1  + z6)  & MASK32; z12 ^= z1;  z12 = ((z12 <<  8) | (z12 >> 24)) & MASK32
          z11 = (z11 + z12) & MASK32; z6  ^= z11; z6  = ((z6  <<  7) | (z6  >> 25)) & MASK32

          z2  = (z2  + z7)  & MASK32; z13 ^= z2;  z13 = ((z13 << 16) | (z13 >> 16)) & MASK32
          z8  = (z8  + z13) & MASK32; z7  ^= z8;  z7  = ((z7  << 12) | (z7  >> 20)) & MASK32
          z2  = (z2  + z7)  & MASK32; z13 ^= z2;  z13 = ((z13 <<  8) | (z13 >> 24)) & MASK32
          z8  = (z8  + z13) & MASK32; z7  ^= z8;  z7  = ((z7  <<  7) | (z7  >> 25)) & MASK32

          z3  = (z3  + z4)  & MASK32; z14 ^= z3;  z14 = ((z14 << 16) | (z14 >> 16)) & MASK32
          z9  = (z9  + z14) & MASK32; z4  ^= z9;  z4  = ((z4  << 12) | (z4  >> 20)) & MASK32
          z3  = (z3  + z4)  & MASK32; z14 ^= z3;  z14 = ((z14 <<  8) | (z14 >> 24)) & MASK32
          z9  = (z9  + z14) & MASK32; z4  ^= z9;  z4  = ((z4  <<  7) | (z4  >> 25)) & MASK32
        end

        [
          (z0  + x0)  & MASK32, (z1  + x1)  & MASK32, (z2  + x2)  & MASK32, (z3  + x3)  & MASK32,
          (z4  + x4)  & MASK32, (z5  + x5)  & MASK32, (z6  + x6)  & MASK32, (z7  + x7)  & MASK32,
          (z8  + x8)  & MASK32, (z9  + x9)  & MASK32, (z10 + x10) & MASK32, (z11 + x11) & MASK32,
          (z12 + x12) & MASK32, (z13 + x13) & MASK32, (z14 + x14) & MASK32, (z15 + x15) & MASK32,
        ].pack("V16")
      end

      # XOR message with ChaCha20 keystream.
      #
      # @param key [String] 32-byte key
      # @param nonce [String] 8-byte nonce
      # @param message [String] plaintext/ciphertext
      # @param counter [Integer] initial 64-bit block counter (default 0)
      # @return [String] XOR'd output (same length as message)
      #
      def xor(key, nonce, message, counter = 0)
        msg    = message.b
        len    = msg.bytesize
        out    = String.new(capacity: len, encoding: Encoding::BINARY)
        offset = 0

        while offset < len
          ks        = block(key, nonce, counter)
          remaining = len - offset
          take      = remaining < 64 ? remaining : 64

          if take == 64
            m = msg.byteslice(offset, 64).unpack("Q<8")
            b = ks.unpack("Q<8")
            out << [m[0] ^ b[0], m[1] ^ b[1], m[2] ^ b[2], m[3] ^ b[3],
                    m[4] ^ b[4], m[5] ^ b[5], m[6] ^ b[6], m[7] ^ b[7]].pack("Q<8")
          else
            m = msg.byteslice(offset, take).unpack("C*")
            b = ks.unpack("C*")
            take.times { |i| m[i] ^= b[i] }
            out << m.pack("C*")
          end

          offset  += take
          counter += 1
        end

        out
      end

      # Generate ChaCha20 keystream bytes (equivalent to XOR against zeros).
      #
      # @param key [String] 32-byte key
      # @param nonce [String] 8-byte nonce
      # @param length [Integer] number of bytes to generate
      # @param counter [Integer] initial 64-bit block counter (default 0)
      # @return [String] keystream bytes
      #
      def stream(key, nonce, length, counter = 0)
        xor(key, nonce, ("\x00".b * length), counter)
      end
    end
  end
end
