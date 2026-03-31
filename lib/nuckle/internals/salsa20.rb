# frozen_string_literal: true

module Nuckle
  module Internals
    # Salsa20 stream cipher family: Salsa20 core, HSalsa20, XSalsa20.
    #
    # References:
    # - https://cr.yp.to/snuffle/spec.pdf (Salsa20 specification)
    # - https://cr.yp.to/snuffle/xsalsa-20110204.pdf (XSalsa20)
    #
    module Salsa20
      MASK32    = 0xFFFFFFFF
      SIGMA     = "expand 32-byte k".b.freeze
      SIGMA_V4  = SIGMA.unpack("V4").freeze

      module_function

      # Salsa20 core function: 20 rounds on 16 x 32-bit words.
      # Returns the 64-byte output block.
      #
      # @param input [String] 64-byte input block
      # @return [String] 64-byte output block
      #
      def core(input)
        x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15 =
          input.unpack("V16")

        z0  = x0;  z1  = x1;  z2  = x2;  z3  = x3
        z4  = x4;  z5  = x5;  z6  = x6;  z7  = x7
        z8  = x8;  z9  = x9;  z10 = x10; z11 = x11
        z12 = x12; z13 = x13; z14 = x14; z15 = x15

        10.times do
          # Column rounds
          t = (z0  + z12) & MASK32; z4  ^= ((t << 7)  | (t >> 25)) & MASK32
          t = (z4  + z0)  & MASK32; z8  ^= ((t << 9)  | (t >> 23)) & MASK32
          t = (z8  + z4)  & MASK32; z12 ^= ((t << 13) | (t >> 19)) & MASK32
          t = (z12 + z8)  & MASK32; z0  ^= ((t << 18) | (t >> 14)) & MASK32

          t = (z5  + z1)  & MASK32; z9  ^= ((t << 7)  | (t >> 25)) & MASK32
          t = (z9  + z5)  & MASK32; z13 ^= ((t << 9)  | (t >> 23)) & MASK32
          t = (z13 + z9)  & MASK32; z1  ^= ((t << 13) | (t >> 19)) & MASK32
          t = (z1  + z13) & MASK32; z5  ^= ((t << 18) | (t >> 14)) & MASK32

          t = (z10 + z6)  & MASK32; z14 ^= ((t << 7)  | (t >> 25)) & MASK32
          t = (z14 + z10) & MASK32; z2  ^= ((t << 9)  | (t >> 23)) & MASK32
          t = (z2  + z14) & MASK32; z6  ^= ((t << 13) | (t >> 19)) & MASK32
          t = (z6  + z2)  & MASK32; z10 ^= ((t << 18) | (t >> 14)) & MASK32

          t = (z15 + z11) & MASK32; z3  ^= ((t << 7)  | (t >> 25)) & MASK32
          t = (z3  + z15) & MASK32; z7  ^= ((t << 9)  | (t >> 23)) & MASK32
          t = (z7  + z3)  & MASK32; z11 ^= ((t << 13) | (t >> 19)) & MASK32
          t = (z11 + z7)  & MASK32; z15 ^= ((t << 18) | (t >> 14)) & MASK32

          # Row rounds
          t = (z0  + z3)  & MASK32; z1  ^= ((t << 7)  | (t >> 25)) & MASK32
          t = (z1  + z0)  & MASK32; z2  ^= ((t << 9)  | (t >> 23)) & MASK32
          t = (z2  + z1)  & MASK32; z3  ^= ((t << 13) | (t >> 19)) & MASK32
          t = (z3  + z2)  & MASK32; z0  ^= ((t << 18) | (t >> 14)) & MASK32

          t = (z5  + z4)  & MASK32; z6  ^= ((t << 7)  | (t >> 25)) & MASK32
          t = (z6  + z5)  & MASK32; z7  ^= ((t << 9)  | (t >> 23)) & MASK32
          t = (z7  + z6)  & MASK32; z4  ^= ((t << 13) | (t >> 19)) & MASK32
          t = (z4  + z7)  & MASK32; z5  ^= ((t << 18) | (t >> 14)) & MASK32

          t = (z10 + z9)  & MASK32; z11 ^= ((t << 7)  | (t >> 25)) & MASK32
          t = (z11 + z10) & MASK32; z8  ^= ((t << 9)  | (t >> 23)) & MASK32
          t = (z8  + z11) & MASK32; z9  ^= ((t << 13) | (t >> 19)) & MASK32
          t = (z9  + z8)  & MASK32; z10 ^= ((t << 18) | (t >> 14)) & MASK32

          t = (z15 + z14) & MASK32; z12 ^= ((t << 7)  | (t >> 25)) & MASK32
          t = (z12 + z15) & MASK32; z13 ^= ((t << 9)  | (t >> 23)) & MASK32
          t = (z13 + z12) & MASK32; z14 ^= ((t << 13) | (t >> 19)) & MASK32
          t = (z14 + z13) & MASK32; z15 ^= ((t << 18) | (t >> 14)) & MASK32
        end

        [
          (z0  + x0)  & MASK32, (z1  + x1)  & MASK32, (z2  + x2)  & MASK32, (z3  + x3)  & MASK32,
          (z4  + x4)  & MASK32, (z5  + x5)  & MASK32, (z6  + x6)  & MASK32, (z7  + x7)  & MASK32,
          (z8  + x8)  & MASK32, (z9  + x9)  & MASK32, (z10 + x10) & MASK32, (z11 + x11) & MASK32,
          (z12 + x12) & MASK32, (z13 + x13) & MASK32, (z14 + x14) & MASK32, (z15 + x15) & MASK32,
        ].pack("V16")
      end

      # HSalsa20: derives a 32-byte subkey from a 32-byte key and 16-byte nonce.
      # Returns words [0,5,10,15,6,7,8,9] from the NON-added state.
      #
      # @param key [String] 32-byte key
      # @param nonce [String] 16-byte nonce
      # @return [String] 32-byte subkey
      #
      def hsalsa20(key, nonce)
        k0, k1, k2, k3, k4, k5, k6, k7 = key.unpack("V8")
        n0, n1, n2, n3 = nonce.unpack("V4")
        s0, s1, s2, s3 = SIGMA_V4

        z0  = s0; z1  = k0; z2  = k1; z3  = k2
        z4  = k3; z5  = s1; z6  = n0; z7  = n1
        z8  = n2; z9  = n3; z10 = s2; z11 = k4
        z12 = k5; z13 = k6; z14 = k7; z15 = s3

        10.times do
          t = (z0  + z12) & MASK32; z4  ^= ((t << 7)  | (t >> 25)) & MASK32
          t = (z4  + z0)  & MASK32; z8  ^= ((t << 9)  | (t >> 23)) & MASK32
          t = (z8  + z4)  & MASK32; z12 ^= ((t << 13) | (t >> 19)) & MASK32
          t = (z12 + z8)  & MASK32; z0  ^= ((t << 18) | (t >> 14)) & MASK32

          t = (z5  + z1)  & MASK32; z9  ^= ((t << 7)  | (t >> 25)) & MASK32
          t = (z9  + z5)  & MASK32; z13 ^= ((t << 9)  | (t >> 23)) & MASK32
          t = (z13 + z9)  & MASK32; z1  ^= ((t << 13) | (t >> 19)) & MASK32
          t = (z1  + z13) & MASK32; z5  ^= ((t << 18) | (t >> 14)) & MASK32

          t = (z10 + z6)  & MASK32; z14 ^= ((t << 7)  | (t >> 25)) & MASK32
          t = (z14 + z10) & MASK32; z2  ^= ((t << 9)  | (t >> 23)) & MASK32
          t = (z2  + z14) & MASK32; z6  ^= ((t << 13) | (t >> 19)) & MASK32
          t = (z6  + z2)  & MASK32; z10 ^= ((t << 18) | (t >> 14)) & MASK32

          t = (z15 + z11) & MASK32; z3  ^= ((t << 7)  | (t >> 25)) & MASK32
          t = (z3  + z15) & MASK32; z7  ^= ((t << 9)  | (t >> 23)) & MASK32
          t = (z7  + z3)  & MASK32; z11 ^= ((t << 13) | (t >> 19)) & MASK32
          t = (z11 + z7)  & MASK32; z15 ^= ((t << 18) | (t >> 14)) & MASK32

          t = (z0  + z3)  & MASK32; z1  ^= ((t << 7)  | (t >> 25)) & MASK32
          t = (z1  + z0)  & MASK32; z2  ^= ((t << 9)  | (t >> 23)) & MASK32
          t = (z2  + z1)  & MASK32; z3  ^= ((t << 13) | (t >> 19)) & MASK32
          t = (z3  + z2)  & MASK32; z0  ^= ((t << 18) | (t >> 14)) & MASK32

          t = (z5  + z4)  & MASK32; z6  ^= ((t << 7)  | (t >> 25)) & MASK32
          t = (z6  + z5)  & MASK32; z7  ^= ((t << 9)  | (t >> 23)) & MASK32
          t = (z7  + z6)  & MASK32; z4  ^= ((t << 13) | (t >> 19)) & MASK32
          t = (z4  + z7)  & MASK32; z5  ^= ((t << 18) | (t >> 14)) & MASK32

          t = (z10 + z9)  & MASK32; z11 ^= ((t << 7)  | (t >> 25)) & MASK32
          t = (z11 + z10) & MASK32; z8  ^= ((t << 9)  | (t >> 23)) & MASK32
          t = (z8  + z11) & MASK32; z9  ^= ((t << 13) | (t >> 19)) & MASK32
          t = (z9  + z8)  & MASK32; z10 ^= ((t << 18) | (t >> 14)) & MASK32

          t = (z15 + z14) & MASK32; z12 ^= ((t << 7)  | (t >> 25)) & MASK32
          t = (z12 + z15) & MASK32; z13 ^= ((t << 9)  | (t >> 23)) & MASK32
          t = (z13 + z12) & MASK32; z14 ^= ((t << 13) | (t >> 19)) & MASK32
          t = (z14 + z13) & MASK32; z15 ^= ((t << 18) | (t >> 14)) & MASK32
        end

        # Return words [0,5,10,15,6,7,8,9] — the diagonal + second row
        [z0, z5, z10, z15, z6, z7, z8, z9].pack("V8")
      end

      # XSalsa20 stream XOR: encrypts/decrypts message using 32-byte key and 24-byte nonce.
      #
      # @param key [String] 32-byte key
      # @param nonce [String] 24-byte nonce
      # @param message [String] plaintext/ciphertext
      # @return [String] XOR'd output (same length as message)
      #
      def xsalsa20_xor(key, nonce, message)
        subkey    = hsalsa20(key, nonce.byteslice(0, 16))
        sub_nonce = (nonce.byteslice(16, 8) + "\x00\x00\x00\x00\x00\x00\x00\x00").b
        salsa20_xor(subkey, sub_nonce, message)
      end

      # Salsa20 stream XOR with 32-byte key and 16-byte nonce/counter.
      #
      # @param key [String] 32-byte key
      # @param nonce [String] 16-byte (8-byte nonce + 8-byte counter, LE)
      # @param message [String] plaintext/ciphertext
      # @return [String] XOR'd output
      #
      def salsa20_xor(key, nonce, message)
        k0, k1, k2, k3, k4, k5, k6, k7 = key.unpack("V8")
        n0, n1, n2, n3 = nonce.unpack("V4")
        s0, s1, s2, s3 = SIGMA_V4

        msg    = message.b
        len    = msg.bytesize
        out    = String.new(capacity: len, encoding: Encoding::BINARY)
        offset = 0

        while offset < len
          # Build + run Salsa20 core inline
          block = core([
            s0, k0, k1, k2,
            k3, s1, n0, n1,
            n2, n3, s2, k4,
            k5, k6, k7, s3,
          ].pack("V16"))

          # XOR message bytes with keystream block
          remaining = len - offset
          take      = remaining < 64 ? remaining : 64

          if take == 64
            # Fast path: XOR 8 x uint64
            m = msg.byteslice(offset, 64).unpack("Q<8")
            b = block.unpack("Q<8")
            out << [m[0] ^ b[0], m[1] ^ b[1], m[2] ^ b[2], m[3] ^ b[3],
                    m[4] ^ b[4], m[5] ^ b[5], m[6] ^ b[6], m[7] ^ b[7]].pack("Q<8")
          else
            # Tail: XOR byte-by-byte
            m = msg.byteslice(offset, take).unpack("C*")
            b = block.unpack("C*")
            take.times { |i| m[i] ^= b[i] }
            out << m.pack("C*")
          end
          offset += take

          # Increment 64-bit counter (words n2, n3)
          counter  = n2 | (n3 << 32)
          counter += 1
          n2       = counter & MASK32
          n3       = (counter >> 32) & MASK32
        end

        out
      end

      # Generate XSalsa20 keystream (no XOR, just the stream bytes).
      #
      # @param key [String] 32-byte key
      # @param nonce [String] 24-byte nonce
      # @param length [Integer] number of bytes to generate
      # @return [String] keystream bytes
      #
      def xsalsa20_stream(key, nonce, length)
        xsalsa20_xor(key, nonce, "\x00".b * length)
      end
    end
  end
end
