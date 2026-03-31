# frozen_string_literal: true

module Nuckle
  # Symmetric authenticated encryption: XSalsa20-Poly1305.
  #
  # Compatible with NaCl crypto_secretbox / libsodium crypto_secretbox_xsalsa20poly1305.
  #
  class SecretBox
    KEYBYTES     = 32
    NONCEBYTES   = 24
    ZEROBYTES    = 32
    BOXZEROBYTES = 16
    MACBYTES     = 16

    def initialize(key)
      key = key.b
      raise ArgumentError, "key must be #{KEYBYTES} bytes (got #{key.bytesize})" unless key.bytesize == KEYBYTES

      @key = key
    end

    def nonce_bytes = NONCEBYTES
    def key_bytes   = KEYBYTES

    # Encrypt plaintext with 24-byte nonce.
    #
    # @param nonce [String] 24-byte nonce
    # @param plaintext [String]
    # @return [String] authenticator (16 bytes) + ciphertext
    #
    def encrypt(nonce, plaintext)
      nonce     = nonce.b
      plaintext = plaintext.b
      raise ArgumentError, "nonce must be #{NONCEBYTES} bytes" unless nonce.bytesize == NONCEBYTES

      # Pad with 32 zero bytes
      padded = ("\x00" * ZEROBYTES + plaintext).b
      c      = Internals::Salsa20.xsalsa20_xor(@key, nonce, padded)

      # First 32 bytes of c: bytes 0..31 of XSalsa20 keystream XOR'd with zeros
      # → bytes 0..31 ARE the keystream. Use first 32 as Poly1305 one-time key.
      poly_key = c.byteslice(0, ZEROBYTES)
      mac      = Internals::Poly1305.mac(poly_key, c.byteslice(ZEROBYTES..))

      # Return: 16-byte MAC + ciphertext (skip first 16 zero bytes of c)
      # Actually NaCl convention: c[0..15] are zeros, c[16..31] replaced by mac
      mac + c.byteslice(ZEROBYTES..)
    end

    # Decrypt ciphertext with 24-byte nonce.
    #
    # @param nonce [String] 24-byte nonce
    # @param ciphertext [String] authenticator (16 bytes) + ciphertext
    # @return [String] plaintext
    # @raise [CryptoError] on authentication failure
    #
    def decrypt(nonce, ciphertext)
      nonce      = nonce.b
      ciphertext = ciphertext.b
      raise ArgumentError, "nonce must be #{NONCEBYTES} bytes" unless nonce.bytesize == NONCEBYTES
      raise CryptoError, "ciphertext too short" if ciphertext.bytesize < MACBYTES

      mac = ciphertext.byteslice(0, MACBYTES)
      ct  = ciphertext.byteslice(MACBYTES..)

      # Generate Poly1305 key from first 32 bytes of XSalsa20 keystream
      poly_key = Internals::Salsa20.xsalsa20_stream(@key, nonce, ZEROBYTES)

      # Verify MAC
      expected_mac = Internals::Poly1305.mac(poly_key, ct)
      raise CryptoError, "decryption failed" unless Util.verify16(mac, expected_mac)

      # Decrypt
      padded = ("\x00" * ZEROBYTES + ct).b
      m      = Internals::Salsa20.xsalsa20_xor(@key, nonce, padded)
      m.byteslice(ZEROBYTES..)
    end

    # Aliases matching rbnacl API
    alias box encrypt
    alias open decrypt
  end
end
