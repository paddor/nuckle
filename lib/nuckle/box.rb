# frozen_string_literal: true

module Nuckle
  # Public-key authenticated encryption: Curve25519-XSalsa20-Poly1305.
  #
  # Compatible with NaCl crypto_box / libsodium crypto_box_curve25519xsalsa20poly1305.
  #
  class Box
    NONCEBYTES     = 24
    PUBLICKEYBYTES = 32
    PRIVATEKEYBYTES = 32
    BEFORENMBYTES  = 32
    MACBYTES       = 16

    def initialize(public_key, private_key)
      pk = extract_bytes(public_key, PUBLICKEYBYTES, "public key")
      sk = extract_bytes(private_key, PRIVATEKEYBYTES, "private key")

      # Compute shared secret via Curve25519 DH
      shared = Internals::Curve25519.scalarmult(sk, pk)

      # Derive symmetric key via HSalsa20 (the "beforenm" step)
      key = Internals::Salsa20.hsalsa20(shared, "\x00" * 16)

      @secret_box = SecretBox.new(key)
    end

    def nonce_bytes = NONCEBYTES

    # Encrypt plaintext with 24-byte nonce.
    def encrypt(nonce, plaintext)
      @secret_box.encrypt(nonce, plaintext)
    end

    # Decrypt ciphertext with 24-byte nonce.
    def decrypt(nonce, ciphertext)
      @secret_box.decrypt(nonce, ciphertext)
    end

    alias box encrypt
    alias open decrypt

    private

    def extract_bytes(key, expected_size, name)
      bytes = case key
              when PublicKey, PrivateKey then key.to_s
              when String               then key.b
              else raise ArgumentError, "#{name} must be a Key or String"
              end
      raise ArgumentError, "#{name} must be #{expected_size} bytes (got #{bytes.bytesize})" unless bytes.bytesize == expected_size

      bytes
    end
  end
end
