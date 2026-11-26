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


    # @param public_key [PublicKey, String] peer's 32-byte public key
    # @param private_key [PrivateKey, String] own 32-byte private key
    # @raise [CryptoError] if +public_key+ is a low-order point. RbNaCl
    #   raises the same error, but only on the first encrypt or decrypt.
    # @raise [TypeError] if a key is the wrong type, e.g. the two are swapped
    def initialize(public_key, private_key)
      public_key  = PublicKey.new(public_key) unless public_key.is_a?(PublicKey)
      private_key = PrivateKey.new(private_key) unless private_key.is_a?(PrivateKey)

      # Compute shared secret via Curve25519 DH
      shared = private_key.diffie_hellman(public_key)

      # Derive symmetric key via HSalsa20 (the "beforenm" step)
      key = Internals::Salsa20.hsalsa20(shared, "\x00" * 16)

      @secret_box = SecretBox.new(key)
    end


    # @return [Integer] required nonce length in bytes
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
  end
end
