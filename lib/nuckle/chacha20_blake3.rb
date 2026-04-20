# frozen_string_literal: true

module Nuckle
  # ChaCha20-BLAKE3 authenticated encryption with associated data (AEAD).
  #
  # Wire-compatible with the `chacha20-blake3` Rust crate
  # (https://github.com/skerkour/chacha20-blake3). Given a 32-byte master key
  # and a 24-byte nonce:
  #
  # 1. BLAKE3-keyed(master_key) absorbing the nonce, then XOF-extracting 72
  #    bytes, splits into (encryption_key, authentication_key, chacha20_nonce)
  #    of sizes (32, 32, 8).
  # 2. Encrypt plaintext with ChaCha20(encryption_key, chacha20_nonce).
  # 3. Tag = BLAKE3-keyed(authentication_key) over
  #    aad || u64_le(aad.bytesize) || ciphertext || u64_le(ciphertext.bytesize).
  # 4. Output is `ciphertext || tag`.
  #
  module Chacha20Blake3
    KEYBYTES   = 32
    NONCEBYTES = 24
    TAGBYTES   = 32

    # Authenticated encryption cipher.
    class Cipher
      # @param key [String] 32-byte master key
      def initialize(key)
        key = key.b
        raise ArgumentError, "key must be #{KEYBYTES} bytes (got #{key.bytesize})" unless key.bytesize == KEYBYTES

        @key = key
      end

      # Encrypt plaintext with the given 24-byte nonce.
      #
      # @param nonce [String] 24-byte nonce
      # @param plaintext [String]
      # @param aad [String] associated data (authenticated but not encrypted)
      # @return [String] ciphertext || 32-byte tag
      #
      def encrypt(nonce, plaintext, aad: "")
        enc_key, auth_key, enc_nonce = derive_subkeys(nonce)
        ct  = Internals::Chacha20.xor(enc_key, enc_nonce, plaintext)
        tag = compute_tag(auth_key, aad, ct)
        ct + tag
      end

      # Decrypt a ciphertext||tag blob with the given 24-byte nonce.
      #
      # @param nonce [String] 24-byte nonce
      # @param ciphertext [String] ciphertext || 32-byte tag
      # @param aad [String]
      # @return [String] plaintext
      # @raise [CryptoError] on authentication failure
      #
      def decrypt(nonce, ciphertext, aad: "")
        ciphertext = ciphertext.b
        raise CryptoError, "ciphertext too short" if ciphertext.bytesize < TAGBYTES

        tag = ciphertext.byteslice(ciphertext.bytesize - TAGBYTES, TAGBYTES)
        ct  = ciphertext.byteslice(0, ciphertext.bytesize - TAGBYTES)
        decrypt_detached(nonce, ct, tag, aad: aad)
      end

      # Encrypt, returning ciphertext and tag separately.
      #
      # @return [Array(String, String)] [ciphertext, tag]
      def encrypt_detached(nonce, plaintext, aad: "")
        enc_key, auth_key, enc_nonce = derive_subkeys(nonce)
        ct  = Internals::Chacha20.xor(enc_key, enc_nonce, plaintext)
        tag = compute_tag(auth_key, aad, ct)
        [ct, tag]
      end

      # Decrypt from a detached ciphertext + tag.
      #
      # @raise [CryptoError] on authentication failure
      def decrypt_detached(nonce, ciphertext, tag, aad: "")
        tag = tag.b
        raise ArgumentError, "tag must be #{TAGBYTES} bytes" unless tag.bytesize == TAGBYTES

        ciphertext = ciphertext.b
        enc_key, auth_key, enc_nonce = derive_subkeys(nonce)
        expected = compute_tag(auth_key, aad, ciphertext)
        raise CryptoError, "decryption failed" unless Util.verify32(tag, expected)

        Internals::Chacha20.xor(enc_key, enc_nonce, ciphertext)
      end

      private

      def derive_subkeys(nonce)
        nonce = nonce.b
        raise ArgumentError, "nonce must be #{NONCEBYTES} bytes" unless nonce.bytesize == NONCEBYTES

        kdf = Internals::Blake3.new_keyed(@key).update(nonce).finalize_xof.read(72)
        [kdf.byteslice(0, 32), kdf.byteslice(32, 32), kdf.byteslice(64, 8)]
      end

      def compute_tag(auth_key, aad, ct)
        aad = aad.b
        Internals::Blake3.new_keyed(auth_key).
          update(aad).
          update([aad.bytesize].pack("Q<")).
          update(ct).
          update([ct.bytesize].pack("Q<")).
          finalize(TAGBYTES)
      end
    end
  end
end
