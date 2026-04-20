# frozen_string_literal: true

require_relative "test_helper"

class Chacha20Blake3Test < Minitest::Test
  C = Nuckle::Chacha20Blake3

  def hex(s)
    [s].pack("H*")
  end

  def test_constants
    assert_equal 32, C::KEYBYTES
    assert_equal 24, C::NONCEBYTES
    assert_equal 32, C::TAGBYTES
  end

  # --- Upstream test vectors --------------------------------------------------
  # From https://github.com/skerkour/chacha20-blake3
  # chacha20-blake3/tests/mod.rs @ rev 9942bf3

  def test_vector_1_empty_plaintext
    key   = hex("0000000000000000000000000000000000000000000000000000000000000000")
    nonce = hex("000000000000000000000000000000000000000000000000")
    aad   = ""
    expected_ct = hex("4fbdd67d41f66924b4304f0fc1eaa87a8e90fc7c5304fe3078f0a1b6e6142c33")
    assert_equal expected_ct, C::Cipher.new(key).encrypt(nonce, "", aad: aad)
  end

  def test_vector_2_chacha20_plaintext
    key   = hex("0100000000000000000000000000000000000000000000000000000000000010")
    nonce = hex("100000000000000000000000000000000000000000000001")
    aad   = "BLAKE3"
    expected_ct = hex("48fecfaf8d9553bfe7121700da72362e77e09080ddd55101aaca18cdcf259953923150cb89e1fef2")
    assert_equal expected_ct, C::Cipher.new(key).encrypt(nonce, "ChaCha20", aad: aad)
  end

  def test_vector_3_32_byte_plaintext
    key   = hex("3eb02a239a2a66de159b9bb5486ccc10a6f63ddf5862ef076650513372353622")
    nonce = hex("768e9bda14afb5686cc34de26210f9ff6fa1dfadc64ee3f0")
    pt    = hex("b8f60975cd7057a003ac84df00d514624fe40cb7855c50dd6594f59b3a2580e5")
    aad   = hex("c8d69ca92da6c5fd22f1805179fcd36cb7a9d45848fa346ba7118c2f34d23a48")
    expected_ct = hex(
      "444d593bb2dea9ecde9cd3839d166141de70481340ce30739b3f0f28b059d63232324ace49e8a19729ac5110a093fba10acaeed93099dea1a9c20463a278c3a7",
    )
    assert_equal expected_ct, C::Cipher.new(key).encrypt(nonce, pt, aad: aad)
  end

  # --- Roundtrip / API behavior -----------------------------------------------

  def test_roundtrip
    key   = "k" * 32
    nonce = "n" * 24
    pt    = "attack at dawn"
    ct    = C::Cipher.new(key).encrypt(nonce, pt)
    assert_equal pt.b, C::Cipher.new(key).decrypt(nonce, ct)
  end

  def test_roundtrip_with_aad
    key   = "k" * 32
    nonce = "n" * 24
    ct    = C::Cipher.new(key).encrypt(nonce, "secret", aad: "context-v1")
    assert_equal "secret".b, C::Cipher.new(key).decrypt(nonce, ct, aad: "context-v1")
  end

  def test_roundtrip_empty_plaintext
    key    = "k" * 32
    nonce  = "n" * 24
    ct     = C::Cipher.new(key).encrypt(nonce, "")
    assert_equal 32, ct.bytesize # only the tag
    assert_equal "".b, C::Cipher.new(key).decrypt(nonce, ct)
  end

  def test_roundtrip_crosses_blake3_chunk_boundary
    key    = "k" * 32
    nonce  = "n" * 24
    pt     = "A" * 2500 # > 2 BLAKE3 chunks
    ct     = C::Cipher.new(key).encrypt(nonce, pt)
    assert_equal pt.b, C::Cipher.new(key).decrypt(nonce, ct)
  end

  def test_tampering_ciphertext_fails
    cipher = C::Cipher.new("k" * 32)
    nonce  = "n" * 24
    ct     = cipher.encrypt(nonce, "hello world")
    ct.setbyte(0, ct.getbyte(0) ^ 0x01)
    assert_raises(Nuckle::CryptoError) { cipher.decrypt(nonce, ct) }
  end

  def test_tampering_tag_fails
    cipher = C::Cipher.new("k" * 32)
    nonce  = "n" * 24
    ct     = cipher.encrypt(nonce, "hello world")
    ct.setbyte(ct.bytesize - 1, ct.getbyte(ct.bytesize - 1) ^ 0x01)
    assert_raises(Nuckle::CryptoError) { cipher.decrypt(nonce, ct) }
  end

  def test_wrong_aad_fails
    cipher = C::Cipher.new("k" * 32)
    nonce  = "n" * 24
    ct     = cipher.encrypt(nonce, "hello", aad: "v1")
    assert_raises(Nuckle::CryptoError) { cipher.decrypt(nonce, ct, aad: "v2") }
  end

  def test_wrong_key_fails
    nonce = "n" * 24
    ct    = C::Cipher.new("k" * 32).encrypt(nonce, "hello")
    assert_raises(Nuckle::CryptoError) { C::Cipher.new("K" * 32).decrypt(nonce, ct) }
  end

  def test_short_ciphertext_fails
    assert_raises(Nuckle::CryptoError) do
      C::Cipher.new("k" * 32).decrypt("n" * 24, "short")
    end
  end

  def test_detached_api
    cipher = C::Cipher.new("k" * 32)
    nonce  = "n" * 24
    ct, tag = cipher.encrypt_detached(nonce, "payload", aad: "aad")
    assert_equal 32, tag.bytesize
    assert_equal 7, ct.bytesize
    assert_equal "payload".b, cipher.decrypt_detached(nonce, ct, tag, aad: "aad")
  end

  def test_invalid_key_size
    assert_raises(ArgumentError) { C::Cipher.new("short") }
  end

  def test_invalid_nonce_size
    cipher = C::Cipher.new("k" * 32)
    assert_raises(ArgumentError) { cipher.encrypt("short", "data") }
  end

  # --- Cross-validation against the Rust-backed sibling gem -------------------

  if HAVE_CHACHA20BLAKE3
    def test_cross_validate_encrypt_ours_decrypt_theirs
      [0, 1, 63, 64, 65, 100, 1024, 2500].each do |pt_len|
        key   = ("\x11" * 32).b
        nonce = ("\x22" * 24).b
        pt    = ("x" * pt_len).b
        aad   = "aad-#{pt_len}"
        ct    = C::Cipher.new(key).encrypt(nonce, pt, aad: aad)
        # Theirs should decrypt ours cleanly
        assert_equal pt, ::ChaCha20Blake3::Cipher.new(key).decrypt(nonce, ct, aad: aad),
                     "ours→theirs failed at pt_len=#{pt_len}"
      end
    end

    def test_cross_validate_encrypt_theirs_decrypt_ours
      [0, 1, 63, 64, 65, 100, 1024, 2500].each do |pt_len|
        key   = ("\x33" * 32).b
        nonce = ("\x44" * 24).b
        pt    = ("y" * pt_len).b
        aad   = "aad-#{pt_len}"
        ct    = ::ChaCha20Blake3::Cipher.new(key).encrypt(nonce, pt, aad: aad)
        assert_equal pt, C::Cipher.new(key).decrypt(nonce, ct, aad: aad),
                     "theirs→ours failed at pt_len=#{pt_len}"
      end
    end

    def test_cross_validate_random_inputs
      10.times do |i|
        key   = Random.bytes(32)
        nonce = Random.bytes(24)
        pt    = Random.bytes(rand(0..3000))
        aad   = Random.bytes(rand(0..64))
        ct_ours   = C::Cipher.new(key).encrypt(nonce, pt, aad: aad)
        ct_theirs = ::ChaCha20Blake3::Cipher.new(key).encrypt(nonce, pt, aad: aad)
        assert_equal ct_theirs, ct_ours, "ciphertext mismatch on iteration #{i}"
      end
    end
  end
end
