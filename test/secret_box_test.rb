# frozen_string_literal: true

require_relative "test_helper"

class SecretBoxTest < Minitest::Test
  def hex(s)    = [s.delete(" ")].pack("H*")
  def to_hex(s) = s.unpack1("H*")

  # rbnacl test vectors (from NaCl distribution)
  SECRET_KEY     = "1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389"
  BOX_NONCE      = "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37"
  BOX_MESSAGE    = "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffc" \
                   "e5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb31" \
                   "0e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde" \
                   "048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f93776384864" \
                   "5e0705"
  BOX_CIPHERTEXT = "f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce" \
                   "48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c972" \
                   "71d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae" \
                   "90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b3" \
                   "7973f622a43d14a6599b1f654cb45a74e355a5"

  def test_encrypt_nacl_vector
    box = Nuckle::SecretBox.new(hex(SECRET_KEY))
    ct  = box.encrypt(hex(BOX_NONCE), hex(BOX_MESSAGE))
    assert_equal hex(BOX_CIPHERTEXT), ct
  end

  def test_decrypt_nacl_vector
    box = Nuckle::SecretBox.new(hex(SECRET_KEY))
    pt  = box.decrypt(hex(BOX_NONCE), hex(BOX_CIPHERTEXT))
    assert_equal hex(BOX_MESSAGE), pt
  end

  def test_roundtrip
    key   = Nuckle::Random.random_bytes(32)
    nonce = Nuckle::Random.random_bytes(24)
    msg   = "Hello, SecretBox!".b

    box = Nuckle::SecretBox.new(key)
    ct  = box.encrypt(nonce, msg)
    pt  = box.decrypt(nonce, ct)
    assert_equal msg, pt
  end

  def test_tampered_ciphertext_raises
    key   = Nuckle::Random.random_bytes(32)
    nonce = Nuckle::Random.random_bytes(24)
    msg   = "tamper me".b

    box = Nuckle::SecretBox.new(key)
    ct  = box.encrypt(nonce, msg)

    # Flip a byte in the ciphertext (after the 16-byte MAC)
    tampered = ct.dup
    tampered.setbyte(20, tampered.getbyte(20) ^ 0xFF)

    assert_raises(Nuckle::CryptoError) { box.decrypt(nonce, tampered) }
  end

  def test_wrong_key_raises
    key1  = Nuckle::Random.random_bytes(32)
    key2  = Nuckle::Random.random_bytes(32)
    nonce = Nuckle::Random.random_bytes(24)
    msg   = "wrong key".b

    ct = Nuckle::SecretBox.new(key1).encrypt(nonce, msg)
    assert_raises(Nuckle::CryptoError) { Nuckle::SecretBox.new(key2).decrypt(nonce, ct) }
  end

  def test_empty_plaintext
    key   = Nuckle::Random.random_bytes(32)
    nonce = Nuckle::Random.random_bytes(24)

    box = Nuckle::SecretBox.new(key)
    ct  = box.encrypt(nonce, "".b)
    assert_equal 16, ct.bytesize  # just the MAC
    pt = box.decrypt(nonce, ct)
    assert_equal "".b, pt
  end

  def test_cross_validation
    skip "rbnacl not available" unless HAVE_RBNACL

    key   = Nuckle::Random.random_bytes(32)
    nonce = Nuckle::Random.random_bytes(24)
    msg   = "cross-validate SecretBox".b

    nuckle_ct = Nuckle::SecretBox.new(key).encrypt(nonce, msg)
    rbnacl_ct = RbNaCl::SecretBox.new(key).encrypt(nonce, msg)
    assert_equal rbnacl_ct, nuckle_ct

    # Cross-decrypt
    pt1 = RbNaCl::SecretBox.new(key).decrypt(nonce, nuckle_ct)
    pt2 = Nuckle::SecretBox.new(key).decrypt(nonce, rbnacl_ct)
    assert_equal msg, pt1
    assert_equal msg, pt2
  end
end
