# frozen_string_literal: true

require_relative "test_helper"

class BoxTest < Minitest::Test
  def hex(s)    = [s.delete(" ")].pack("H*")
  def to_hex(s) = s.unpack1("H*")

  # rbnacl test vectors (NaCl distribution)
  ALICE_PRIVATE  = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
  ALICE_PUBLIC   = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
  BOB_PRIVATE    = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
  BOB_PUBLIC     = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
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
    box = Nuckle::Box.new(hex(ALICE_PUBLIC), hex(BOB_PRIVATE))
    ct  = box.encrypt(hex(BOX_NONCE), hex(BOX_MESSAGE))
    assert_equal hex(BOX_CIPHERTEXT), ct
  end

  def test_decrypt_nacl_vector
    box = Nuckle::Box.new(hex(ALICE_PUBLIC), hex(BOB_PRIVATE))
    pt  = box.decrypt(hex(BOX_NONCE), hex(BOX_CIPHERTEXT))
    assert_equal hex(BOX_MESSAGE), pt
  end

  def test_roundtrip_with_key_objects
    alice = Nuckle::PrivateKey.generate
    bob   = Nuckle::PrivateKey.generate
    nonce = Nuckle::Random.random_bytes(24)
    msg   = "Hello from Alice!".b

    alice_box = Nuckle::Box.new(bob.public_key, alice)
    bob_box   = Nuckle::Box.new(alice.public_key, bob)

    ct = alice_box.encrypt(nonce, msg)
    pt = bob_box.decrypt(nonce, ct)
    assert_equal msg, pt
  end

  def test_tampered_ciphertext_raises
    alice = Nuckle::PrivateKey.generate
    bob   = Nuckle::PrivateKey.generate
    nonce = Nuckle::Random.random_bytes(24)

    box = Nuckle::Box.new(bob.public_key, alice)
    ct  = box.encrypt(nonce, "tamper me".b)

    tampered = ct.dup
    tampered.setbyte(20, tampered.getbyte(20) ^ 0xFF)

    box2 = Nuckle::Box.new(alice.public_key, bob)
    assert_raises(Nuckle::CryptoError) { box2.decrypt(nonce, tampered) }
  end

  def test_cross_validation
    skip "rbnacl not available" unless HAVE_RBNACL

    nonce = Nuckle::Random.random_bytes(24)
    msg   = "cross-validate Box".b

    alice_pk = hex(ALICE_PUBLIC)
    bob_sk   = hex(BOB_PRIVATE)

    nuckle_ct = Nuckle::Box.new(alice_pk, bob_sk).encrypt(nonce, msg)
    rbnacl_ct = RbNaCl::Box.new(
      RbNaCl::PublicKey.new(alice_pk),
      RbNaCl::PrivateKey.new(bob_sk)
    ).encrypt(nonce, msg)

    assert_equal rbnacl_ct, nuckle_ct

    # Cross-decrypt
    pt1 = RbNaCl::Box.new(
      RbNaCl::PublicKey.new(alice_pk),
      RbNaCl::PrivateKey.new(bob_sk)
    ).decrypt(nonce, nuckle_ct)
    pt2 = Nuckle::Box.new(alice_pk, bob_sk).decrypt(nonce, rbnacl_ct)
    assert_equal msg, pt1
    assert_equal msg, pt2
  end
end
