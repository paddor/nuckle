# frozen_string_literal: true

require_relative "test_helper"

class Curve25519Test < Minitest::Test
  C = Nuckle::Internals::Curve25519

  def hex(s)    = [s.delete(" ")].pack("H*")
  def to_hex(s) = s.unpack1("H*")

  # RFC 7748 / rbnacl test vectors
  ALICE_PRIVATE = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
  ALICE_PUBLIC  = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
  BOB_PRIVATE   = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
  BOB_PUBLIC    = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
  SHARED_SECRET = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

  def test_alice_public_key_derivation
    pub = C.scalarmult_base(hex(ALICE_PRIVATE))
    assert_equal hex(ALICE_PUBLIC), pub
  end

  def test_bob_public_key_derivation
    pub = C.scalarmult_base(hex(BOB_PRIVATE))
    assert_equal hex(BOB_PUBLIC), pub
  end

  def test_shared_secret_alice_side
    shared = C.scalarmult(hex(ALICE_PRIVATE), hex(BOB_PUBLIC))
    assert_equal hex(SHARED_SECRET), shared
  end

  def test_shared_secret_bob_side
    shared = C.scalarmult(hex(BOB_PRIVATE), hex(ALICE_PUBLIC))
    assert_equal hex(SHARED_SECRET), shared
  end

  def test_shared_secrets_match
    alice_shared = C.scalarmult(hex(ALICE_PRIVATE), hex(BOB_PUBLIC))
    bob_shared   = C.scalarmult(hex(BOB_PRIVATE), hex(ALICE_PUBLIC))
    assert_equal alice_shared, bob_shared
  end

  # RFC 7748 Section 5.2: iterated scalar multiplication
  def test_rfc7748_iteration_1
    # After one iteration: k = X25519(k, u) where k=u=basepoint(9)
    k = hex("0900000000000000000000000000000000000000000000000000000000000000")
    u = hex("0900000000000000000000000000000000000000000000000000000000000000")

    result = C.scalarmult(k, u)
    expected = hex("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
    assert_equal expected, result
  end

  # Cross-validate with rbnacl
  def test_cross_validation
    skip "rbnacl not available" unless HAVE_RBNACL

    sk = Nuckle::Random.random_bytes(32)

    nuckle_pk = C.scalarmult_base(sk)
    rbnacl_pk = RbNaCl::PrivateKey.new(sk).public_key.to_s

    assert_equal rbnacl_pk, nuckle_pk
  end
end
