# frozen_string_literal: true

require_relative "test_helper"

class KeyTest < Minitest::Test
  def hex(s) = [s.delete(" ")].pack("H*")

  def test_private_key_generate
    sk = Nuckle::PrivateKey.generate
    assert_equal 32, sk.to_s.bytesize
  end

  def test_private_key_from_bytes
    bytes = Nuckle::Random.random_bytes(32)
    sk    = Nuckle::PrivateKey.new(bytes)
    assert_equal bytes, sk.to_s
  end

  def test_public_key_derivation
    sk = Nuckle::PrivateKey.new(hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
    pk = sk.public_key
    assert_equal hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"), pk.to_s
  end

  def test_public_key_from_bytes
    bytes = Nuckle::Random.random_bytes(32)
    pk    = Nuckle::PublicKey.new(bytes)
    assert_equal bytes, pk.to_s
  end

  def test_wrong_key_length_raises
    assert_raises(ArgumentError) { Nuckle::PrivateKey.new("short") }
    assert_raises(ArgumentError) { Nuckle::PublicKey.new("short") }
  end

  def test_cross_validation
    skip "rbnacl not available" unless HAVE_RBNACL

    sk_bytes = Nuckle::Random.random_bytes(32)

    nuckle_pk = Nuckle::PrivateKey.new(sk_bytes).public_key.to_s
    rbnacl_pk = RbNaCl::PrivateKey.new(sk_bytes).public_key.to_s

    assert_equal rbnacl_pk, nuckle_pk
  end
end
