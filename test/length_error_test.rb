# frozen_string_literal: true

require_relative "test_helper"

describe "Nuckle::LengthError" do
  let(:k32) { "\x01".b * 32 }
  let(:n24) { "\x02".b * 24 }


  it "is an ArgumentError, like RbNaCl::LengthError" do
    assert_operator Nuckle::LengthError, :<, ArgumentError
    assert_operator RbNaCl::LengthError, :<, ArgumentError if HAVE_RBNACL
  end


  it "is raised for wrong-size keys" do
    assert_raises(Nuckle::LengthError) { Nuckle::PublicKey.new("x" * 31) }
    assert_raises(Nuckle::LengthError) { Nuckle::PrivateKey.new("x" * 33) }
    assert_raises(Nuckle::LengthError) { Nuckle::Box.new("x" * 31, k32) }
    assert_raises(Nuckle::LengthError) { Nuckle::Box.new(k32, "x" * 31) }
    assert_raises(Nuckle::LengthError) { Nuckle::PrivateKey.new(k32).diffie_hellman("x" * 31) }
    assert_raises(Nuckle::LengthError) { Nuckle::SecretBox.new("x" * 31) }
    assert_raises(Nuckle::LengthError) { Nuckle::Chacha20Blake3::Cipher.new("x" * 31) }
    assert_raises(Nuckle::LengthError) { Nuckle::Internals::Blake3.keyed_hash("x" * 31, "") }
  end


  it "is raised for wrong-size nonces and tags" do
    sbox = Nuckle::SecretBox.new(k32)
    assert_raises(Nuckle::LengthError) { sbox.encrypt("x" * 23, "m") }
    assert_raises(Nuckle::LengthError) { sbox.decrypt("x" * 25, "m" * 32) }

    box = Nuckle::Box.new(Nuckle::PrivateKey.generate.public_key, Nuckle::PrivateKey.generate)
    assert_raises(Nuckle::LengthError) { box.encrypt("x" * 23, "m") }
    assert_raises(Nuckle::LengthError) { box.decrypt("x" * 25, "m" * 32) }

    c = Nuckle::Chacha20Blake3::Cipher.new(k32)
    assert_raises(Nuckle::LengthError) { c.encrypt("x" * 12, "m") }
    assert_raises(Nuckle::LengthError) { c.decrypt("x" * 25, "m" * 40) }
    assert_raises(Nuckle::LengthError) { c.decrypt_detached(n24, "m", "t" * 31) }
  end


  it "is not raised for short ciphertexts, which are CryptoError as in RbNaCl" do
    assert_raises(Nuckle::CryptoError) { Nuckle::SecretBox.new(k32).decrypt(n24, "x" * 15) }
    assert_raises(Nuckle::CryptoError) { Nuckle::Chacha20Blake3::Cipher.new(k32).decrypt(n24, "x" * 31) }
  end
end
