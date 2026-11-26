# frozen_string_literal: true

require_relative "test_helper"

# X25519 public keys of small order. Each one makes the shared secret all
# zero for every clamped scalar. libsodium lists the first seven (top bit
# clear); the rest are the same points with the top bit set, which X25519
# masks off.
LOW_ORDER_PUBLIC_KEYS = %w[
  0000000000000000000000000000000000000000000000000000000000000000
  0100000000000000000000000000000000000000000000000000000000000000
  e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800
  5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157
  ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f
  edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f
  eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f
  0000000000000000000000000000000000000000000000000000000000000080
  0100000000000000000000000000000000000000000000000000000000000080
  e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880
  5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7
  ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
  edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
  eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
].map { |hex| [hex].pack("H*").freeze }.freeze


describe "low-order public keys" do
  before do
    @sk = Nuckle::PrivateKey.generate
  end


  it "makes the raw X25519 output all zero" do
    LOW_ORDER_PUBLIC_KEYS.each do |pk|
      assert_equal "\x00".b * 32, Nuckle::Internals::Curve25519.scalarmult(@sk.to_s, pk)
    end
  end


  it "makes PrivateKey#diffie_hellman raise CryptoError" do
    LOW_ORDER_PUBLIC_KEYS.each do |pk|
      assert_raises(Nuckle::CryptoError, pk.unpack1("H*")) { @sk.diffie_hellman(pk) }
      assert_raises(Nuckle::CryptoError, pk.unpack1("H*")) { @sk.diffie_hellman(Nuckle::PublicKey.new(pk)) }
    end
  end


  it "makes Box.new raise CryptoError" do
    LOW_ORDER_PUBLIC_KEYS.each do |pk|
      assert_raises(Nuckle::CryptoError, pk.unpack1("H*")) { Nuckle::Box.new(pk, @sk) }
      assert_raises(Nuckle::CryptoError, pk.unpack1("H*")) { Nuckle::Box.new(Nuckle::PublicKey.new(pk), @sk.to_s) }
    end
  end


  it "matches RbNaCl, which raises CryptoError on first use" do
    skip "rbnacl not available" unless HAVE_RBNACL

    nonce = "\x00".b * 24
    LOW_ORDER_PUBLIC_KEYS.each do |pk|
      assert_raises(RbNaCl::CryptoError) { RbNaCl::Box.new(pk, @sk.to_s).encrypt(nonce, "x") }
      assert_raises(RbNaCl::CryptoError) { RbNaCl::GroupElement.new(pk).mult(@sk.to_s) }
    end
  end


  it "still accepts ordinary public keys" do
    peer = Nuckle::PrivateKey.generate
    assert_equal peer.diffie_hellman(@sk.public_key), @sk.diffie_hellman(peer.public_key)
    Nuckle::Box.new(peer.public_key, @sk)
  end
end


describe Nuckle::Util do
  describe ".zero?" do
    it "is true only for all-zero strings" do
      assert Nuckle::Util.zero?("")
      assert Nuckle::Util.zero?("\x00".b * 32)
      32.times do |i|
        s = "\x00".b * 32
        s.setbyte(i, 1 << (i % 8))
        refute Nuckle::Util.zero?(s), "byte #{i}"
      end
    end
  end
end
