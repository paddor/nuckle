# frozen_string_literal: true

require_relative "test_helper"

describe "key argument types" do
  before do
    @sk = Nuckle::PrivateKey.generate
    @pk = Nuckle::PrivateKey.generate.public_key
  end


  describe Nuckle::Box do
    it "rejects swapped key objects" do
      assert_raises(TypeError) { Nuckle::Box.new(@sk, @pk) }
    end


    it "rejects a PublicKey as the private key" do
      assert_raises(TypeError) { Nuckle::Box.new(@pk, @pk) }
    end


    it "rejects a PrivateKey as the public key" do
      assert_raises(TypeError) { Nuckle::Box.new(@sk, @sk) }
    end


    it "rejects non-string arguments" do
      assert_raises(TypeError) { Nuckle::Box.new(nil, @sk) }
      assert_raises(TypeError) { Nuckle::Box.new(@pk, 42) }
    end


    it "accepts key objects and strings in the right places" do
      nonce = "\x00".b * 24
      ct    = Nuckle::Box.new(@pk, @sk).encrypt(nonce, "hi")
      assert_equal ct, Nuckle::Box.new(@pk.to_s, @sk.to_s).encrypt(nonce, "hi")
      assert_equal ct, Nuckle::Box.new(@pk, @sk.to_s).encrypt(nonce, "hi")
      assert_equal ct, Nuckle::Box.new(@pk.to_s, @sk).encrypt(nonce, "hi")
    end
  end


  describe Nuckle::PublicKey do
    it "rejects a PrivateKey" do
      assert_raises(TypeError) { Nuckle::PublicKey.new(@sk) }
    end


    it "rejects objects that only have #to_s" do
      assert_raises(TypeError) { Nuckle::PublicKey.new(("a" * 32).to_sym) }
      assert_raises(TypeError) { Nuckle::PublicKey.new(12345678901234567890123456789012) }
      assert_raises(TypeError) { Nuckle::PublicKey.new(nil) }
    end


    it "accepts a PublicKey and #to_str objects" do
      assert_equal @pk.to_s, Nuckle::PublicKey.new(@pk).to_s

      str = Object.new
      str.define_singleton_method(:to_str) { "\x09".b * 32 }
      assert_equal "\x09".b * 32, Nuckle::PublicKey.new(str).to_s
    end
  end


  describe Nuckle::PrivateKey do
    it "rejects a PublicKey" do
      assert_raises(TypeError) { Nuckle::PrivateKey.new(@pk) }
    end


    it "rejects objects that only have #to_s" do
      assert_raises(TypeError) { Nuckle::PrivateKey.new(12345678901234567890123456789012) }
      assert_raises(TypeError) { Nuckle::PrivateKey.new(nil) }
    end


    it "accepts a PrivateKey" do
      assert_equal @sk.to_s, Nuckle::PrivateKey.new(@sk).to_s
    end


    it "rejects a PrivateKey as the peer key in #diffie_hellman" do
      assert_raises(TypeError) { @sk.diffie_hellman(@sk) }
      assert_raises(TypeError) { @sk.diffie_hellman(nil) }
    end
  end
end
