# frozen_string_literal: true

require_relative "test_helper"

describe "argument and key buffer mutation" do
  describe "key bytes" do
    [Nuckle::PrivateKey, Nuckle::PublicKey].each do |klass|
      it "#{klass}#to_s and #to_bytes cannot change the key" do
        key = klass.new("\x33".b * 32)
        assert_predicate key.to_s, :frozen?
        assert_predicate key.to_bytes, :frozen?
        assert_raises(FrozenError) { key.to_s.setbyte(0, 0) }
        assert_equal "\x33".b * 32, key.to_s
      end


      it "#{klass}.new copies the caller's buffer" do
        buf = "\x33".b * 32
        key = klass.new(buf)
        buf.setbyte(0, 0)
        assert_equal "\x33".b * 32, key.to_s
      end
    end
  end


  describe "inputs" do
    def snapshot(*args)
      args.map { |a| [a.dup, a.encoding] }
    end


    it "leaves Box and SecretBox arguments as they were" do
      sk    = "\x44".b * 32
      pk    = Nuckle::PrivateKey.generate.public_key.to_s.dup
      nonce = "\x55".b * 24
      msg   = +"héllo"
      args  = [sk, pk, nonce, msg]
      before = snapshot(*args)

      box = Nuckle::Box.new(pk, sk)
      box.decrypt(nonce, box.encrypt(nonce, msg))
      sbox = Nuckle::SecretBox.new(sk)
      sbox.decrypt(nonce, sbox.encrypt(nonce, msg))
      Nuckle::PrivateKey.new(sk).diffie_hellman(pk)

      assert_equal before, snapshot(*args)
    end


    it "leaves ChaCha20-BLAKE3 and BLAKE3 arguments as they were" do
      key   = "\x66".b * 32
      nonce = "\x77".b * 24
      msg   = +"héllo"
      aad   = +"äad"
      args  = [key, nonce, msg, aad]
      before = snapshot(*args)

      c = Nuckle::Chacha20Blake3::Cipher.new(key)
      c.decrypt(nonce, c.encrypt(nonce, msg, aad: aad), aad: aad)
      ct, tag = c.encrypt_detached(nonce, msg, aad: aad)
      c.decrypt_detached(nonce, ct, tag, aad: aad)
      Nuckle::Internals::Blake3.keyed_hash(key, msg)
      Nuckle::Internals::Blake3.derive_key(aad, msg)

      assert_equal before, snapshot(*args)
    end


    it "accepts frozen arguments" do
      key   = ("\x11".b * 32).freeze
      nonce = ("\x22".b * 24).freeze
      msg   = "hi".freeze
      sbox  = Nuckle::SecretBox.new(key)
      assert_equal msg.b, sbox.decrypt(nonce, sbox.encrypt(nonce, msg).freeze)
      c = Nuckle::Chacha20Blake3::Cipher.new(key)
      assert_equal msg.b, c.decrypt(nonce, c.encrypt(nonce, msg, aad: "a".freeze).freeze, aad: "a".freeze)
    end
  end
end
