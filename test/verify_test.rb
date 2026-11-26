# frozen_string_literal: true

require_relative "test_helper"

describe "Nuckle::Util.verify" do
  it "does not use String#==, which stops at the first differing byte" do
    a    = "\x01".b * 32
    b    = "\x01".b * 32
    used = false
    [a, b].each do |s|
      s.define_singleton_method(:==) do |other|
        used = true
        super(other)
      end
    end

    assert Nuckle::Util.verify32(a, b)
    refute used, "String#== was called"
  end


  it "finds a difference at any byte position" do
    [16, 32, 64].each do |n|
      a = Nuckle::Random.random_bytes(n)
      assert Nuckle::Util.verify(a, a.dup, n)
      n.times do |i|
        b = a.dup
        b.setbyte(i, b.getbyte(i) ^ 0x80)
        refute Nuckle::Util.verify(a, b, n), "size #{n}, byte #{i}"
      end
    end
  end


  it "returns false for unequal or unexpected sizes" do
    refute Nuckle::Util.verify("ab", "abc")
    refute Nuckle::Util.verify16("a" * 16, "a" * 17)
    refute Nuckle::Util.verify32("a" * 31, "a" * 31)
    assert Nuckle::Util.verify("", "")
  end


  it "compares bytes, not encodings" do
    assert Nuckle::Util.verify32("é" * 16, ("é" * 16).b)
  end


  it "backs PublicKey#==" do
    pk = Nuckle::PrivateKey.generate.public_key
    assert_equal pk, Nuckle::PublicKey.new(pk.to_s.dup)
    refute_equal pk, Nuckle::PrivateKey.generate.public_key
  end
end
