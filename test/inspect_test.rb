# frozen_string_literal: true

require_relative "test_helper"
require "pp"

describe "#inspect on objects that hold secrets" do
  let(:key) { "s3cr3t-k3y-".ljust(32, "x").b }


  def assert_hides_key(obj, key)
    [obj.inspect, obj.pretty_inspect].each do |text|
      refute_includes text, key.byteslice(0, 6)
      refute_includes text, key.unpack1("H*").byteslice(0, 8)
      refute_includes text, key.inspect[1, 12]
    end
  end


  it "hides a PrivateKey" do
    assert_hides_key Nuckle::PrivateKey.new(key), key
  end


  it "hides a SecretBox key" do
    assert_hides_key Nuckle::SecretBox.new(key), key
  end


  it "hides a Box shared key" do
    box    = Nuckle::Box.new(Nuckle::PrivateKey.generate.public_key, Nuckle::PrivateKey.new(key))
    shared = box.instance_variable_get(:@secret_box).instance_variable_get(:@key)
    assert_hides_key box, shared
  end


  it "hides a Chacha20Blake3::Cipher key" do
    assert_hides_key Nuckle::Chacha20Blake3::Cipher.new(key), key
  end


  it "names the class" do
    assert_match(/Nuckle::PrivateKey/, Nuckle::PrivateKey.new(key).inspect)
    assert_match(/Nuckle::SecretBox/, Nuckle::SecretBox.new(key).inspect)
  end
end
