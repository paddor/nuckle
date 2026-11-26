# frozen_string_literal: true

require_relative "test_helper"

describe Nuckle::Internals::Blake3 do
  let(:b3) { Nuckle::Internals::Blake3 }


  it "works as a Hash key and in #uniq" do
    assert_equal 1, { b3 => 1 }.size
    assert_equal 1, [b3, b3].uniq.size
    assert_kind_of Integer, b3.hash
    assert_equal b3.hash, b3.hash
  end


  it "still hashes input with .hash(input, length)" do
    assert_equal "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", b3.hash("").unpack1("H*")
    assert_equal 16, b3.hash("x", 16).bytesize
  end
end
