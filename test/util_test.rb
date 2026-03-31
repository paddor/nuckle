# frozen_string_literal: true

require_relative "test_helper"

class UtilTest < Minitest::Test
  def test_verify32_equal
    a = Nuckle::Random.random_bytes(32)
    assert Nuckle::Util.verify32(a, a.dup)
  end

  def test_verify32_different
    a = Nuckle::Random.random_bytes(32)
    b = Nuckle::Random.random_bytes(32)
    refute Nuckle::Util.verify32(a, b)
  end

  def test_verify32_wrong_size
    refute Nuckle::Util.verify32("short", "short")
  end

  def test_verify64_equal
    a = Nuckle::Random.random_bytes(64)
    assert Nuckle::Util.verify64(a, a.dup)
  end

  def test_verify64_different
    a = Nuckle::Random.random_bytes(64)
    b = Nuckle::Random.random_bytes(64)
    refute Nuckle::Util.verify64(a, b)
  end

  def test_verify16_equal
    a = Nuckle::Random.random_bytes(16)
    assert Nuckle::Util.verify16(a, a.dup)
  end

  def test_verify_arbitrary_size
    a = "hello".b
    assert Nuckle::Util.verify(a, "hello".b)
    refute Nuckle::Util.verify(a, "world".b)
    refute Nuckle::Util.verify(a, "hi".b)
  end
end
