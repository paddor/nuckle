# frozen_string_literal: true

require_relative "test_helper"

class Chacha20Test < Minitest::Test
  # Mirror of RFC 8439 § 2.3.2, mapped to the 8-byte-nonce variant:
  #   RFC state[12] (u32 counter)           = 1
  #   RFC state[13] (nonce[0..4] LE u32)    = high 32 bits of 64-bit counter
  #   RFC state[14..15] (nonce[4..12])      = 8-byte nonce
  def test_block_rfc8439_vector
    key = [
      "000102030405060708090a0b0c0d0e0f" \
      "101112131415161718191a1b1c1d1e1f",
    ].pack("H*")

    # RFC 12-byte nonce = 00:00:00:09:00:00:00:4a:00:00:00:00
    # counter = (0x09000000 << 32) | 1
    counter = (0x09000000 << 32) | 1
    nonce   = ["000000" "4a" "000000" "00"].pack("H*") # "\x00\x00\x00\x4a\x00\x00\x00\x00"

    expected = [
      "10f1e7e4d13b5915500fdd1fa32071c4" \
      "c7d1f4c733c068030422aa9ac3d46c4e" \
      "d2826446079faa0914c2d705d98b02a2" \
      "b5129cd1de164eb9cbd083e8a2503c4e",
    ].pack("H*")

    assert_equal expected, Nuckle::Internals::Chacha20.block(key, nonce, counter)
  end

  def test_xor_roundtrip
    key     = "\x11".b * 32
    nonce   = "\x22".b * 8
    message = "The quick brown fox jumps over the lazy dog." * 4 # 176 bytes, crosses blocks

    ct = Nuckle::Internals::Chacha20.xor(key, nonce, message)
    refute_equal message.b, ct
    assert_equal message.b, Nuckle::Internals::Chacha20.xor(key, nonce, ct)
  end

  def test_xor_deterministic
    key   = "\x33".b * 32
    nonce = "\x44".b * 8
    msg   = "hello world"
    assert_equal Nuckle::Internals::Chacha20.xor(key, nonce, msg),
                 Nuckle::Internals::Chacha20.xor(key, nonce, msg)
  end

  def test_stream_equals_xor_with_zeros
    key    = "\x55".b * 32
    nonce  = "\x66".b * 8
    length = 200
    ks     = Nuckle::Internals::Chacha20.stream(key, nonce, length)
    assert_equal length, ks.bytesize
    assert_equal Nuckle::Internals::Chacha20.xor(key, nonce, "\x00".b * length), ks
  end

  def test_counter_advances_per_block
    key   = "\x77".b * 32
    nonce = "\x88".b * 8
    # Two single-block calls should match one two-block call if counters align.
    b0 = Nuckle::Internals::Chacha20.block(key, nonce, 0)
    b1 = Nuckle::Internals::Chacha20.block(key, nonce, 1)
    ks = Nuckle::Internals::Chacha20.stream(key, nonce, 128)
    assert_equal (b0 + b1), ks
  end

  def test_empty_message
    ks = Nuckle::Internals::Chacha20.xor("\x00".b * 32, "\x00".b * 8, "")
    assert_equal "".b, ks
    assert_equal Encoding::BINARY, ks.encoding
  end

  def test_partial_last_block
    key   = "\x99".b * 32
    nonce = "\xaa".b * 8
    msg   = "x" * 100 # 1 full block + 36-byte tail
    ct    = Nuckle::Internals::Chacha20.xor(key, nonce, msg)
    assert_equal 100, ct.bytesize
    assert_equal msg.b, Nuckle::Internals::Chacha20.xor(key, nonce, ct)
  end

  def test_non_zero_initial_counter
    key   = "\xbb".b * 32
    nonce = "\xcc".b * 8
    full  = Nuckle::Internals::Chacha20.stream(key, nonce, 192) # counters 0,1,2
    tail  = Nuckle::Internals::Chacha20.stream(key, nonce, 128, 1)
    assert_equal full.byteslice(64, 128), tail
  end
end
