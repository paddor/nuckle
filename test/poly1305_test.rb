# frozen_string_literal: true

require_relative "test_helper"

class Poly1305Test < Minitest::Test
  P = Nuckle::Internals::Poly1305

  def hex(s)    = [s.delete(" ")].pack("H*")
  def to_hex(s) = s.unpack1("H*")

  # RFC 8439 Section 2.5.2 test vector
  def test_rfc8439_vector
    key = hex(
      "85d6be7857556d337f4452fe42d506a8" \
      "0103808afb0db2fd4abff6af4149f51b"
    )
    message = "Cryptographic Forum Research Group".b
    expected = hex("a8061dc1305136c6c22b8baf0c0127a9")

    tag = P.mac(key, message)
    assert_equal expected, tag
  end

  # Empty message
  def test_empty_message
    key = hex(
      "00000000000000000000000000000000" \
      "00000000000000000000000000000000"
    )
    tag = P.mac(key, "".b)
    assert_equal 16, tag.bytesize
    # With zero key, tag should be zero
    assert_equal "\x00" * 16, tag
  end

  # Cross-validate with rbnacl OneTimeAuth if available
  def test_cross_validation
    skip "rbnacl not available" unless HAVE_RBNACL

    key     = Nuckle::Random.random_bytes(32)
    message = "Hello Poly1305!".b

    nuckle_tag = P.mac(key, message)

    rbnacl_auth = RbNaCl::OneTimeAuth.new(key)
    rbnacl_tag  = rbnacl_auth.auth(message)

    assert_equal rbnacl_tag, nuckle_tag
  end

  # Multi-block message (> 16 bytes)
  def test_multiblock
    key     = Nuckle::Random.random_bytes(32)
    message = Nuckle::Random.random_bytes(256)

    tag = P.mac(key, message)
    assert_equal 16, tag.bytesize

    # Same key + message → same tag
    tag2 = P.mac(key, message)
    assert_equal tag, tag2
  end
end
