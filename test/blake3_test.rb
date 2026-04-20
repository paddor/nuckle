# frozen_string_literal: true

require_relative "test_helper"

class Blake3Test < Minitest::Test
  B3 = Nuckle::Internals::Blake3

  # BLAKE3 test input: bytes[i] = i % 251, from the official spec.
  def make_input(n)
    (0...n).map { |i| (i % 251).chr }.join.b
  end

  def hex(x)
    x.unpack1("H*")
  end

  # Official hash-of-empty vector from the BLAKE3 spec.
  def test_hash_empty
    assert_equal "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
                 hex(B3.hash(""))
  end

  def test_hash_length_parameter
    # Truncated output at shorter lengths, extended via XOF at longer.
    assert_equal 32, B3.hash("hello").bytesize
    assert_equal 16, B3.hash("hello", 16).bytesize
    assert_equal 80, B3.hash("hello", 80).bytesize
    # The first 32 bytes of a longer hash must equal the default 32-byte hash.
    assert_equal B3.hash("hello"), B3.hash("hello", 80).byteslice(0, 32)
  end

  def test_streaming_equals_oneshot
    input = make_input(5000)
    oneshot   = B3.hash(input)
    streaming = B3.new_hasher.update(input.byteslice(0, 1)).
                              update(input.byteslice(1, 63)).
                              update(input.byteslice(64, 1024)).
                              update(input.byteslice(1088..)).
                              finalize
    assert_equal oneshot, streaming
  end

  def test_keyed_hash_size
    key = "a" * 32
    assert_equal 32, B3.keyed_hash(key, "data").bytesize
    assert_equal 64, B3.keyed_hash(key, "data", 64).bytesize
    assert_raises(ArgumentError) { B3.keyed_hash("short", "data") }
  end

  def test_derive_key_is_deterministic_and_context_separated
    ctx1 = "nuckle test context A"
    ctx2 = "nuckle test context B"
    material = "shared key material"

    k1a = B3.derive_key(ctx1, material)
    k1b = B3.derive_key(ctx1, material)
    k2  = B3.derive_key(ctx2, material)

    assert_equal k1a, k1b
    refute_equal k1a, k2
    assert_equal 32, k1a.bytesize
    assert_equal 64, B3.derive_key(ctx1, material, 64).bytesize
  end

  def test_xof_stream_equals_long_hash
    xof    = B3.new_hasher.update("xof test").finalize_xof
    pieces = Array.new(10) { xof.read(17) } # 170 bytes, odd chunk size
    oneshot = B3.hash("xof test", 170)
    assert_equal oneshot, pieces.join
  end

  def test_multi_chunk_boundaries
    # Inputs at exactly chunk / parent boundaries — exercises the tree code.
    [0, 1, 63, 64, 65, 1023, 1024, 1025, 2047, 2048, 2049, 3072, 3073, 5000].each do |n|
      input = make_input(n)
      assert_equal 32, B3.hash(input).bytesize, "at size=#{n}"
    end
  end

  if HAVE_BLAKE3
    # Cross-validate unkeyed hash against the blake3-rb gem (libblake3).
    def test_cross_validate_against_blake3_rb
      [0, 1, 3, 64, 100, 1023, 1024, 1025, 2048, 5000].each do |n|
        input = make_input(n)
        assert_equal Digest::Blake3.digest(input), B3.hash(input),
                     "mismatch at size=#{n}"
      end
    end

    def test_cross_validate_xof_against_blake3_rb
      # Digest::Blake3 doesn't expose XOF directly, so we compare the default
      # 32-byte digest against the first 32 bytes of our XOF output.
      [10, 100, 1000, 10_000].each do |n|
        input = make_input(n)
        xof_first_32 = B3.new_hasher.update(input).finalize_xof.read(32)
        assert_equal Digest::Blake3.digest(input), xof_first_32
      end
    end
  end
end
