# frozen_string_literal: true

require_relative "test_helper"
require "json"

describe "known-answer vectors" do
  def unhex(s)
    [s.delete(" \n")].pack("H*")
  end


  describe "X25519 (RFC 7748 section 5.2)" do
    let(:curve) { Nuckle::Internals::Curve25519 }


    it "matches both single-step vectors" do
      [
        %w[a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4
           e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c
           c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552],
        # The u-coordinate has its top bit set, which X25519 must mask off.
        %w[4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d
           e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493
           95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957],
      ].each do |k, u, out|
        assert_equal unhex(out), curve.scalarmult(unhex(k), unhex(u))
      end
    end


    it "matches the 1 and 1,000 iteration vectors" do
      k = u = unhex("09" + "00" * 31)
      1000.times do |i|
        k, u = curve.scalarmult(k, u), k
        assert_equal unhex("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"), k if i.zero?
      end
      assert_equal unhex("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"), k
    end


    it "reduces non-canonical u-coordinates and masks the top bit" do
      k = Nuckle::Random.random_bytes(32)
      prime = (1 << 255) - 19
      (0..18).each do |u|
        canonical = curve.encode_u(u)
        expected  = curve.scalarmult(k, canonical)
        noncanon  = curve.encode_u(u + prime)
        top_bit   = canonical.dup
        top_bit.setbyte(31, top_bit.getbyte(31) | 0x80)

        assert_equal expected, curve.scalarmult(k, noncanon), "u = #{u} + p"
        assert_equal expected, curve.scalarmult(k, top_bit), "u = #{u} with top bit"
        next unless HAVE_RBNACL && !Nuckle::Util.zero?(expected)

        assert_equal expected, RbNaCl::GroupElement.new(noncanon).mult(k), "u = #{u} + p vs RbNaCl"
      end
    end
  end


  describe "Poly1305 (RFC 8439 appendix A.3)" do
    let(:ietf) do
      "Any submission to the IETF intended by the Contributor for publication as all or part " \
        "of an IETF Internet-Draft or RFC and any statement made within the context of an IETF " \
        "activity is considered an \"IETF Contribution\". Such statements include oral statements " \
        "in IETF sessions, as well as written and electronic communications made at any time or " \
        "place, which are addressed to"
    end
    let(:jabberwocky) do
      "'Twas brillig, and the slithy toves\nDid gyre and gimble in the wabe:\n" \
        "All mimsy were the borogoves,\nAnd the mome raths outgrabe."
    end


    it "matches vectors #1 to #11" do
      vectors = [
        ["00" * 32, unhex("00" * 64), "00" * 16],
        ["00" * 16 + "36e5f6b5c5e06070f0efca96227a863e", ietf, "36e5f6b5c5e06070f0efca96227a863e"],
        ["36e5f6b5c5e06070f0efca96227a863e" + "00" * 16, ietf, "f3477e7cd95417af89a6b8794c310cf0"],
        ["1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0", jabberwocky,
         "4541669a7eaaee61e708dc7cbcc5eb62"],
        ["02" + "00" * 31, unhex("ff" * 16), "03" + "00" * 15],
        ["02" + "00" * 15 + "ff" * 16, unhex("02" + "00" * 15), "03" + "00" * 15],
        ["01" + "00" * 31, unhex("ff" * 16 + "f0" + "ff" * 15 + "11" + "00" * 15), "05" + "00" * 15],
        ["01" + "00" * 31, unhex("ff" * 16 + "fb" + "fe" * 15 + "01" * 16), "00" * 16],
        ["02" + "00" * 31, unhex("fd" + "ff" * 15), "fa" + "ff" * 15],
        ["01" + "00" * 7 + "04" + "00" * 23,
         unhex("e33594d7505e43b9" + "00" * 8 + "3394d7505e4379cd01" + "00" * 23 + "01" + "00" * 15),
         "14" + "00" * 7 + "55" + "00" * 7],
        ["01" + "00" * 7 + "04" + "00" * 23,
         unhex("e33594d7505e43b9" + "00" * 8 + "3394d7505e4379cd01" + "00" * 23),
         "13" + "00" * 15],
      ]
      assert_equal 375, ietf.bytesize
      assert_equal 127, jabberwocky.bytesize

      vectors.each.with_index(1) do |(key, msg, tag), n|
        assert_equal unhex(tag), Nuckle::Internals::Poly1305.mac(unhex(key), msg), "vector ##{n}"
      end
    end
  end


  describe "BLAKE3 (official test_vectors.json)" do
    let(:b3)      { Nuckle::Internals::Blake3 }
    let(:vectors) { JSON.parse(File.read(File.join(__dir__, "vectors", "blake3_test_vectors.json"))) }


    def input(len)
      Array.new(len) { |i| i % 251 }.pack("C*")
    end


    it "matches hash, keyed_hash and derive_key with extended output" do
      key = vectors["key"]
      ctx = vectors["context_string"]
      vectors["cases"].each do |c|
        msg = input(c["input_len"])
        {
          "hash"       => ->(len) { b3.hash(msg, len) },
          "keyed_hash" => ->(len) { b3.keyed_hash(key, msg, len) },
          "derive_key" => ->(len) { b3.derive_key(ctx, msg, len) },
        }.each do |mode, fn|
          expected = unhex(c[mode])
          assert_equal expected, fn.call(expected.bytesize), "#{mode}, input_len #{c["input_len"]}"
          assert_equal expected.byteslice(0, 32), fn.call(32), "#{mode} default length, input_len #{c["input_len"]}"
        end
      end
    end


    it "matches when streamed in odd pieces and read incrementally" do
      vectors["cases"].each do |c|
        msg    = input(c["input_len"])
        hasher = b3.new_keyed(vectors["key"])
        off    = 0
        step   = 0
        while off < msg.bytesize
          len = [1, 63, 64, 65, 1023, 1024, 1025][step % 7]
          hasher.update(msg.byteslice(off, len))
          off  += len
          step += 1
        end

        expected = unhex(c["keyed_hash"])
        xof      = hasher.finalize_xof
        out      = String.new(encoding: Encoding::BINARY)
        out << xof.read([7, 64, 1].fetch(out.bytesize % 3)) while out.bytesize < expected.bytesize
        assert_equal expected, out.byteslice(0, expected.bytesize), "input_len #{c["input_len"]}"
      end
    end
  end
end
