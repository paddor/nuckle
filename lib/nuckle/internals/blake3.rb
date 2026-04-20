# frozen_string_literal: true

module Nuckle
  module Internals
    # BLAKE3 cryptographic hash (unkeyed, keyed, and derive_key modes) with XOF.
    #
    # References:
    # - https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf
    # - https://github.com/BLAKE3-team/BLAKE3 (reference impl)
    #
    module Blake3
      MASK32    = 0xFFFFFFFF
      OUT_LEN   = 32
      KEY_LEN   = 32
      BLOCK_LEN = 64
      CHUNK_LEN = 1024

      # Domain-separation flags (per-compression, not global).
      CHUNK_START         = 1
      CHUNK_END           = 2
      PARENT              = 4
      ROOT                = 8
      KEYED_HASH          = 16
      DERIVE_KEY_CONTEXT  = 32
      DERIVE_KEY_MATERIAL = 64

      # Same constants as SHA-256 IV.
      IV = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
      ].freeze

      # Message-word permutation applied between rounds.
      MSG_PERMUTATION = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8].freeze

      module_function

      # Quarter-round (G) on a 16-word state.
      def g(state, a, b, c, d, mx, my)
        state[a] = (state[a] + state[b] + mx) & MASK32
        t = state[d] ^ state[a]
        state[d] = ((t >> 16) | (t << 16)) & MASK32
        state[c] = (state[c] + state[d]) & MASK32
        t = state[b] ^ state[c]
        state[b] = ((t >> 12) | (t << 20)) & MASK32
        state[a] = (state[a] + state[b] + my) & MASK32
        t = state[d] ^ state[a]
        state[d] = ((t >> 8) | (t << 24)) & MASK32
        state[c] = (state[c] + state[d]) & MASK32
        t = state[b] ^ state[c]
        state[b] = ((t >> 7) | (t << 25)) & MASK32
      end

      def round(state, m)
        # Columns
        g(state, 0, 4,  8, 12, m[0],  m[1])
        g(state, 1, 5,  9, 13, m[2],  m[3])
        g(state, 2, 6, 10, 14, m[4],  m[5])
        g(state, 3, 7, 11, 15, m[6],  m[7])
        # Diagonals
        g(state, 0, 5, 10, 15, m[8],  m[9])
        g(state, 1, 6, 11, 12, m[10], m[11])
        g(state, 2, 7,  8, 13, m[12], m[13])
        g(state, 3, 4,  9, 14, m[14], m[15])
      end

      def permute(m)
        MSG_PERMUTATION.map { |i| m[i] }
      end

      # BLAKE3 compression function.
      #
      # @param cv [Array<Integer>] 8-word chaining value
      # @param block_words [Array<Integer>] 16-word message block
      # @param counter [Integer] 64-bit counter (chunk index, XOF block index, or 0 for parents)
      # @param block_len [Integer] number of valid bytes in the block (1..64, or 0 for empty)
      # @param flags [Integer] domain-separation flags
      # @return [Array<Integer>] 16-word output (first 8 = new CV for non-XOF)
      #
      def compress(cv, block_words, counter, block_len, flags)
        state = [
          cv[0], cv[1], cv[2], cv[3],
          cv[4], cv[5], cv[6], cv[7],
          IV[0], IV[1], IV[2], IV[3],
          counter & MASK32, (counter >> 32) & MASK32, block_len, flags
        ]
        m = block_words.dup

        round(state, m)
        6.times do
          m = permute(m)
          round(state, m)
        end

        # Final xor: state[0..8] ^= state[8..16]; state[8..16] ^= cv[0..8]
        8.times do |i|
          state[i]     ^= state[i + 8]
          state[i + 8] ^= cv[i]
        end
        state
      end

      # Parse a 64-byte string (or zero-padded short string) into 16 LE u32 words.
      def words_from_block(block)
        block = block + ("\x00".b * (BLOCK_LEN - block.bytesize)) if block.bytesize < BLOCK_LEN
        block.unpack("V16")
      end

      # Deferred final compression. Supports variable-length output via XOF.
      class Output
        def initialize(input_cv, block_words, counter, block_len, flags)
          @cv        = input_cv
          @block     = block_words
          @counter   = counter
          @block_len = block_len
          @flags     = flags
          @xof_ctr   = 0
          @buffer    = String.new(encoding: Encoding::BINARY)
        end

        # 8-word CV (non-root). Used when folding intermediate parents.
        def chaining_value
          Blake3.compress(@cv, @block, @counter, @block_len, @flags)[0, 8]
        end

        # Read the next n bytes from the root XOF stream.
        def read(n)
          out = String.new(capacity: n, encoding: Encoding::BINARY)
          while out.bytesize < n
            if @buffer.empty?
              words = Blake3.compress(@cv, @block, @xof_ctr, @block_len, @flags | ROOT)
              @buffer = words.pack("V16")
              @xof_ctr += 1
            end
            take     = [@buffer.bytesize, n - out.bytesize].min
            out     << @buffer.byteslice(0, take)
            @buffer  = @buffer.byteslice(take..) || "".b
          end
          out
        end
      end

      # Streaming hasher. Supports update/finalize/finalize_xof.
      class Hasher
        # @param key_words [Array<Integer>] 8-word base key (IV or actual key)
        # @param flags [Integer] base flags (0, KEYED_HASH, or DERIVE_KEY_MATERIAL)
        def initialize(key_words, flags)
          @key_words         = key_words.freeze
          @flags             = flags
          @cv_stack          = []
          @chunk_counter     = 0
          @chunk_cv          = key_words.dup
          @chunk_block       = String.new(encoding: Encoding::BINARY)
          @blocks_compressed = 0
        end

        # Feed more input. Returns self for chaining.
        def update(input)
          input  = input.b
          len    = input.bytesize
          offset = 0

          while offset < len
            if @chunk_block.bytesize == BLOCK_LEN
              if @blocks_compressed < 15
                flush_intermediate_block
              else
                flush_final_chunk_block
                push_and_merge_chunk
                start_new_chunk
              end
            end

            need = BLOCK_LEN - @chunk_block.bytesize
            take = [need, len - offset].min
            @chunk_block << input.byteslice(offset, take)
            offset += take
          end
          self
        end

        # Return `out_len` bytes of output (default 32).
        def finalize(out_len = OUT_LEN)
          build_root_output.read(out_len)
        end

        # Return an Output that can be read incrementally via `read(n)`.
        def finalize_xof
          build_root_output
        end

        private

        def flush_intermediate_block
          words = @chunk_block.unpack("V16")
          flags = @flags
          flags |= CHUNK_START if @blocks_compressed == 0
          @chunk_cv           = Blake3.compress(@chunk_cv, words, @chunk_counter, BLOCK_LEN, flags)[0, 8]
          @chunk_block        = String.new(encoding: Encoding::BINARY)
          @blocks_compressed += 1
        end

        # Finalize the current (full-size, 16th) block of a chunk and produce its CV.
        def flush_final_chunk_block
          flags = @flags | CHUNK_END
          flags |= CHUNK_START if @blocks_compressed == 0
          words = @chunk_block.unpack("V16")
          @chunk_cv = Blake3.compress(@chunk_cv, words, @chunk_counter, BLOCK_LEN, flags)[0, 8]
        end

        def push_and_merge_chunk
          completed = @chunk_counter
          @cv_stack.push(@chunk_cv)
          total = completed + 1
          while (total & 1).zero?
            right = @cv_stack.pop
            left  = @cv_stack.pop
            block = left + right
            @cv_stack.push(Blake3.compress(@key_words, block, 0, BLOCK_LEN, @flags | PARENT)[0, 8])
            total >>= 1
          end
        end

        def start_new_chunk
          @chunk_counter    += 1
          @chunk_cv          = @key_words.dup
          @chunk_block       = String.new(encoding: Encoding::BINARY)
          @blocks_compressed = 0
        end

        # Build the final (deferred) Output — the last compression is not
        # actually performed until root_output#read / chaining_value.
        def build_root_output
          # Current chunk (possibly partial) becomes the right-most subtree.
          flags = @flags | CHUNK_END
          flags |= CHUNK_START if @blocks_compressed == 0
          block_len = @chunk_block.bytesize
          padded    = block_len == BLOCK_LEN ? @chunk_block : @chunk_block + ("\x00".b * (BLOCK_LEN - block_len))
          block_words = padded.unpack("V16")

          output = Output.new(@chunk_cv, block_words, @chunk_counter, block_len, flags)

          # Fold stack right-to-left; each fold creates a new PARENT Output.
          # The last one (leftmost stack entry) is the root — ROOT flag is
          # applied inside Output#read.
          @cv_stack.reverse_each do |left_cv|
            right_cv = output.chaining_value
            output = Output.new(@key_words, left_cv + right_cv, 0, BLOCK_LEN, @flags | PARENT)
          end
          output
        end
      end

      # One-shot unkeyed hash.
      def hash(input, length = OUT_LEN)
        Hasher.new(IV, 0).update(input).finalize(length)
      end

      # Build a Hasher for the unkeyed mode (for streaming use).
      def new_hasher
        Hasher.new(IV, 0)
      end

      # One-shot keyed hash (32-byte key).
      def keyed_hash(key, input, length = OUT_LEN)
        new_keyed(key).update(input).finalize(length)
      end

      def new_keyed(key)
        raise ArgumentError, "key must be 32 bytes" unless key.bytesize == KEY_LEN

        Hasher.new(key.b.unpack("V8"), KEYED_HASH)
      end

      # Derive a subkey from a context string and key material.
      def derive_key(context, material, length = OUT_LEN)
        new_derive_key(context).update(material).finalize(length)
      end

      def new_derive_key(context)
        ctx_key_bytes = Hasher.new(IV, DERIVE_KEY_CONTEXT).update(context).finalize(KEY_LEN)
        Hasher.new(ctx_key_bytes.unpack("V8"), DERIVE_KEY_MATERIAL)
      end
    end
  end
end
