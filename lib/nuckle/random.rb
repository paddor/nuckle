# frozen_string_literal: true

require "securerandom"

module Nuckle
  # Cryptographically secure random byte generation.
  module Random
    # Generates +n+ cryptographically secure random bytes.
    #
    # @param n [Integer] number of bytes
    # @return [String] random bytes (binary)
    def self.random_bytes(n)
      SecureRandom.random_bytes(n)
    end
  end
end
