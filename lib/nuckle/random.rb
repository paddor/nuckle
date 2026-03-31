# frozen_string_literal: true

require "securerandom"

module Nuckle
  module Random
    def self.random_bytes(n)
      SecureRandom.random_bytes(n)
    end
  end
end
