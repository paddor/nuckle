# frozen_string_literal: true

module Nuckle
  # Raised when authenticated decryption fails (MAC verification failure).
  class CryptoError < StandardError
  end
end
