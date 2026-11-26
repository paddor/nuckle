# frozen_string_literal: true

module Nuckle
  # Raised when a key, nonce or tag has the wrong length. An ArgumentError,
  # like RbNaCl::LengthError.
  class LengthError < ArgumentError
  end
end
