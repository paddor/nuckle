# frozen_string_literal: true

require "minitest/autorun"
require "nuckle"

begin
  require "rbnacl"
  HAVE_RBNACL = true
rescue LoadError
  HAVE_RBNACL = false
end

begin
  require "digest/blake3"
  HAVE_BLAKE3 = true
rescue LoadError
  HAVE_BLAKE3 = false
end

begin
  require "chacha20blake3"
  HAVE_CHACHA20BLAKE3 = true
rescue LoadError
  HAVE_CHACHA20BLAKE3 = false
end
