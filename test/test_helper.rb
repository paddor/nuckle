# frozen_string_literal: true

require "minitest/autorun"
require "nuckle"

begin
  require "rbnacl"
  HAVE_RBNACL = true
rescue LoadError
  HAVE_RBNACL = false
end
