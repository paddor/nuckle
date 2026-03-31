# frozen_string_literal: true

require_relative "lib/nuckle/version"

Gem::Specification.new do |s|
  s.name     = "nuckle"
  s.version  = Nuckle::VERSION
  s.authors  = ["Patrik Wenger"]
  s.email    = ["paddor@gmail.com"]
  s.summary  = "Pure Ruby NaCl crypto primitives"
  s.description = "Pure Ruby implementation of the NaCl crypto primitives " \
                  "(Curve25519, XSalsa20, Poly1305). No C extensions, no FFI, " \
                  "no libsodium. Is it any good? No."
  s.homepage = "https://github.com/paddor/nuckle"
  s.license  = "ISC"

  s.required_ruby_version = ">= 3.3"

  s.files = Dir["lib/**/*.rb", "README.md", "LICENSE"]
end
