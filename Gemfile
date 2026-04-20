# frozen_string_literal: true

source "https://rubygems.org"

gemspec

gem "minitest"
gem "rake"
gem "rbnacl", "~> 7.0"
gem "benchmark-ips"

# Optional dev dependencies for cross-validation tests. Skipped gracefully
# when unavailable (see test/test_helper.rb).
gem "blake3-rb", require: false
if File.exist?(File.expand_path("../chacha20blake3", __dir__))
  gem "chacha20blake3", path: "../chacha20blake3", require: false
end
