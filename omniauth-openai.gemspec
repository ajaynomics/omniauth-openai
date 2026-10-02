# frozen_string_literal: true

require_relative "lib/omniauth/openai/version"

Gem::Specification.new do |spec|
  spec.name          = "omniauth-openai"
  spec.version       = OmniAuth::OpenAI::VERSION
  spec.authors       = [ "Ajay Krishnan" ]
  spec.email         = [ "omniauth-openai@ajay.to" ]

  spec.summary       = "OmniAuth strategy for Sign in with ChatGPT (OpenAI OpenID Connect)."
  spec.description   = <<~DESC
    Adds "Sign in with ChatGPT" to Rack and Rails applications through
    OmniAuth and Devise. Authorization code flow with PKCE and a nonce; the
    ID token's signature, issuer, audience, expiry, and nonce are verified
    against OpenAI's published keys before the application sees an identity.
    Unofficial; not affiliated with or endorsed by OpenAI.
  DESC
  spec.homepage      = "https://github.com/ajaynomics/omniauth-openai"
  spec.license       = "MIT"
  spec.required_ruby_version = ">= 3.2.0"

  spec.metadata["source_code_uri"]       = spec.homepage
  spec.metadata["changelog_uri"]         = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata["bug_tracker_uri"]       = "#{spec.homepage}/issues"
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files = Dir.glob("lib/**/*.rb") + %w[README.md LICENSE CHANGELOG.md omniauth-openai.gemspec]
  spec.require_paths = [ "lib" ]

  spec.add_dependency "jwt", ">= 2.7", "< 4"
  spec.add_dependency "omniauth-oauth2", "~> 1.8"

  spec.add_development_dependency "minitest", ">= 5.20"
  spec.add_development_dependency "rack-test", "~> 2.1"
  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "webmock", "~> 3.20"
end
