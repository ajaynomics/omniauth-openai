# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

require "omniauth-openai"
require "minitest/autorun"
require "rack/test"
require "webmock/minitest"
require "logger"

WebMock.disable_net_connect!

OmniAuth.config.logger = Logger.new(nil)
# Request-phase CSRF protection belongs to the host application (for Rails,
# omniauth-rails_csrf_protection); these tests exercise the strategy itself.
OmniAuth.config.request_validation_phase = nil
OmniAuth.config.on_failure = lambda do |env|
  [ 401, { "content-type" => "text/plain" }, [ env["omniauth.error.type"].to_s ] ]
end
