# frozen_string_literal: true

require "test_helper"

# Drives the strategy through a Rack stack against stubbed OpenAI token and
# JWKS endpoints, so state, PKCE, nonce, client authentication, and ID token
# verification all run as they do in production.
class StrategyTest < Minitest::Test
  include Rack::Test::Methods

  CLIENT_ID = "oaiapp_test"
  CALLBACK_URL = "http://example.org/auth/openai/callback"
  TOKEN_URL = "https://auth.openai.com/api/accounts/oauth/token"
  JWKS_URL = "https://auth.openai.com/.well-known/jwks.json"
  SIGNING_KEY = JWT::JWK.new(OpenSSL::PKey::RSA.generate(2048), kid: "openai-test-key")

  def setup
    OmniAuth::Strategies::OpenAI::KEY_SETS.clear
    @session = {}
    @client_secret = nil
    @strategy_options = {}
    stub_request(:get, JWKS_URL).to_return(json(JWT::JWK::Set.new(SIGNING_KEY).export))
  end

  def app
    session = @session
    strategy = OmniAuth::Strategies::OpenAI.new(
      ->(env) { [ 200, { "content-type" => "application/json" }, [ JSON.dump(env["omniauth.auth"].to_hash) ] ] },
      CLIENT_ID, @client_secret, **@strategy_options
    )
    ->(env) { env["rack.session"] = session; strategy.call(env) }
  end

  def test_authorize_redirect_carries_pkce_nonce_and_identity_scopes
    authorize = start_sign_in

    assert_equal "auth.openai.com", authorize.host
    assert_equal "/api/accounts/authorize", authorize.path
    assert_equal CLIENT_ID, authorize.params["client_id"]
    assert_equal "code", authorize.params["response_type"]
    assert_equal "openid profile email", authorize.params["scope"]
    assert_equal "S256", authorize.params["code_challenge_method"]
    assert_equal CALLBACK_URL, authorize.params["redirect_uri"]
    refute_empty authorize.params["state"]
    refute_empty authorize.params["nonce"]
  end

  def test_each_sign_in_gets_a_fresh_state_nonce_and_challenge
    first = start_sign_in.params
    second = start_sign_in.params

    %w[state nonce code_challenge].each { |param| refute_equal first[param], second[param], param }
  end

  def test_a_verified_id_token_becomes_the_auth_hash
    authorize = start_sign_in
    stub_token_exchange(authorize)

    auth = finish_sign_in(authorize)

    assert_equal "openai", auth["provider"]
    assert_equal "user-openai-sub", auth["uid"]
    assert_equal({ "email" => "person@example.com", "name" => "Chat Person", "first_name" => "Chat",
                   "last_name" => "Person", "image" => "https://example.com/p.png" }, auth["info"])
    assert_equal "https://auth.openai.com", auth["extra"]["raw_info"]["iss"]
    assert_empty auth["credentials"]
  end

  def test_an_unverified_email_is_left_out_of_info
    authorize = start_sign_in
    stub_token_exchange(authorize, email_verified: false)

    auth = finish_sign_in(authorize)

    refute auth["info"].key?("email")
    assert_equal false, auth["extra"]["raw_info"]["email_verified"]
  end

  def test_a_public_client_sends_only_its_client_id
    authorize = start_sign_in
    exchange = stub_token_exchange(authorize) do |request, body|
      request.headers["Authorization"].nil? && !body.key?("client_secret")
    end

    finish_sign_in(authorize)

    assert_requested exchange
  end

  def test_a_confidential_client_uses_form_encoded_http_basic_by_default
    @client_secret = "s3cr:et/+="
    authorize = start_sign_in
    expected = "Basic #{[ "oaiapp_test:s3cr%3Aet%2F%2B%3D" ].pack("m0")}"
    exchange = stub_token_exchange(authorize) do |request, body|
      request.headers["Authorization"] == expected && !body.key?("client_secret")
    end

    finish_sign_in(authorize)

    assert_requested exchange
  end

  def test_client_secret_post_sends_the_secret_in_the_body
    @client_secret = "s3cret"
    @strategy_options = { client_auth_method: :post }
    authorize = start_sign_in
    exchange = stub_token_exchange(authorize) do |request, body|
      request.headers["Authorization"].nil? && body["client_secret"] == "s3cret"
    end

    finish_sign_in(authorize)

    assert_requested exchange
  end

  def test_a_wrong_nonce_fails
    authorize = start_sign_in
    stub_token_exchange(authorize, nonce: "replayed")

    assert_fails_with "invalid_credentials", authorize
  end

  def test_a_missing_nonce_fails
    authorize = start_sign_in
    stub_token_exchange(authorize, nonce: nil)

    assert_fails_with "invalid_credentials", authorize
  end

  def test_another_audience_fails
    authorize = start_sign_in
    stub_token_exchange(authorize, aud: "oaiapp_someone_else")

    assert_fails_with "invalid_credentials", authorize
  end

  def test_several_audiences_need_this_client_as_authorized_party
    authorize = start_sign_in
    stub_token_exchange(authorize, aud: [ CLIENT_ID, "other" ])

    assert_fails_with "invalid_credentials", authorize
  end

  def test_several_audiences_pass_when_this_client_is_the_authorized_party
    authorize = start_sign_in
    stub_token_exchange(authorize, aud: [ CLIENT_ID, "other" ], azp: CLIENT_ID)

    assert_equal "user-openai-sub", finish_sign_in(authorize)["uid"]
  end

  def test_another_issuer_fails
    authorize = start_sign_in
    stub_token_exchange(authorize, iss: "https://auth.example.com")

    assert_fails_with "invalid_credentials", authorize
  end

  def test_an_expired_token_fails
    authorize = start_sign_in
    stub_token_exchange(authorize, exp: Time.now.to_i - 60)

    assert_fails_with "invalid_credentials", authorize
  end

  def test_a_token_signed_by_an_unknown_key_fails
    authorize = start_sign_in
    stranger = JWT::JWK.new(OpenSSL::PKey::RSA.generate(2048), kid: "stranger")
    stub_token_exchange(authorize, key: stranger)

    assert_fails_with "invalid_credentials", authorize
  end

  def test_an_unsigned_token_fails
    authorize = start_sign_in
    unsigned = JWT.encode(claims_for(authorize), nil, "none")
    stub_request(:post, TOKEN_URL).to_return(json(id_token: unsigned))

    assert_fails_with "invalid_credentials", authorize
  end

  def test_a_token_response_without_an_id_token_fails
    authorize = start_sign_in
    stub_request(:post, TOKEN_URL).to_return(json(access_token: "at", token_type: "Bearer"))

    assert_fails_with "invalid_credentials", authorize
  end

  def test_a_token_response_that_is_not_json_fails
    authorize = start_sign_in
    stub_request(:post, TOKEN_URL).to_return(status: 200, body: "<html>maintenance</html>", headers: { "Content-Type" => "text/html" })

    assert_fails_with "invalid_credentials", authorize
  end

  def test_a_token_response_that_is_a_json_array_fails
    authorize = start_sign_in
    stub_request(:post, TOKEN_URL).to_return(status: 200, body: "[]", headers: { "Content-Type" => "application/json" })

    assert_fails_with "invalid_credentials", authorize
  end

  def test_a_token_endpoint_error_fails
    authorize = start_sign_in
    stub_request(:post, TOKEN_URL).to_return(status: 400, body: JSON.dump(error: "invalid_grant"), headers: { "Content-Type" => "application/json" })

    assert_fails_with "invalid_credentials", authorize
  end

  def test_an_id_token_that_is_not_a_jwt_fails
    authorize = start_sign_in
    stub_request(:post, TOKEN_URL).to_return(json(id_token: "not-a-jwt", token_type: "Bearer"))

    assert_fails_with "invalid_credentials", authorize
  end

  def test_an_id_token_without_a_subject_fails
    authorize = start_sign_in
    stub_token_exchange(authorize, sub: nil)

    assert_fails_with "invalid_credentials", authorize
  end

  def test_an_empty_subject_fails
    authorize = start_sign_in
    stub_token_exchange(authorize, sub: " ")

    assert_fails_with "invalid_credentials", authorize
  end

  def test_a_key_set_that_is_not_json_fails_without_being_cached
    authorize = start_sign_in
    stub_token_exchange(authorize)
    stub_request(:get, JWKS_URL)
      .to_return({ status: 200, body: "<html>oops</html>", headers: { "Content-Type" => "text/html" } },
                 json(JWT::JWK::Set.new(SIGNING_KEY).export))

    assert_fails_with "invalid_credentials", authorize

    retry_authorize = start_sign_in
    stub_token_exchange(retry_authorize)
    assert_equal "user-openai-sub", finish_sign_in(retry_authorize)["uid"]
  end

  def test_an_unreachable_key_set_fails
    authorize = start_sign_in
    stub_token_exchange(authorize)
    stub_request(:get, JWKS_URL).to_return(status: 503)

    assert_fails_with "invalid_credentials", authorize
  end

  def test_a_forged_state_never_reaches_the_token_endpoint
    authorize = start_sign_in
    exchange = stub_token_exchange(authorize)

    get "/auth/openai/callback", code: "auth-code", state: "forged"

    assert_equal 401, last_response.status
    assert_equal "csrf_detected", last_response.body
    assert_not_requested exchange
  end

  def test_a_declined_consent_fails_without_a_token_request
    authorize = start_sign_in
    exchange = stub_token_exchange(authorize)

    get "/auth/openai/callback", error: "access_denied", state: authorize.params["state"]

    assert_equal "access_denied", last_response.body
    assert_not_requested exchange
  end

  private

  Authorize = Struct.new(:host, :path, :params)

  def start_sign_in
    post "/auth/openai"
    location = URI.parse(last_response.location)
    Authorize.new(location.host, location.path, Rack::Utils.parse_query(location.query))
  end

  def finish_sign_in(authorize)
    get "/auth/openai/callback", code: "auth-code", state: authorize.params["state"]
    assert_equal 200, last_response.status, last_response.body
    JSON.parse(last_response.body)
  end

  def assert_fails_with(type, authorize)
    get "/auth/openai/callback", code: "auth-code", state: authorize.params["state"]

    assert_equal 401, last_response.status
    assert_equal type, last_response.body
  end

  def claims_for(authorize, overrides = {})
    {
      iss: "https://auth.openai.com", aud: CLIENT_ID, sub: "user-openai-sub",
      nonce: authorize.params["nonce"], iat: Time.now.to_i, exp: Time.now.to_i + 300,
      email: "person@example.com", email_verified: true, name: "Chat Person",
      given_name: "Chat", family_name: "Person", picture: "https://example.com/p.png"
    }.merge(overrides).compact
  end

  # Answers only an exchange whose verifier matches the authorize challenge,
  # so every passing sign-in proves PKCE end to end.
  def stub_token_exchange(authorize, key: SIGNING_KEY, **overrides, &extra_check)
    id_token = JWT.encode(claims_for(authorize, overrides), key.signing_key, "RS256", kid: key.kid)

    stub_request(:post, TOKEN_URL)
      .with { |request| pkce_exchange?(request, authorize, &extra_check) }
      .to_return(json(id_token: id_token, token_type: "Bearer"))
  end

  def pkce_exchange?(request, authorize)
    body = Rack::Utils.parse_query(request.body)
    challenge = Base64.urlsafe_encode64(Digest::SHA256.digest(body["code_verifier"].to_s), padding: false)

    body["grant_type"] == "authorization_code" &&
      body["code"] == "auth-code" &&
      body["client_id"] == CLIENT_ID &&
      body["redirect_uri"] == CALLBACK_URL &&
      challenge == authorize.params["code_challenge"] &&
      (!block_given? || yield(request, body))
  end

  def json(body)
    { status: 200, body: JSON.dump(body), headers: { "Content-Type" => "application/json" } }
  end
end
