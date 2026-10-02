# frozen_string_literal: true

require "json"
require "jwt"
require "omniauth-oauth2"
require "omniauth/openai/key_set"
require "rack/utils"
require "securerandom"
require "uri"

module OmniAuth
  module Strategies
    # Sign in with ChatGPT: OpenID Connect over the authorization code flow,
    # with PKCE and a nonce. See https://developers.openai.com/siwc/website.
    #
    # The strategy establishes who the person is and nothing more. It trusts
    # only the ID token, after checking its signature, issuer, audience,
    # expiry, and nonce. It makes no userinfo call and returns no OpenAI
    # tokens, because identity sign-in needs none.
    #
    # The endpoints come from https://auth.openai.com/.well-known/openid-configuration.
    # They are fixed options rather than discovered at boot, so a slow
    # discovery request cannot hold up an application starting.
    class OpenAI < OmniAuth::Strategies::OAuth2
      ISSUER = "https://auth.openai.com"
      KEY_SETS = Hash.new { |sets, uri| sets[uri] = OmniAuth::OpenAI::KeySet.new }
      KEY_SETS_LOCK = Mutex.new

      option :name, "openai"
      option :scope, "openid profile email"
      option :pkce, true
      option :issuer, ISSUER
      option :jwks_uri, "#{ISSUER}/.well-known/jwks.json"
      # :basic (client_secret_basic), :post (client_secret_post), or :none for
      # a public client, the three methods OpenAI's discovery document lists.
      # Left nil, a client with a secret uses :basic, the OpenID Connect
      # default, and one without uses :none.
      option :client_auth_method, nil
      option :leeway, 5
      option :client_options, {
        site: ISSUER,
        authorize_url: "/api/accounts/authorize",
        token_url: "/api/accounts/oauth/token"
      }

      uid { id_token_claims.fetch("sub") }

      # Applications commonly match accounts by email, so the email is
      # included only when OpenAI says the person verified it.
      info do
        {
          email: (id_token_claims["email"] if id_token_claims["email_verified"] == true),
          name: id_token_claims["name"],
          first_name: id_token_claims["given_name"],
          last_name: id_token_claims["family_name"],
          nickname: id_token_claims["preferred_username"],
          image: id_token_claims["picture"]
        }.compact
      end

      extra do
        { "raw_info" => id_token_claims }
      end

      # OmniAuth merges credentials blocks down the class chain, so the
      # parent's token keys can only be dropped by overriding the method.
      def credentials
        {}
      end

      # The token request carries client_id in the body for every method.
      # oauth2's :tls_client_auth scheme does exactly that and nothing more;
      # the secret, if any, is added by #token_params.
      def client
        ::OAuth2::Client.new(options.client_id, options.client_secret,
                             deep_symbolize(options.client_options).merge(auth_scheme: :tls_client_auth))
      end

      # OAuth2 appends the callback's query string, but OpenAI compares
      # redirect_uri exactly with the one sent to the authorize endpoint.
      def callback_url
        options.redirect_uri || (full_host + callback_path)
      end

      def authorize_params
        super.tap do |params|
          params[:nonce] = session[nonce_session_key] = SecureRandom.urlsafe_base64(32)
        end
      end

      def token_params
        params = super
        case client_auth_method
        when :basic then params.merge(headers: { "Authorization" => basic_authorization })
        when :post then params.merge(client_secret: options.client_secret)
        else params
        end
      end

      private

      attr_reader :id_token_claims

      # Runs inside OAuth2#callback_phase, which turns a CallbackError into an
      # :invalid_credentials failure. A token that fails verification never
      # reaches uid, info, or the application.
      def build_access_token
        expected_nonce = session.delete(nonce_session_key)
        super.tap do |token|
          @id_token_claims = verify_id_token(token.response.parsed["id_token"], expected_nonce)
        end
      end

      def verify_id_token(id_token, expected_nonce)
        raise CallbackError.new(:invalid_id_token, "The token response carried no ID token") if id_token.to_s.empty?

        claims, = ::JWT.decode(
          id_token, nil, true,
          algorithms: [ "RS256" ],
          jwks: ->(loader_options) { signing_keys(**loader_options.slice(:kid_not_found)) },
          iss: options.issuer, verify_iss: true,
          aud: options.client_id, verify_aud: true,
          required_claims: %w[sub exp iat],
          verify_iat: true,
          leeway: options.leeway
        )

        verify_authorized_party(claims)
        verify_nonce(claims, expected_nonce)
        claims
      rescue ::JWT::DecodeError, ::OAuth2::Error, ::Faraday::Error, ::JSON::ParserError => e
        raise CallbackError.new(:invalid_id_token, e.message)
      end

      # OpenID Connect Core 3.1.3.7: a token for several audiences must name
      # this client as the party it was issued to.
      def verify_authorized_party(claims)
        audiences = Array(claims["aud"])
        return if audiences.one? || claims["azp"] == options.client_id

        raise CallbackError.new(:invalid_id_token, "The ID token was issued to another party")
      end

      def verify_nonce(claims, expected_nonce)
        return if expected_nonce && Rack::Utils.secure_compare(claims["nonce"].to_s, expected_nonce)

        raise CallbackError.new(:invalid_id_token, "The ID token nonce did not match")
      end

      def signing_keys(kid_not_found: false)
        key_set.fetch(kid_not_found: kid_not_found) do
          client.request(:get, options.jwks_uri).parsed
        end
      end

      def key_set
        KEY_SETS_LOCK.synchronize { KEY_SETS[options.jwks_uri] }
      end

      def client_auth_method
        method = options.client_auth_method&.to_sym
        method || (options.client_secret.to_s.empty? ? :none : :basic)
      end

      # RFC 6749 2.3.1: both halves are form-encoded before Base64.
      def basic_authorization
        pair = [ options.client_id, options.client_secret ].map { |part| URI.encode_www_form_component(part.to_s) }.join(":")
        "Basic #{[ pair ].pack("m0")}"
      end

      def nonce_session_key
        "omniauth.#{name}.nonce"
      end
    end
  end
end

OmniAuth.config.add_camelization "openai", "OpenAI"
