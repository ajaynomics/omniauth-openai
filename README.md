# omniauth-openai

An [OmniAuth](https://github.com/omniauth/omniauth) strategy for
[Sign in with ChatGPT](https://developers.openai.com/siwc/website), OpenAI's
OpenID Connect sign-in.

It runs the authorization code flow with PKCE and a nonce, then verifies the
ID token's signature, issuer, audience, expiry, and nonce against OpenAI's
published keys before your application sees an identity. It makes no userinfo
call and hands your application no OpenAI tokens: sign-in proves who someone
is, nothing more.

Unofficial. Not affiliated with or endorsed by OpenAI.

## Before you start

Sign in with ChatGPT is in limited access. Request it through
[OpenAI's interest form](https://openai.com/form/sign-in-with-chatgpt-interest/).
OpenAI then issues a client ID (`oaiapp_…`), and a client secret if you ask for
a confidential client, and registers your exact callback URL, for example
`https://example.com/users/auth/openai/callback`.

## Install

```ruby
gem "omniauth-openai"
gem "omniauth-rails_csrf_protection" # Rails: sign-in must start with a POST
```

## Use

### Devise

```ruby
# config/initializers/devise.rb
config.omniauth :openai, ENV["OPENAI_CLIENT_ID"], ENV["OPENAI_CLIENT_SECRET"]
```

```ruby
# app/models/user.rb
devise :omniauthable, omniauth_providers: %i[openai]
```

```erb
<%= button_to "Continue with ChatGPT", user_openai_omniauth_authorize_path, data: { turbo: false } %>
```

### Plain Rack or Rails without Devise

```ruby
use OmniAuth::Builder do
  provider :openai, ENV["OPENAI_CLIENT_ID"], ENV["OPENAI_CLIENT_SECRET"]
end
```

A public client has no secret: pass `nil` and the strategy sends only its
client ID.

### The auth hash

```ruby
{
  "provider" => "openai",
  "uid" => "user-…",            # the ID token's sub: key accounts on this
  "info" => {
    "email" => "person@example.com", # present only when email_verified is true
    "name" => "Chat Person",
    "image" => "https://…"
  },
  "credentials" => {},
  "extra" => { "raw_info" => { … all verified ID token claims … } }
}
```

Key accounts on `provider` and `uid`, not email: one email can belong to more
than one OpenAI account. If you link to an existing account by email, link only
to one whose email your application has itself confirmed, or an attacker who
registers the address first gains the real owner's sign-in.

## Options

| Option | Default | Meaning |
| --- | --- | --- |
| `scope` | `"openid profile email"` | Requested scopes. |
| `client_auth_method` | `:basic` with a secret, `:none` without | `:basic` (client_secret_basic), `:post` (client_secret_post), or `:none`. |
| `redirect_uri` | the callback URL | Set it when a proxy changes the host the app sees. Must match the registered URL exactly. |
| `leeway` | `5` | Seconds of clock skew allowed on `exp` and `iat`. |
| `issuer`, `jwks_uri`, `client_options` | OpenAI's | Endpoints from `https://auth.openai.com/.well-known/openid-configuration`. |

Signing keys are cached per process for an hour. A token signed with a key the
cache lacks triggers one fresh download, at most once every five minutes.

## Failures

Every verification failure ends in OmniAuth's failure path with
`:invalid_credentials`, so a bad token never reaches your callback. A forged or
missing `state` fails as `:csrf_detected`; a person who declines consent fails
as `:access_denied`.

## Development

```sh
bundle install
bundle exec rake test
JWT_VERSION="~> 2.10" bundle update jwt && bundle exec rake test
```

## License

MIT
