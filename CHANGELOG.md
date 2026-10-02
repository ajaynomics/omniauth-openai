# Changelog

## 0.1.1 - 2026-10-02

### Fixed

- A key set response that is not a JSON Web Key Set (an HTML error page
  served with 200, say) fails the sign-in without being cached, so one bad
  answer from the issuer no longer breaks sign-in until the cache expires.
- Reject an ID token whose `sub` is empty or not a string; ruby-jwt's
  required-claims check only confirms the claim exists.

### Verified

- A full sign-in against the live `auth.openai.com` (public client, PKCE,
  nonce): OpenAI accepts the authorize request, returns the nonce in the ID
  token, sends `aud` as a one-item list without `azp`, and marks the email
  verified.

## 0.1.0 - 2026-10-01

First release: Sign in with ChatGPT for OmniAuth and Devise, with PKCE, a
nonce, and full ID token verification against OpenAI's published keys.
