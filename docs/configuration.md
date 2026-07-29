# Configuration Guide

Environment variables, rate limiting, JWT key rotation, and the session-related response
headers/cookies `@zanix/auth` manages for you.

## 🧭 Table of Contents

1. [Environment Variables](#-environment-variables)
2. [Rate Limiting](#-rate-limiting)
3. [Key Rotation](#-key-rotation)
4. [Session Response Headers](#-session-response-headers)

---

## 🌐 Environment Variables

| Variable                      | Description                                                              | Example                                    |
| ----------------------------- | ------------------------------------------------------------------------ | ------------------------------------------ |
| `GOOGLE_OAUTH2_CLIENT_ID`     | Google OAuth2 client ID                                                  | `your-google-client-id`                    |
| `GOOGLE_OAUTH2_CLIENT_SECRET` | Google OAuth2 client secret                                              | `your-google-client-secret`                |
| `GOOGLE_OAUTH2_REDIRECT_URI`  | OAuth2 redirect URI                                                      | `https://yourapp.com/auth/google/callback` |
| `GOOGLE_OAUTH2_AUTH_URL`      | Override for Google's authorization endpoint. Rarely needed.             | `https://proxy.example.com/authorize`      |
| `GOOGLE_OAUTH2_USERINFO_URL`  | Override for Google's user-info endpoint. Rarely needed.                 | `https://proxy.example.com/userinfo`       |
| `GOOGLE_OAUTH2_REVOKE_URL`    | Override for Google's token-revocation endpoint. Rarely needed.          | `https://proxy.example.com/revoke`         |
| `JWK_ROTATION_CYCLE`          | Rotation cycle for JWK keys. Used only when multiple JWK versions exist. | `"30m"`                                    |
| `JWT_KEY`                     | Base key for HMAC JWTs (`user` tokens)                                   | `my-secret-key`                            |
| `JWT_KEY_V1`                  | Versioned HMAC key                                                       | `another-key`                              |
| `JWK_PRI`                     | RSA private key for `api` tokens                                         | `base64`                                   |
| `JWK_PUB`                     | RSA public key for `api` tokens                                          | `base64`                                   |
| `JWK_PRI_V1`                  | Versioned RSA private key                                                | `…`                                        |
| `JWK_PUB_V1`                  | Versioned RSA public key                                                 | `…`                                        |
| `RATE_LIMIT_WINDOW_SECONDS`   | Rate limit window duration (seconds)                                     | `60`                                       |
| `RATE_LIMIT_PLANS`            | Rate limit plans.                                                        | `0:100;1:1000;2:3000`                      |

> The `GOOGLE_OAUTH2_*_URL` overrides default to Google's real endpoints and rarely need to be set —
> they exist for enterprise proxies or pointing a `GoogleOAuth2Connector` at a mock server in tests.

---

## ⏱️ Rate Limiting

When using `rateLimitGuard`:

- `RATE_LIMIT_WINDOW_SECONDS` defines the time window for rate limiting.
- `RATE_LIMIT_PLANS` maps plan indices to allowed requests per window.

The `session.rateLimit` determines which plan applies (e.g., `0` → 100 requests, `1` → 1000). If no
plan matches, the value directly sets the allowed number of requests per window.

Both `rateLimitGuard` and `jwtValidationGuard` accept an `app` option to scope the rate-limit cache
key per app, so multiple apps sharing the same session/user ID don't collide.

Response headers may include:

- `X-Znx-RateLimit-Limit` – maximum requests allowed in the current window
- `X-Znx-RateLimit-Remaining` – remaining requests in the current window
- `X-Znx-RateLimit-Reset` – seconds until the window resets
- `Retry-After` – seconds to wait before retrying when the limit is exceeded

> These names are the `RATE_LIMIT_HEADERS` constant, exported from `@zanix/server` — see
> `@zanix/server`'s `docs/CONFIGURATION.md#auth--admin-protocol-headers` if you need the raw object.

---

## 🔄 Key Rotation

`JWK_ROTATION_CYCLE` defines the rotation interval for JWT/JWK signing keys. You can provide a
human-readable duration (e.g., `"1h"`, `"30m"`, `"7d"`) or a numeric value in seconds.

Rotation only occurs if multiple versioned keys are available (e.g., `JWK_PRI_V1`, `JWK_PRI_V2`, …).
The system cycles through the available keys at each rotation interval. If only one key exists,
rotation is disabled.

---

## 📨 Session Response Headers

When a valid session is present, the following headers may be added to the response:

- `x-znx-<type>-session-status:<SessionStatus>` – indicates the current session status.
- `x-znx-<type>-id` – subject ID, included when a user token contains a `sub` claim.
- If `X-Znx-Cookies-Accepted: true` is present (in headers or cookies), session cookies are sent via
  `Set-Cookie`:

  ```text
  X-Znx-App-Token=<refreshToken>; Max-Age=<refreshTokenSeconds>; Path=/; HttpOnly; SameSite=Strict

  X-Znx-<type>-Session-Status=<SessionStatus>; Max-Age=<seconds>; Path=/; HttpOnly; SameSite=Strict

  X-Znx-<type>-Id=<sub>; Max-Age=<seconds>; Path=/; HttpOnly; SameSite=Strict

  X-Znx-Cookies-Accepted=true; Max-Age=<seconds>; Path=/; HttpOnly; SameSite=Strict
  ```

  `X-Znx-App-Token`'s `Max-Age` is derived from the refresh token's own expiration (e.g. ~1 year),
  independent of `<seconds>` above (derived from the access token's expiration, capped at 1h) used
  by the other three cookies.

> These header names come from the `AUTH_HEADERS`/`SESSION_HEADERS`/`GENERAL_HEADERS` constants,
> exported from `@zanix/server` (not from `@zanix/auth` itself) — see `@zanix/server`'s
> `docs/CONFIGURATION.md#auth--admin-protocol-headers` if you need the raw objects.

---

## See also

- [README](../README.md) — installation, core registration, and basic usage.
- [Changelog](../CHANGELOG.md) — version history.
