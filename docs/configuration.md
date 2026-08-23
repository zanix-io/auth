# Configuration Guide

Environment variables, rate limiting, JWT key rotation, and the session-related response
headers/cookies `@zanix/auth` manages for you.

## 🧭 Table of Contents

1. [Environment Variables](#-environment-variables)
2. [Rate Limiting](#-rate-limiting)
3. [Captcha (Anti-bot Verification)](#-captcha-anti-bot-verification)
4. [Key Rotation](#-key-rotation)
5. [Session Response Headers](#-session-response-headers)

---

## 🌐 Environment Variables

| Variable                      | Description                                                                                                                                         | Example                                                    |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| `GOOGLE_OAUTH2_CLIENT_ID`     | Google OAuth2 client ID                                                                                                                             | `your-google-client-id`                                    |
| `GOOGLE_OAUTH2_CLIENT_SECRET` | Google OAuth2 client secret                                                                                                                         | `your-google-client-secret`                                |
| `GOOGLE_OAUTH2_REDIRECT_URI`  | OAuth2 redirect URI                                                                                                                                 | `https://yourapp.com/auth/google/callback`                 |
| `GOOGLE_OAUTH2_AUTH_URL`      | Override for Google's authorization endpoint. Rarely needed.                                                                                        | `https://proxy.example.com/authorize`                      |
| `GOOGLE_OAUTH2_USERINFO_URL`  | Override for Google's user-info endpoint. Rarely needed.                                                                                            | `https://proxy.example.com/userinfo`                       |
| `GOOGLE_OAUTH2_REVOKE_URL`    | Override for Google's token-revocation endpoint. Rarely needed.                                                                                     | `https://proxy.example.com/revoke`                         |
| `GOOGLE_OAUTH2_TOKEN_URL`     | Override for Google's token endpoint, used by the authorization-code flow (`authenticateWithCode()`). Rarely needed.                                | `https://proxy.example.com/token`                          |
| `GOOGLE_OAUTH2_RESPONSE_TYPE` | `'code'` switches the connector to the recommended authorization-code flow; any other value (or unset) keeps the implicit-flow default (`'token'`). | `code`                                                     |
| `GITHUB_OAUTH2_CLIENT_ID`     | GitHub OAuth2 client ID                                                                                                                             | `your-github-client-id`                                    |
| `GITHUB_OAUTH2_CLIENT_SECRET` | GitHub OAuth2 client secret                                                                                                                         | `your-github-client-secret`                                |
| `GITHUB_OAUTH2_REDIRECT_URI`  | OAuth2 redirect URI                                                                                                                                 | `https://yourapp.com/auth/github/callback`                 |
| `GITHUB_OAUTH2_AUTH_URL`      | Override for GitHub's authorization endpoint. Rarely needed.                                                                                        | `https://proxy.example.com/authorize`                      |
| `GITHUB_OAUTH2_USERINFO_URL`  | Override for GitHub's user-info endpoint. Rarely needed.                                                                                            | `https://proxy.example.com/userinfo`                       |
| `GITHUB_OAUTH2_REVOKE_URL`    | Override for GitHub's token-revocation endpoint. Rarely needed.                                                                                     | `https://proxy.example.com/applications/{client_id}/token` |
| `GITHUB_OAUTH2_TOKEN_URL`     | Override for GitHub's token endpoint, used by the authorization-code flow (`authenticateWithCode()`). Rarely needed.                                | `https://proxy.example.com/token`                          |
| `GITHUB_OAUTH2_RESPONSE_TYPE` | GitHub already defaults to `'code'` (its only real flow); overriding to `'token'` breaks login against real GitHub.                                 | `code`                                                     |
| `JWK_ROTATION_CYCLE`          | Rotation cycle for JWK keys. Used only when multiple JWK versions exist.                                                                            | `"30m"`                                                    |
| `JWT_KEY`                     | Base key for HMAC JWTs (`user` tokens)                                                                                                              | `my-secret-key`                                            |
| `JWT_KEY_V1`                  | Versioned HMAC key                                                                                                                                  | `another-key`                                              |
| `JWK_PRI`                     | RSA private key for `api` tokens                                                                                                                    | `base64`                                                   |
| `JWK_PUB`                     | RSA public key for `api` tokens                                                                                                                     | `base64`                                                   |
| `JWK_PRI_V1`                  | Versioned RSA private key                                                                                                                           | `…`                                                        |
| `JWK_PUB_V1`                  | Versioned RSA public key                                                                                                                            | `…`                                                        |
| `RATE_LIMIT_WINDOW_SECONDS`   | Rate limit window duration (seconds)                                                                                                                | `60`                                                       |
| `RATE_LIMIT_PLANS`            | Rate limit plans.                                                                                                                                   | `0:100;1:1000;2:3000`                                      |
| `CAPTCHA_PROVIDER`            | Explicitly selects the captcha provider `captchaGuard` uses. Only required when more than one provider's own secret key (below) is set at once.     | `recaptcha`                                                |
| `RECAPTCHA_SECRET_KEY`        | Google reCAPTCHA secret key (works for both v2 and v3 site keys).                                                                                   | `6Lc...`                                                   |
| `RECAPTCHA_API_BASE`          | Override for reCAPTCHA's verification API base URL. Rarely needed.                                                                                  | `https://proxy.example.com/recaptcha/api`                  |
| `HCAPTCHA_SECRET_KEY`         | hCaptcha secret key.                                                                                                                                | `0x0000...`                                                |
| `HCAPTCHA_API_BASE`           | Override for hCaptcha's verification API base URL. Rarely needed.                                                                                   | `https://proxy.example.com`                                |
| `TURNSTILE_SECRET_KEY`        | Cloudflare Turnstile secret key.                                                                                                                    | `0x4AAA...`                                                |
| `TURNSTILE_API_BASE`          | Override for Turnstile's verification API base URL. Rarely needed.                                                                                  | `https://proxy.example.com/turnstile/v0`                   |

> The `GOOGLE_OAUTH2_*_URL`/`GITHUB_OAUTH2_*_URL` overrides default to each provider's real
> endpoints and rarely need to be set — they exist for enterprise proxies or pointing a connector at
> a mock server in tests.

---

## ⏱️ Rate Limiting

When using `rateLimitGuard`:

- `RATE_LIMIT_WINDOW_SECONDS` defines the time window for rate limiting.
- `RATE_LIMIT_PLANS` maps plan indices to allowed requests per window.

The `session.rateLimit` determines which plan applies (e.g., `0` → 100 requests, `1` → 1000). If no
plan matches, the value directly sets the allowed number of requests per window.

Both `rateLimitGuard` and `jwtValidationGuard` accept an `app` option to scope the rate-limit cache
key per app, so multiple apps sharing the same session/user ID don't collide.

> **`trustProxyHeader` is required whenever an anonymous session identity needs to be resolved** —
> no default, ever. `true` keys the identity off the resolved client IP
> (`x-forwarded-for`/`cf-connecting-ip`/`x-real-ip`) — only safe behind a trusted proxy that
> overwrites those headers, since a client fully controls them otherwise. `false` makes every
> anonymous request share ONE identity instead — a deliberate, explicit trade-off: closes the
> spoofing bypass, at the cost of one abusive (or just busy) anonymous client exhausting a shared
> quota for everyone else, where that identity is used to key one (`rateLimitGuard`'s bucket).
>
> The enforcement lives at the source (`getAnonymousSessionId`, `@zanix/auth`'s internal anonymous-
> identity resolver) — so every path that can reach it is covered, not just `rateLimitGuard`:
>
> - `rateLimitGuard({...})` additionally validates eagerly, **at construction time** (when the guard
>   is built, e.g. as a `@Controller`'s `guards` argument — not deferred to the first request),
>   whenever anonymous access is enabled (`anonymousLimit` isn't `false`/`0`).
> - `getDefaultSessionHeaders({...})` (used directly, or internally by `jwtValidationGuard` to build
>   a failure-response's headers/cookies) also accepts `trustProxyHeader`/`trustedHeaders`, required
>   only when it actually falls back to an anonymous identity (no client subject resolvable from
>   `cookies`/`headers`). `jwtValidationGuard` itself always passes `false` there internally — that
>   identity only ever labels an already-rejected response, it never keys a shared resource the way
>   `rateLimitGuard`'s bucket does, so there's no trade-off to expose as its own option.
>
> `RateLimitsOptions`, `IpAllowlistOptions`, and `AnonymousSessionOptions` are all built on
> `@zanix/helpers`'s shared `ProxyTrustOptions` contract — one shape, three consumers, so
> `trustProxyHeader`/`trustedHeaders` can't drift apart between them. Same contract
> `ipAllowlistGuard`'s own `trustProxyHeader` already establishes for this identical class of
> decision.

Response headers may include:

- `X-Znx-RateLimit-Limit` – maximum requests allowed in the current window
- `X-Znx-RateLimit-Remaining` – remaining requests in the current window
- `X-Znx-RateLimit-Reset` – seconds until the window resets
- `Retry-After` – seconds to wait before retrying when the limit is exceeded

> These names are the `RATE_LIMIT_HEADERS` constant, exported from `@zanix/server` — see
> `@zanix/server`'s `docs/configuration.md#auth--admin-protocol-headers` if you need the raw object.

---

## 🤖 Captcha (Anti-bot Verification)

`captchaGuard`/`@CaptchaGuard()` verifies a client-submitted captcha response token against a
third-party anti-bot provider — Google reCAPTCHA, hCaptcha, or Cloudflare Turnstile — before
allowing a request through. Defense-in-depth, the same as `ipAllowlistGuard`/`rateLimitGuard`: never
a replacement for real authentication/authorization, typically added on top of
`@AuthTokenValidation` on a sign-up/login/contact-form endpoint prone to bot abuse.

```ts
@Controller()
@CaptchaGuard()
export class SignupController extends ZanixController {
  // ...
}
```

**Token**: the request must carry the provider's response token — produced client-side by the
provider's own widget/script, the consumer's own responsibility to load and forward — in the
`X-Znx-Captcha-Token` header (see `CAPTCHA_TOKEN_HEADER`). This guard only validates a token that
already arrives; it never renders or serves anything of its own, the same way `OAuth2Connector`
doesn't either.

**Provider resolution**: a provider adapter can be supplied directly (`options.adapter`), or
resolved automatically — `CAPTCHA_PROVIDER` (+ each provider's own `*_SECRET_KEY`/`*_API_BASE` env
vars) only needs to be set when more than one provider's secret key is configured at once (the same
optional-selector shape `@zanix/notifications`'s `SMS_PROVIDER`/`WHATSAPP_PROVIDER` uses); with
exactly one provider's secret key set, it's auto-detected with zero extra config. If nothing is
configured at all, this guard is a pass-through — it does not restrict requests, matching
`ipAllowlistGuard`'s own unconfigured behavior.

**Score-based providers**: reCAPTCHA v3 (and any future provider/key that returns a confidence
`score`) is gated by `options.minScore` (default `0.5`) — a response below that threshold is
rejected the same way `success: false` is. reCAPTCHA v2, hCaptcha, and Turnstile respond pass/fail
only, so `minScore` never applies to them.

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
  X-Znx-App-Token=<refreshToken>; Max-Age=<refreshTokenSeconds>; Path=/; HttpOnly; Secure; SameSite=Strict

  X-Znx-<type>-Session-Status=<SessionStatus>; Max-Age=<seconds>; Path=/; HttpOnly; Secure; SameSite=Strict

  X-Znx-<type>-Id=<sub>; Max-Age=<seconds>; Path=/; HttpOnly; Secure; SameSite=Strict

  X-Znx-Cookies-Accepted=true; Max-Age=<seconds>; Path=/; HttpOnly; Secure; SameSite=Strict
  ```

  `X-Znx-App-Token`'s `Max-Age` is derived from the refresh token's own expiration (e.g. ~1 year),
  independent of `<seconds>` above (derived from the access token's expiration, capped at 1h) used
  by the other three cookies.

> These header names come from the `AUTH_HEADERS`/`SESSION_HEADERS`/`GENERAL_HEADERS` constants,
> exported from `@zanix/server` (not from `@zanix/auth` itself) — see `@zanix/server`'s
> `docs/configuration.md#auth--admin-protocol-headers` if you need the raw objects.

---

## See also

- [README](../README.md) — installation, core registration, and basic usage.
- [Changelog](../CHANGELOG.md) — version history.
