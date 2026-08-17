# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/) and this project
adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.0] - 2026-08-17

### Added

- `DEFAULT_AUTH_ISSUER` — now exported from `mod.ts` alongside `createJWT`/`verifyJWT`/`decodeJWT`.
  Lets a consumer verifying a token this package minted (`type: 'api'` service tokens included)
  reference the same default `iss` this package's own `verifyJWT` calls already assume, instead of
  hardcoding the literal string.
- `ServiceAuthClientOptions.httpClient` (`createServiceAuthClient`) — an optional `Deno.HttpClient`
  every exchange call from the returned function is issued through, passed straight to
  `RestClient`'s own new `client` option (see `@zanix/server`'s changelog). Lets a caller present a
  client certificate on the exchange call itself, not only on whatever request it makes afterward
  with the returned headers — needed against a target that enforces mTLS on the WHOLE connection
  (exchange included), since `requestCert`/`rejectUnauthorized` are negotiated once per TLS
  connection, not per HTTP request. Omit for the previous behavior (a plain `RestClient`,
  unchanged).

## [0.6.1] - 2026-08-04

### Fixed

- `jwtValidationGuard` now assigns `accessToken` on the session it builds — this request's own
  verified access token, taken from its `Authorization`/`X-Znx-Authorization` header. Previously the
  guard never stored it anywhere on `ctx.session`, so a handler had no way to read/forward the
  caller's own token (e.g. to authenticate a downstream call made on their behalf) without
  re-parsing the header itself. Stored under `accessToken`, distinct from `token` (the refresh token
  field `sessionHeadersInterceptor` reads to set the `X-Znx-App-Token` cookie) — reusing that name
  would have made the interceptor overwrite the refresh-token cookie with the access token on every
  authenticated request. See
  [Authentication Methods: Reading the Current Request's Access Token](docs/authentication-methods.md#-reading-the-current-requests-access-token).

## [0.6.0] - 2026-08-01

### Added

- `createServiceAuthClient(options)` — a generic, reusable building block on top of
  `createServiceAssertion`/`exchangeServiceCredential` for ANY app (not just `@zanix/admin`) that
  needs to call another Zanix service authenticated as itself. Given
  `{serviceId, privateKey, keyId?,
  assertionExpiration?}`, it returns a
  `(targetServiceId, exchangeUrl) => Promise<ServiceAuthHeaders>` function that signs an assertion,
  exchanges it at `exchangeUrl`, and returns `{ 'X-Znx-Authorization': 'Bearer <token>' }` — caching
  the result per `targetServiceId` and re-exchanging automatically a few seconds before the cached
  token's `expiresIn` elapses. Knows nothing about `ServiceRegistry` or any other admin-specific
  concept — see `@zanix/admin`'s `createServiceRegistryAuthHeaders` for the thin adapter that wires
  this into a `ServiceRegistryEntry`.
- **`createServiceAssertion`'s `privateKey` is now optional** — omit it to resolve
  `JWK_PRI_<serviceId>`/`JWK_PRI_<serviceId>_<keyId>` automatically, the exact mirror image of how
  the verifying side (`exchangeServiceCredential`) already resolves
  `JWK_PUB_<serviceId>`/`JWK_PUB_<serviceId>_<keyId>`. New exported
  `resolveServiceAssertionPrivateKey(serviceId, keyId)` does the resolution (throwing
  `InternalError` naming the exact missing env var if nothing's registered) — exported so a consumer
  that wants to validate its own config upfront, before any real signing attempt, can check
  resolvability without reimplementing this naming rule itself (see `@zanix/notifications`'s
  `assertTemplatesConfigNotConflicting()` for a real example). `createServiceAuthClient`'s own
  `ServiceAuthClientOptions.privateKey` is optional for the same reason — every consumer of either
  function gets env-var resolution for free instead of each inventing its own env var name on top of
  it, which is exactly what motivated this change: a `TEMPLATES_SERVICE_PRIVATE_KEY`-shaped env var
  was about to be reinvented per consuming package.
- **`createServiceAssertion`'s `keyId` is now also resolved automatically** — omit it to resolve
  `JWK_ID_<serviceId>`, falling back to `serviceId` itself (today's single-key default) when that's
  unset too. New exported `resolveServiceAssertionKeyId(serviceId)` does the resolution. Same
  motivation as the `privateKey` change above, extended to "which key": rotating a service's keypair
  is now a pure config change — flip `JWK_ID_<serviceId>` once
  `JWK_PRI_<serviceId>_<newId>`/`JWK_PUB_<serviceId>_<newId>` are both registered — with no
  `TEMPLATES_SERVICE_AUTH_KEY_ID`-shaped env var needed per consuming package either. An explicit
  `keyId` argument still always wins when passed.

### Changed (breaking)

- **`createServiceAssertion`'s `privateKey` option must now be base64-encoded**, matching the
  convention `JWK_PRI`/`JWK_PUB_<serviceId>` already use everywhere else in this package —
  previously it expected the raw PEM string directly, the only inconsistent case of this kind in the
  whole package. `createServiceAssertion` now `atob()`-decodes it internally before signing; passing
  a raw (non-base64) PEM now rejects instead of silently mis-signing. Also changed from a plain
  function to `async`, so this decode failure (or any other malformed-key error) always surfaces as
  a rejected Promise, consistent with its declared `Promise<string>` return type, rather than
  sometimes throwing synchronously.
- **`privateKey` must be PKCS#8** (`-----BEGIN PRIVATE KEY-----`) — unchanged behavior, but now
  documented: the underlying `crypto.subtle.importKey` call always imports with `format: 'pkcs8'`,
  so a PKCS#1 key (`-----BEGIN RSA PRIVATE KEY-----`, e.g. from `openssl genrsa`) fails to import.
  `generateRSAKeys()` (from `@zanix/helpers`) already produces PKCS#8; convert an existing PKCS#1
  key with `openssl pkcs8 -topk8 -nocrypt -in old.pem -out new.pem`.

## [0.5.0] - 2026-07-28

### Added

- `ipAllowlistGuard` — a middleware guard restricting access to a configured allowlist of exact IPs
  or CIDR ranges, resolved from the request's real client IP (`trustProxyHeader`-gated, to avoid
  blindly trusting a spoofable proxy header) or explicit `allow` entries. `IpAllowlistGuard`
  decorator applies it declaratively at the controller/method level; `IpAllowlistOptions` configures
  it. Falls back to the `ADMIN_IP_ALLOWLIST` env var when no explicit configuration is given.
  Rejects out-of-allowlist requests with **403 Forbidden**. See `docs/network.md`.
- `createServiceAssertion()`/`exchangeServiceCredential()` — see `docs/service-credential.md` —
  machine-to-machine authentication without a shared secret or a human-shaped session. A calling
  service signs a short-lived self-assertion with its own keypair (`createServiceAssertion`), and
  `exchangeServiceCredential` verifies it against `JWK_PUB_<serviceId>` (reusing the existing
  `kid`-based key resolution, no new registry concept) before minting a real `type: 'api'` access
  token via the existing `createAppToken`. Granted permissions come only from the
  operator-configured `SERVICE_PERMISSIONS_<serviceId>`, never from the caller — same for rate
  limiting: `SERVICE_RATE_LIMIT_<serviceId>` sets the minted token's `rateLimit` claim, falling back
  to `createAppToken`'s own default (`100`) otherwise, the same default a `type: 'user'` session
  gets. `rateLimitGuard` already applies to `api` sessions exactly the same way it does to `user`
  ones (no type-specific branch), so this makes the two paths fully consistent. Exported as plain
  functions, not a mounted route — a consumer wires its own single handler around
  `exchangeServiceCredential`, same as it already does for `@zanix/core`'s
  `TemplatesAdminRepository`/`Service`.
- `createServiceAssertion()`'s new optional `keyId` option, plus `JWK_PUB_<serviceId>_<keyId>` as an
  alternative to the bare `JWK_PUB_<serviceId>` registration — supports rotating a calling service's
  own assertion-signing key with a real overlap window (old and new key both registered and valid at
  once, no deploy-ordering requirement). `keyId` defaults to `serviceId` when omitted, reproducing
  today's single-key behavior unchanged; it only ever selects which registered key verifies the
  assertion — identity (`iss`/`sub`, always `serviceId`) and granted permissions/rate limit (always
  keyed by `serviceId` alone) are unaffected, and a key registered under one `serviceId` can never
  authenticate as a different one. See `docs/service-credential.md`'s new "Rotating a Service's Key"
  section for the step-by-step procedure.

### Changed

- `AuthTokenValidation`/`jwtValidationGuard`'s `type` option now also accepts an array (e.g.
  `type: ['user', 'api']`) to accept either token shape on the same route — the first configured
  type whose own header (`Authorization` for `user`, `X-Znx-Authorization` for `api`) actually
  carries a Bearer token is the one the request is validated against. Passing a single value keeps
  today's exact behavior.
- `AUTH_HEADERS`, `SESSION_HEADERS`, `RATE_LIMIT_HEADERS`, and `GENERAL_HEADERS` moved to
  `@zanix/server` (which `@zanix/auth` already depends on) to eliminate duplicate/diverging copies
  of the same header names across `@zanix/auth`, `@zanix/core`, and `@zanix/notifications`. This is
  an internal change only — `@zanix/auth`'s own public exports (`userSessionHeaders`,
  `apiSessionHeaders`, `rateLimitGuard`, etc.) are unaffected. See `@zanix/server`'s
  `docs/CONFIGURATION.md#auth--admin-protocol-headers`.
- Anonymous session IP resolution now uses the shared `getClientIp()` helper instead of manually
  parsing proxy headers, centralizing client IP extraction across the framework.

### Fixed

- **`sessionHeadersInterceptor` never actually added session response headers/cookies on a
  successful request, and `permissionsPipe`/`@RequirePermissions` rejected every request with "No
  active user session" regardless of whether the caller was authenticated.** Both read
  `ctx.locals.session`, but `@zanix/server`'s `contextSettingPipe` always promotes it to the frozen
  `ctx.session` (and deletes `locals.session`) between the guard phase and any pipe/interceptor — so
  by the time either of these ran, `locals.session` was already gone. Confirmed with a minimal
  reproduction exercising the real guard → pipe → interceptor order. `rate-limit.guard.ts` was never
  affected — it runs during the guard phase, before the promotion happens. **Follow-up:** reading
  only `ctx.session` turned out to be incomplete — `contextSettingPipe`'s promotion is one-shot,
  happening once before the pipe stage, but `defineLocalSession` is also called from handler-stage
  code (`generateSessionTokens`/`refreshSessionTokens`/ `revokeSessionToken`, i.e.
  login/OTP/TOTP/OAuth2/refresh/revoke), which runs _after_ that promotion and only ever writes
  `ctx.locals.session`, never `ctx.session`. Since `sessionHeadersInterceptor` is registered
  globally and runs on every response, this meant a login response carried no session cookie at all,
  a refresh response omitted the rotated refresh token, and a revoke/logout response reported the
  stale pre-revocation status. Both now check `ctx.locals.session` first (the freshest value, when
  something re-set it after the initial promotion) and fall back to `ctx.session` otherwise. For
  `permissionsPipe` this is a defensive fallback only — nothing in `@zanix/auth` itself re-populates
  `locals.session` before it runs — but costs nothing and protects a consuming app's own custom pipe
  composed alongside `@RequirePermissions`.
- `getSessionHeaders` pushed a malformed `undefined=undefined; Max-Age=0; ...` cookie for
  `type:
  'api'` responses whenever `cookiesAccepted` was true and `maxAge` was `0` (the default on
  every auth failure, via `getDefaultSessionHeaders`, which never passes `expiration`) — an operator
  precedence bug (`tokenHeader && refreshToken || maxAge === 0`) let the `maxAge === 0` branch fire
  even when `tokenHeader` (`SESSION_HEADERS.api.token`) is `undefined`. Fixed to
  `tokenHeader &&
  (refreshToken || maxAge === 0)`. Decided not to give `SESSION_HEADERS.api.token`
  a real value instead (the ADR's own open question) — `type: 'api'` sessions have no refresh-token
  concept at all under `exchangeServiceCredential`'s design, so there's nothing meaningful for it to
  carry.
- `JWTValidationOpts.type` didn't accept a `readonly` array, only a mutable `SessionTypes[]` —
  masked by the test suite always running with `--no-check` (`deno test` doesn't type-check by
  default), but a real `deno check`/JSR-publish failure for any consumer declaring its `type: [...]`
  array as a shared `as const` constant (the exact pattern `@zanix/core`'s and `@zanix/admin`'s own
  admin controllers use). Widened to `SessionTypes | SessionTypes[] | readonly SessionTypes[]`.
- Widening `type` above (previous entry) then exposed a second, related `deno check` failure inside
  `jwtValidationGuard` itself: `Array.isArray`'s type guard doesn't cleanly narrow a union mixing
  mutable and `readonly` array members, silently leaving the resolved `type`/`authHeaderKey`
  implicitly `any` — no runtime impact (this only affects static type-checking), but still a real
  `deno check` failure. Fixed by normalizing via `[...configuredType]` (spread) instead of relying
  on the narrowed assignment directly.

### Security

- `ipAllowlistGuard` requires `trustProxyHeader: true` explicitly before it will read a client IP
  from any proxy header — it never trusts one implicitly, since a spoofable header would otherwise
  defeat the allowlist entirely.
- **Resolved** the previously-documented rotation asymmetry between `exchangeServiceCredential`'s
  two keys: the calling service's own registered key now supports the same kind of overlap-window
  rotation `@zanix/auth`'s own `JWK_PRI`/`JWK_PUB` already had, via the new
  `JWK_PUB_<serviceId>_
  <keyId>` form (see the `Added` entry above) — no more atomic env-var-swap
  requirement or deploy-ordering window. The two rotation mechanisms remain fully independent:
  rotating a calling service's key never invalidates an access token it already minted, and vice
  versa; a key registered under one `serviceId` can never authenticate as a different one,
  regardless of `keyId` collisions between services. Covered by `service-exchange.test.ts`: old key
  valid while registered, new key valid once registered, both valid simultaneously during a rotation
  overlap window, the old key rejected once retired, an unknown `keyId` rejected, a `sub`/`iss`
  mismatch rejected, and an already-minted access token proven to survive its issuing service's key
  rotation — plus the pre-existing mint→verify round trip through a rotated `JWK_PRI_V1` end to end.

## [0.4.0] - 2026-02-04

### Removed

- **BREAKING**: Removed the `createAuthProvider()` DSL function (previously used to register
  `ZanixAuthProvider` manually, e.g. in a `base.defs.ts` file). Migration:

  ```diff
  - // base.defs.ts
  - import { createAuthProvider } from '@zanix/auth'
  - createAuthProvider()
  ```

  ```diff
  + // anywhere that runs at startup
  + import '@zanix/auth/core'
  ```

  If your app bootstraps via `@zanix/core`'s `Zanix.start()`, no change is needed — it imports
  `@zanix/auth/core` for you.

### Added

- `ZanixAuthProvider` is now registered automatically (as the `'auth'` core-provider) by importing
  the new `jsr:@zanix/auth/core` entrypoint once — replaces the manual `createAuthProvider()` call.
  The same entrypoint also auto-registers the default session headers interceptor and, when
  `GOOGLE_OAUTH2_CLIENT_ID` is set, a default `GoogleOAuth2Connector`.
- Publicly exported several previously-internal types from the main entrypoint: `AuthConnectors`,
  `CoreAuthConnectors`, `GoogleUserInfo`, `JWTAlgorithm`, `JWTOptions`, `JWTVerifyOptions`,
  `Headers`, `AuthSessionOptions`, `GenerateOTPOptions`, `JWTValidationOpts`, `OAuthFlow`,
  `OtpFlow`, `SessionFlow`, `AppTokenBaseAccess`, `RateLimitsOptions`, `SessionStatus`,
  `SessionTokens`, `SessionTypes`.
- Migrated the `@zanix/server` dependency from `1.*` to `2.x`.
- `OAuth2Connector`: new abstract base class extracted from `GoogleOAuth2Connector`, for building
  custom OAuth2 providers (GitHub, Microsoft, …) without reimplementing `generateAuthUrl()`/
  `getUserInfo()`/`revokeToken()`/`authenticate()`. `GoogleOAuth2Connector` is now a thin subclass
  with identical public behavior. The authorize URL's `response_type` (`'token'`/`'code'`) and every
  endpoint URL/`defaultScope` are configurable, both per-provider (subclass defaults) and
  per-instance (constructor `options`). `GoogleOAuth2Connector` additionally resolves its endpoint
  URLs from the new `GOOGLE_OAUTH2_AUTH_URL`/`GOOGLE_OAUTH2_USERINFO_URL`/`GOOGLE_OAUTH2_REVOKE_URL`
  env vars before falling back to Google's real endpoints.
- TOTP (RFC 6238) authenticator-app 2FA, compatible with Google Authenticator, Microsoft
  Authenticator, and similar apps: `generateTOTPSecret()`, `getTOTPProvisioningUri()`,
  `generateTOTP()`, `verifyTOTP()`, plus a bound `.totp` on the default provider
  (`.generateSecret()`, `.getProvisioningUri()`, `.verify()`, `.authenticate()`). Always
  HMAC-SHA1/6-digit/30s-step by design (the values real authenticator apps expect), with a
  configurable drift `window` (default `1` step) for clock tolerance, and an `issuer` that defaults
  to `'zanix-auth'` when omitted. New exported types: `TotpFlow`, `TOTPVerifyOptions`.

### Changed

- The missing-credentials constructor error (`clientId`/`clientSecret`/`redirectUri`) is now generic
  OAuth2 wording instead of Google-specific, since it's now shared by every `OAuth2Connector`
  subclass.

### Fixed

- `apiSessionHeaders` was incorrectly assigned the `user` session header names instead of the `api`
  ones.
- `rateLimitGuard`: the "Anonymous users are not permitted" rejection reason was unreachable dead
  code; it now correctly fires when there is no session at all, distinct from a session that lacks a
  valid rate-limit configuration.
- `jwtValidationGuard` was overwriting `ctx.locals.session.token` with the current request's access
  token on every authenticated request (instead of leaving the session's refresh token untouched),
  which corrupted the `X-Znx-App-Token` cookie via `sessionHeadersInterceptor` on any request after
  login.
- `getSessionHeaders`: the refresh-token cookie's `Max-Age` was computed from the access token's
  expiration (capped at 1h, scaled by an unrelated constant) instead of from the refresh token's own
  `exp` claim (typically ~1y) — it's now derived from the refresh token itself, and forced to `0`
  when the session is being invalidated.

## [0.3.18] - 2026-02-04

### Added

- `rateLimitGuard` and `jwtValidationGuard` accept an `app` option to scope the rate-limit cache key
  per app, avoiding collisions when multiple apps share the same session/user ID.

## [0.3.17] - 2026-01-27

### Changed

- Adjusted the refresh-token cookie's `Max-Age` formula (superseded by the fix in 0.4.0).

## [0.3.16] - 2026-01-27

### Changed

- Extended the refresh-token cookie's `Max-Age` beyond the other session cookies' lifetime instead
  of expiring it together with them (superseded by the fix in 0.4.0).

## [0.3.15] - 2025-12-17

### Fixed

- `jwtValidationGuard` failure responses (missing/invalid token, key resolution errors, verification
  errors) now correctly include their `Set-Cookie` headers — previously only the rate-limited
  response applied them.

## [0.3.14] - 2025-12-17

### Fixed

- `revokeSessionToken` now returns `UNAUTHORIZED` (matching `refreshSessionTokens`) instead of
  `INTERNAL_SERVER_ERROR` when there is no refresh token available to revoke.

### Changed

- Consolidated the "invalid refresh token" error construction shared by `refreshSessionTokens` and
  `revokeSessionToken` into a single `invalidRefreshTokenError` helper.

## [0.3.12] - 2025-12-17

### Fixed

- Clarified error messages related to session tokens.
- Assigned a prefix to the KV key storage for OTPs.

## [0.3.11] - 2025-11-30

### Fixed

- Fixed JWT key rotation issue.
- Fixed blocklist expiration time handling.

### Changed

-Added default iss to JWT generation and verification, using the provided issuer or falling back to
the default.

## [0.3.3] - 2025-11-25

### Fixed

- Fixed injection issue in the Google OAuth connector.

### Added

- Integrated cookie handling.
- Added support for refresh tokens in user sessions.

## [0.3.2] - 2025-11-24

### Fixed

- Correctly decoded RSA JWT keys.
- Properly registered the headers interceptor.

## [0.3.1] - 2025-11-24

### Fixed

- Updated the AuthProvider registration to use a scoped instance instead of the previous lifetime.

## [0.3.0] - 2025-11-24

### Changed

- Renamed **session tokens** to **app tokens** for consistency across the authentication system.

### Added

- Implemented the **app token flow** in the authentication provider.

## [0.2.0] - 2025-11-19

### Changed

- Updated several dependencies and libraries to improve performance, security, and compatibility
  with the latest versions.

## [0.1.0] - 2025-11-19

- First commit
