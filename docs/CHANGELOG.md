# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/) and this project
adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
