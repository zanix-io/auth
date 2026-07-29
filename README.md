# Zanix – Auth

[![Version](https://img.shields.io/jsr/v/@zanix/auth?color=blue&label=jsr)](https://jsr.io/@zanix/auth/versions)\
[![Release](https://img.shields.io/github/v/release/zanix-io/auth?color=blue&label=git)](https://github.com/zanix-io/auth/releases)\
[![License](https://img.shields.io/badge/license-MIT-green.svg)](https://opensource.org/licenses/MIT)

---

## 🧭 Table of Contents

1. [Description](#-description)
2. [Features](#-features)
3. [Installation](#-installation)
4. [Core Registration](#-core-registration)
5. [Basic Usage](#-basic-usage)
6. [Authentication Methods](#-authentication-methods)
7. [Configuration](#-configuration)
8. [Contributing](#-contributing)
9. [Changelog](#-changelog)
10. [License](#-license)
11. [Resources](#-resources)

---

## 🧩 Description

**Zanix Auth** is the authentication and authorization module of the **Zanix** ecosystem, designed
to manage sessions, JWT tokens, OAuth2 (especially Google), blocklists, permission validation, and
abuse protection via rate limiting.

It provides a **unified and extensible system** for:

- OAuth2 connectors (Google built in; extend `OAuth2Connector` for any other provider)
- TOTP authenticator-app 2FA (Google Authenticator, Microsoft Authenticator, etc.)
- JWT generation and verification (HMAC and RSA with key rotation)
- Session management (create, revoke, generate session headers)
- Permission and scope validation (JWT audience)
- Configurable rate limiting based on per-session plans
- Ready-to-use middleware to protect routes and resources
- Decorators and pipes for interactors and controllers

> 💡 If you're building a full application (not just consuming auth in isolation), use
> **[`@zanix/core`](https://jsr.io/@zanix/core)**'s `Zanix.start()`/`Zanix.startWorker()` as your
> entrypoint — it wires `@zanix/auth` together with `@zanix/datamaster`, `@zanix/notifications`, and
> `@zanix/asyncmq` for you.

---

## ✨ Features

- **OAuth2 Connector**
  - `GoogleOAuth2Connector`: `generateAuthUrl()`, `getUserInfo()`/`validateToken()`,
    `revokeToken()`, and a combined `authenticate()` that also creates the local session.
  - Also available bound to the default provider: `this.providers.get('auth').google`.
  - `OAuth2Connector`: the abstract base class `GoogleOAuth2Connector` itself extends — use it to
    add a custom OAuth2 provider (GitHub, Microsoft, …) without reimplementing the flow. See
    [Adding a Custom OAuth2 Provider](./docs/authentication-methods.md#-adding-a-custom-oauth2-provider).

- **Provider DSL**
  - A default `ZanixAuthProvider` is registered automatically under the `'auth'` core-provider key —
    `this.providers.get('auth')` works with zero setup, the same pattern `@zanix/asyncmq` uses for
    its `'worker'` provider.
  - This registration (along with the default session headers interceptor, and the Google connector
    when `GOOGLE_OAUTH2_CLIENT_ID` is set) is wired by importing `jsr:@zanix/auth/core` once — see
    [Core Registration](#-core-registration). If your app already bootstraps via `@zanix/core`'s
    `Zanix.start()`, this is handled for you.
  - The provider also exposes `.otp`, `.totp`, and `.session` (see below), bound to the current
    request context — no need to thread `ctx`/cache/connectors through the lower-level functions
    yourself.

- **JWT Handling**
  - Exported types: `JWT`, `JWTHeader`, `JWTPayload`.
  - `createJWT(payload, secret, opts?)`: create JWT tokens.
  - `verifyJWT(token, secret, opts?)`: verify JWT tokens.
  - `decodeJWT(token)`: decode a JWT's header/payload without verifying its signature.
  - `getSecretByToken(token, type?)`: resolve the signing/verification secret for a given token.
  - Supports both HMAC and RSA keys.
  - JWK key rotation with versioned keys (`_V1`, `_V2`, …), controlled by `JWK_ROTATION_CYCLE`.

- **Session Management**
  - `generateSessionTokens()`, `createAccessToken()`, `createRefreshToken()`: generate different
    session token types.
  - `revokeAppTokens()`, `revokeSessionToken()`: revoke tokens or a full session.
  - `getSessionHeaders()`, `getDefaultSessionHeaders()`: add standardized session headers to
    responses (see [Session Response Headers](./docs/configuration.md#-session-response-headers)).
  - `userSessionHeaders`, `apiSessionHeaders`: the `user`/`api` header and cookie names used above
    (`sub`, `session`, `token`), for consumers that need to reference them directly.
  - Also available bound to the default provider: `this.providers.get('auth').session` —
    `.generateTokens()`, `.refreshTokens()`, `.revokeToken()`.

- **Service-Credential Exchange (Machine-to-Machine)**
  - `createServiceAssertion()`: a calling service signs a short-lived self-assertion with its own
    keypair — no shared secret, no human-shaped session.
  - `exchangeServiceCredential()`: verifies the assertion against a registered `JWK_PUB_<serviceId>`
    and mints a real `type: 'api'` access token, scoped to whatever
    `SERVICE_PERMISSIONS_<serviceId>`/`SERVICE_RATE_LIMIT_<serviceId>` the operator configured —
    never anything the caller requests. See
    [Service-Credential Exchange Guide](./docs/service-credential.md).

- **Block List**
  - `addTokenToBlockList(token, cache, kvDb?)`: add a JWT to the blocklist (by its `jti`, extracted
    internally).
  - `checkTokenBlockList(jti, cache, kvDb)`: verify whether a token ID is blocked.

- **OTP (One-Time Password)**
  - `generateOTP()`: generate OTP codes for additional authentication steps.
  - `verifyOTP()`: verify OTP validity.
  - Also available bound to the default provider: `this.providers.get('auth').otp` — `.generate()`,
    `.verify()`, and a combined `.authenticate()` that also creates the local session (mirrors
    `.google.authenticate()`).

- **TOTP (Authenticator App 2FA)**
  - `generateTOTPSecret()`, `getTOTPProvisioningUri()`: enroll a user with an authenticator app
    (Google Authenticator, Microsoft Authenticator, etc.) — generate a secret and a QR-code URI.
    `issuer` defaults to `'zanix-auth'` when omitted.
  - `generateTOTP()`, `verifyTOTP()`: compute/verify a time-based code, tolerating clock drift.
  - Always HMAC-SHA1, 6 digits, 30s steps — the defaults every authenticator app expects.
  - Also available bound to the default provider: `this.providers.get('auth').totp` —
    `.generateSecret()`, `.getProvisioningUri()`, `.verify()`, and a combined `.authenticate()` that
    also creates the local session. See
    [Two-Factor Authentication (TOTP)](./docs/authentication-methods.md#-two-factor-authentication-totp).

- **Scope / Permission Validation**
  - `scopeValidation()`: validate that JWTs include the required permissions or scopes.

- **Middlewares**
  - `sessionHeadersInterceptor`: injects session headers.
  - `jwtValidationGuard`: validates JWT tokens in incoming requests.
  - `rateLimitGuard`: applies rate limiting.
  - `ipAllowlistGuard`: restricts access to configured IP addresses or CIDR ranges.
  - `permissionsPipe`: validates permissions before executing route logic.

- **Decorators**
  - `AuthTokenValidation`: ensures that a method or route requires a valid token.
  - `RequirePermissions`: requires specific permissions or scopes.
  - `RateLimitGuard`: limits request rates at the method level.
  - `IpAllowlistGuard`: restricts controllers to configured IP addresses or CIDR ranges.

---

## 📦 Installation

Install via **JSR** using **Deno**:

```ts
import * as auth from 'jsr:@zanix/auth@[version]'
```

> Replace `[version]` with the latest version:
> [https://jsr.io/@zanix/auth](https://jsr.io/@zanix/auth)

Import specific modules:

```ts
import { GoogleOAuth2Connector } from 'jsr:@zanix/auth@[version]'
```

---

## 🧷 Core Registration

Importing `jsr:@zanix/auth` (the default entrypoint) only exposes its exported classes, functions,
and types — it does **not** register anything with the Zanix framework by itself. To get the
zero-config behavior described under [Provider DSL](#-features) (the default `ZanixAuthProvider`
under `'auth'`, the session headers interceptor, and — when `GOOGLE_OAUTH2_CLIENT_ID` is set — a
default `GoogleOAuth2Connector`), import the `./core` subpath once, anywhere it will run at startup:

```ts
import 'jsr:@zanix/auth/core'
```

> If your app bootstraps via **[`@zanix/core`](https://jsr.io/@zanix/core)**'s `Zanix.start()`/
> `Zanix.startWorker()`, this import already happens for you — no extra setup needed.

---

## 🚀 Basic Usage

Example showing how to:

1. Configure the authentication provider
2. Use Google OAuth2
3. Generate and verify session tokens

```ts
import { AuthTokenValidation } from 'jsr:@zanix/auth@latest'
import { Interactor, ZanixInteractor } from '@zanix/server'

@Interactor()
class LoginInteractor extends ZanixInteractor {
  public async auth() {
    const connector = this.providers.get('auth').google

    const { code } = /* … obtain OAuth2 auth code … */
    // `permissions` here becomes the session token's `aud` claim — see Permissions & Scopes
    // in the Authentication Methods guide (docs/authentication-methods.md).
    const { user, session } = await connector.authenticate(code, { permissions: ['admin'] })

    // For security reasons, never expose Google OAuth tokens or refresh tokens to the frontend.
    // These tokens must always remain server-side.
    return session.accessToken
  }
}

class SecureInteractor extends ZanixInteractor {
  @AuthTokenValidation({ permissions: ['admin', 'write:user'] }) // any ONE of these is enough
  async handle() {
    /** your code */
  }
}
```

---

## 🔐 Authentication Methods

Beyond the Google OAuth2 flow shown above, `@zanix/auth` also supports adding custom OAuth2
providers (GitHub, Microsoft, …), OTP (one-time password) delivery over email/SMS, and TOTP
authenticator-app 2FA — plus how `permissions`/scopes are checked across all of them. Use these when
Google isn't your only identity provider, or when you need a second authentication factor.

See the [Authentication Methods Guide](./docs/authentication-methods.md) for flows, examples, and
security considerations for each.

---

## 🔧 Configuration

Environment variables (Google OAuth2, JWT/JWK keys, rate-limit plans), rate limiting behavior, JWK
key rotation, and the session response headers/cookies added to responses are all documented in the
[Configuration Guide](./docs/configuration.md).

---

## 🤝 Contributing

1. Open an issue for bugs or feature requests.
2. Fork the `zanix-io/auth` repository and create a feature branch.
3. Implement your changes following project guidelines.
4. Add or update tests when applicable.
5. Submit a pull request with a clear description.

---

## 🕒 Changelog

See [`CHANGELOG`](./CHANGELOG.md) for the version history.

---

## 📜 License

Licensed under the **MIT License**. See the [`LICENSE`](./LICENSE) file for details.

---

## 🔗 Resources

- [Authentication Methods Guide](./docs/authentication-methods.md) — custom OAuth2 providers, OTP,
  TOTP 2FA, and permissions/scopes.
- [Configuration Guide](./docs/configuration.md) — environment variables, rate limiting, key
  rotation, session response headers.
- [IP Allowlisting Guide](./docs/network.md) — configuring IP restrictions, CIDR ranges, trusted
  proxy headers, and security considerations.
- [Service-Credential Exchange Guide](./docs/service-credential.md) — machine-to-machine
  authentication, key registration, and permission/rate-limit configuration.
- [Zanix Framework](https://github.com/zanix-io)
- [Deno Documentation](https://deno.com)
- Repository: [https://github.com/zanix-io/auth](https://github.com/zanix-io/auth)

---

_Developed with ❤️ by Ismael Calle | [@iscam2216](https://github.com/iscam2216)_
