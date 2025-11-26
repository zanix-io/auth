# Zanix – Auth

[![Version](https://img.shields.io/jsr/v/@zanix/auth?color=blue&label=jsr)](https://jsr.io/@zanix/auth/versions)\
[![Release](https://img.shields.io/github/v/release/zanix-io/auth?color=blue&label=git)](https://github.com/zanix-io/auth/releases)\
[![License](https://img.shields.io/badge/license-MIT-green.svg)](https://opensource.org/licenses/MIT)

---

## 🧭 Table of Contents

- [🧩 Description](#🧩-description)
- [⚙️ Features](#⚙️-features)
- [📦 Installation](#📦-installation)
- [🚀 Basic Usage](#🚀-basic-usage)
- [🤝 Contributing](#🤝-contributing)
- [🕒 Changelog](#🕒-changelog)
- [⚖️ License](#⚖️-license)
- [🔗 Resources](#🔗-resources)

---

## 🧩 Description

**Zanix Auth** is the authentication and authorization module of the **Zanix** ecosystem, designed
to manage sessions, JWT tokens, OAuth2 (especially Google), blocklists, permission validation, and
abuse protection via rate limiting.

It provides a **unified and extensible system** for:

- OAuth2 connectors (Google currently supported)
- JWT generation and verification (HMAC and RSA with key rotation)
- Session management (create, revoke, generate session headers)
- Permission and scope validation (JWT audience)
- Configurable rate limiting based on per-session plans
- Ready-to-use middleware to protect routes and resources
- Decorators and pipes for interactors and controllers

---

## ⚙️ Features

- **OAuth2 Connector**
  - `GoogleOAuth2Connector`: authenticate users using Google OAuth2.
  - Easy integration with `ZanixAuthProvider`.

- **Provider DSL**
  - `createAuthProvider()`: generates a `ZanixAuthProvider` using the Zanix `@Provider` decorator.
  - Supports lazy initialization and can be used in interactors (`@Interactor({ Provider })`).

- **JWT Handling**
  - Exported types: `JWT`, `JWTHeader`, `JWTPayload`.
  - `createJWT(data, opts)`: create JWT tokens.
  - `verifyJWT(token, opts)`: verify JWT tokens.
  - Supports both HMAC and RSA keys.
  - JWK key rotation with versioned keys (`_V1`, `_V2`, …), controlled by `JWK_ROTATION_CYCLE`.

- **Session Management**
  - `createSessionToken()`, `createAccessToken()`, `createRefreshToken()`: generate different
    session token types.
  - `revokeSessionAndToken()`, `revokeSessionTokens()`: revoke sessions and tokens.
  - `getSessionHeaders()`, `getDefaultSessionHeaders()`: add standardized session headers to
    responses.

- **Block List**
  - `addTokenToBlockList(jti)`: add a JWT (by its `jti`) to the blocklist.
  - `checkTokenBlockList(jti)`: verify whether a token is blocked.

- **OTP (One-Time Password)**
  - `generateOTP()`: generate OTP codes for additional authentication steps.
  - `verifyOTP()`: verify OTP validity.

- **Scope / Permission Validation**
  - `scopeValidation()`: validate that JWTs include the required permissions or scopes.

- **Middlewares**
  - `sessionHeadersInterceptor`: injects session headers.
  - `jwtValidationGuard`: validates JWT tokens in incoming requests.
  - `rateLimitGuard`: applies rate limiting.
  - `permissionsPipe`: validates permissions before executing route logic.

- **Decorators**
  - `AuthTokenValidation`: ensures that a method or route requires a valid token.
  - `RequirePermissions`: requires specific permissions or scopes.
  - `RateLimitGuard`: limits request rates at the method level.

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
import { createAuthProvider, GoogleOAuth2Connector } from 'jsr:@zanix/auth@[version]'
```

---

## 🚀 Basic Usage

Example showing how to:

1. Configure the authentication provider
2. Use Google OAuth2
3. Generate and verify session tokens

```ts
import { createAuthProvider, RequirePermissions } from 'jsr:@zanix/auth@latest'
import { Interactor, ZanixInteractor } from '@zanix/server'

const AuthProvider = createAuthProvider()

@Interactor({ Provider: AuthProvider })
class LoginInteractor extends ZanixInteractor {
  public async auth() {
    const connector = this.provider.google

    const { code } = /* … obtain OAuth2 auth code … */
    const { tokens, session } = await connector.authenticate(code, this.context)

    // For security reasons, never expose Google OAuth tokens or refresh tokens to the frontend.
    // These tokens must always remain server-side.
    return session.accessToken
  }
}

@RequirePermissions(['admin'])
class SecureInteractor extends ZanixInteractor {
  async handle() {
    /** your code */
  }
}
```

---

### 🌐 Environment Variables

| Variable                      | Description                                                              | Example                                    |
| ----------------------------- | ------------------------------------------------------------------------ | ------------------------------------------ |
| `GOOGLE_OAUTH2_CLIENT_ID`     | Google OAuth2 client ID                                                  | `your-google-client-id`                    |
| `GOOGLE_OAUTH2_CLIENT_SECRET` | Google OAuth2 client secret                                              | `your-google-client-secret`                |
| `GOOGLE_OAUTH2_REDIRECT_URI`  | OAuth2 redirect URI                                                      | `https://yourapp.com/auth/google/callback` |
| `JWK_ROTATION_CYCLE`          | Rotation cycle for JWK keys. Used only when multiple JWK versions exist. | `"30m"`                                    |
| `JWT_KEY`                     | Base key for HMAC JWTs (`user` tokens)                                   | `my-secret-key`                            |
| `JWT_KEY_V1`                  | Versioned HMAC key                                                       | `another-key`                              |
| `JWK_PRI`                     | RSA private key for `api` tokens                                         | `base64`                                   |
| `JWK_PUB`                     | RSA public key for `api` tokens                                          | `base64`                                   |
| `JWK_PRI_V1`                  | Versioned RSA private key                                                | `…`                                        |
| `JWK_PUB_V1`                  | Versioned RSA public key                                                 | `…`                                        |
| `RATE_LIMIT_WINDOW_SECONDS`   | Rate limit window duration (seconds)                                     | `60`                                       |
| `RATE_LIMIT_PLANS`            | Rate limit plans.                                                        | `0:100;1:1000;2:3000`                      |

---
### 🔐 Session & Security

#### ⏱️ Rate Limiting

When using `rateLimitGuard`:

- `RATE_LIMIT_WINDOW_SECONDS` defines the time window for rate limiting.
- `RATE_LIMIT_PLANS` maps plan indices to allowed requests per window.

The `session.rateLimit` determines which plan applies (e.g., `0` → 100 requests, `1` → 1000).
If no plan matches, the value directly sets the allowed number of requests per window.

Response headers may include:

- `X-Znx-RateLimit-Limit` – maximum requests allowed in the current window
- `X-Znx-RateLimit-Remaining` – remaining requests in the current window
- `X-Znx-RateLimit-Reset` – seconds until the window resets
- `Retry-After` – seconds to wait before retrying when the limit is exceeded
---

#### 🔄 Key Rotation

`JWK_ROTATION_CYCLE` defines the rotation interval for JWT/JWK signing keys. You can provide a
human-readable duration (e.g., `"1h"`, `"30m"`, `"7d"`) or a numeric value in seconds.

Rotation only occurs if multiple versioned keys are available (e.g., `JWK_PRI_V1`, `JWK_PRI_V2`,
…).\
The system cycles through the available keys at each rotation interval. If only one key exists,
rotation is disabled.

---

#### 📨 Session Response Headers

When a valid session is present, the following headers may be added to the response:

- `x-znx-<type>-session-status:<SessionStatus>` – indicates the current session status.
- `x-znx-<type>-id` – subject ID, included when a user token contains a `sub` claim.
- If `X-Znx-Cookies-Accepted: true` is present (in headers or cookies), session cookies are sent via
  `Set-Cookie`:

  ```text
  X-Znx-App-Token=<sessionToken>; Max-Age=<seconds>; Path=/; HttpOnly; SameSite=Strict

  X-Znx-<type>-Session-Status=<SessionStatus>; Max-Age=<seconds>; Path=/; HttpOnly; SameSite=Strict

  X-Znx-<type>-Id=<sub>; Max-Age=<seconds>; Path=/; HttpOnly; SameSite=Strict

  X-Znx-Cookies-Accepted=true; Max-Age=<seconds>; Path=/; HttpOnly; SameSite=Strict
  ```

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

## ⚖️ License

Licensed under the **MIT License**. See the [`LICENSE`](./LICENSE) file for details.

---

## 🔗 Resources

- [Zanix Framework](https://github.com/zanix-io)
- [Deno Documentation](https://deno.com)
- Repository: [https://github.com/zanix-io/auth](https://github.com/zanix-io/auth)

---

_Developed with ❤️ by Ismael Calle | [@iscam2216](https://github.com/iscam2216)_
