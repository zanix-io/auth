# Authentication Methods

Beyond the flagship Google OAuth2 example in the [README](../README.md#-basic-usage), `@zanix/auth`
supports building custom OAuth2 providers, one-time-password (OTP) delivery over email/SMS, and TOTP
authenticator-app 2FA — plus how permissions and scopes are checked across all of them. This guide
covers all four.

## 🧭 Table of Contents

1. [Permissions & Scopes](#-permissions--scopes)
2. [Adding a Custom OAuth2 Provider](#-adding-a-custom-oauth2-provider)
3. [OTP (One-Time Password)](#-otp-one-time-password)
4. [Two-Factor Authentication (TOTP)](#-two-factor-authentication-totp)

---

## 🔑 Permissions & Scopes

The `permissions` you set when creating session tokens (`generateTokens()`/`authenticate()`, in any
of the flows below or in the README's Google OAuth2 example) are stored as the JWT's `aud`
(audience) claim. That same claim is what every permission check — in `AuthTokenValidation` or
`RequirePermissions` — is matched against:

- **`AuthTokenValidation({ permissions })`** checks `permissions` against the token's `aud` claim as
  part of JWT verification itself — before a session even exists. This is the common case, and what
  real handlers use almost exclusively: one decorator both authenticates the request and authorizes
  it.
- **`RequirePermissions`/`permissionsPipe`** checks the same required `permissions` against
  `ctx.session.scope` (the `aud` claim copied onto the session once it exists) — it does not touch
  the JWT signature at all. Use it only when authentication already happened earlier in the pipeline
  and a specific method needs a narrower/additional permission check on top.
- In both cases, access is granted if **at least one** required permission matches — not all of
  them. `permissions: ['admin', 'write:user']` means "admin OR write:user", not "both."
- A session whose `aud`/scope includes `'*'` is granted access to any permission check.

---

## 🔌 Adding a Custom OAuth2 Provider

`GoogleOAuth2Connector` is itself a thin subclass of the exported `OAuth2Connector<TUserInfo>` base
class. To support another provider, extend it directly — you only need to supply the endpoints, the
default scope, and how to derive the session subject from that provider's user-info shape:

```ts
import { OAuth2Connector, type OAuth2ConnectorOptions } from 'jsr:@zanix/auth@[version]'

type GitHubUserInfo = { id: number; email: string }

class GitHubOAuth2Connector extends OAuth2Connector<GitHubUserInfo> {
  constructor(options: OAuth2ConnectorOptions = {}) {
    super({
      authUrl: 'https://github.com/login/oauth/authorize',
      userInfoUrl: 'https://api.github.com/user',
      revokeUrl: 'https://api.github.com/applications/{client_id}/token',
      defaultScope: 'read:user user:email',
    }, options)
  }

  protected getSubject(user: GitHubUserInfo): string {
    return user.email
  }
}
```

`generateAuthUrl()`, `getUserInfo()`, `revokeToken()`, and `authenticate()` all come for free from
the base class. `response_type` (`'token'`/`'code'`) and every endpoint URL/`defaultScope` can be
overridden per-instance via the constructor's `options`, on top of the subclass's own defaults —
useful for auth-code flows or pointing at a proxy/mock endpoint.

---

## 📟 OTP (One-Time Password)

Generate a short-lived numeric code, deliver it yourself (email, SMS, …), then verify it against the
session context — useful when you don't want to rely on an authenticator app:

```ts
class LoginInteractor extends ZanixInteractor {
  public async requestOtp(user: { email: string }) {
    const code = await this.providers.get('auth').otp.generate({ target: user.email })

    // Send `code` to the user yourself (email/SMS) — the library only generates and caches it.
    return { sent: true }
  }

  public async verifyOtp(user: { email: string }, code: string) {
    // `permissions` here becomes the session token's `aud` claim — see Permissions & Scopes above.
    const session = await this.providers.get('auth').otp.authenticate(
      user.email,
      code,
      { permissions: ['admin'] },
    )

    return session.accessToken
  }
}
```

The code is cached server-side (Redis when `REDIS_URI` is set, otherwise in-memory) against
`target`, expires after `exp` seconds (default `300`), and is removed as soon as it's verified once.

---

## 🔒 Two-Factor Authentication (TOTP)

Enroll a user with an authenticator app (Google Authenticator, Microsoft Authenticator, etc.),
persist the secret on your own user record, then verify the codes it generates:

```ts
class TwoFactorInteractor extends ZanixInteractor {
  public enroll(user: { email: string }) {
    const totp = this.providers.get('auth').totp

    const secret = totp.generateSecret()
    const uri = totp.getProvisioningUri(secret, user.email, { issuer: 'MyApp' })

    // Render `uri` as a QR code for the user to scan, and persist `secret` yourself
    // (e.g. on the user record) — the library never stores it for you.
    return { uri }
  }

  public async verify(user: { email: string; totpSecret: string }, code: string) {
    // `permissions` here becomes the session token's `aud` claim — see Permissions & Scopes above.
    const session = await this.providers.get('auth').totp.authenticate(
      user.totpSecret,
      code,
      { subject: user.email, permissions: ['admin'] },
    )

    return session.accessToken
  }
}
```

`generateTOTP()`/`verifyTOTP()` always use HMAC-SHA1, 6-digit codes, and 30-second steps — the
defaults real authenticator apps expect — and `verifyTOTP()` accepts the previous/current/next step
by default to tolerate clock drift. `issuer` defaults to `'zanix-auth'` when omitted.

---

## See also

- [README](../README.md) — installation, core registration, and the flagship Google OAuth2 example.
- [Configuration Guide](./configuration.md) — environment variables, rate limiting, key rotation,
  session response headers.
- [Changelog](../CHANGELOG.md) — version history.
