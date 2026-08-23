# Authentication Methods

Beyond the flagship Google OAuth2 example in the [README](../README.md#-basic-usage), `@zanix/auth`
ships a second built-in OAuth2 provider (GitHub), supports building custom OAuth2 providers beyond
those two, one-time-password (OTP) delivery over email/SMS, and TOTP authenticator-app 2FA — plus
how permissions and scopes are checked across all of them. This guide covers all five.

## 🧭 Table of Contents

1. [Permissions & Scopes](#-permissions--scopes)
2. [Reading the Current Request's Access Token](#-reading-the-current-requests-access-token)
3. [GitHub OAuth2](#-github-oauth2)
4. [Adding a Custom OAuth2 Provider](#-adding-a-custom-oauth2-provider)
5. [OTP (One-Time Password)](#-otp-one-time-password)
6. [Two-Factor Authentication (TOTP)](#-two-factor-authentication-totp)

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

## 🎟️ Reading the Current Request's Access Token

Once `jwtValidationGuard`/`AuthTokenValidation` succeeds, `ctx.session.accessToken` holds **this
request's own verified access token** — the exact value taken from its `Authorization`/
`X-Znx-Authorization` header:

```ts
class ProxyInteractor extends ZanixInteractor {
  @AuthTokenValidation()
  async handle() {
    // Forward the caller's own identity to a downstream service call made on their behalf.
    const upstream = await fetch('https://internal-service/resource', {
      headers: { Authorization: `Bearer ${this.context.session.accessToken}` },
    })
    return upstream.json()
  }
}
```

**`accessToken` is never the refresh token.** The session also carries a separate `token` field once
a session is created/refreshed (`generateTokens()`, `refreshTokens()`, OTP/TOTP/OAuth2
`authenticate()`) — that's the long-lived refresh token `sessionHeadersInterceptor` stores in the
`X-Znx-App-Token` cookie, and it is never set by request validation alone. A request that only went
through `jwtValidationGuard` (no login/refresh in the same request) has `accessToken` but no
`token`.

---

## 🐙 GitHub OAuth2

`GitHubOAuth2Connector` is a second built-in provider alongside `GoogleOAuth2Connector` — same
shape, same `this.providers.get('auth').github` access path — but it **defaults to the
authorization-code flow (`responseType: 'code'`), unlike Google's implicit-flow default.** GitHub's
own OAuth2 implementation has no implicit flow at all — its `/login/oauth/authorize` redirect always
comes back with `?code=...`, never a bearer token directly — so `.authenticate()`/`.validateToken()`
cannot work against real GitHub; only `.authenticateWithCode()`/`.validateCode()` do:

```ts
class LoginInteractor extends ZanixInteractor {
  public async auth() {
    const connector = this.providers.get('auth').github

    const { code } = /* … obtain the OAuth2 auth code from the redirect (?code=...) … */
    // `permissions` here becomes the session token's `aud` claim — see Permissions & Scopes above.
    const { user, session } = await connector.authenticateWithCode(code, { permissions: ['admin'] })

    return session.accessToken
  }
}
```

GitHub's own `GET /user` response can return a `null` email for an account with a private email
setting, even with the `user:email` scope granted, so `GitHubOAuth2Connector.getSubject()` derives
the session subject from the account's immutable numeric `id` instead — unlike
`GoogleOAuth2Connector`, whose `email` is always present. `GitHubOAuth2Connector` also overrides
`revokeToken()`: GitHub's own token-revocation endpoint (`DELETE applications/{client_id}/token`,
HTTP Basic auth with `clientId`/`clientSecret`, a JSON `{ access_token }` body) has a genuinely
different shape from the base class's generic `POST`-with-form-body implementation Google's own
revoke endpoint uses.

Configured the same way as `GoogleOAuth2Connector` — `GITHUB_OAUTH2_CLIENT_ID`/
`GITHUB_OAUTH2_CLIENT_SECRET`/`GITHUB_OAUTH2_REDIRECT_URI` plus the same set of `*_URL`/
`GITHUB_OAUTH2_RESPONSE_TYPE` overrides — see the [Configuration Guide](./configuration.md).

---

## 🔌 Adding a Custom OAuth2 Provider

`GoogleOAuth2Connector`/`GitHubOAuth2Connector` are both thin subclasses of the exported
`OAuth2Connector<TUserInfo>` base class. To support a provider that isn't already one of those two,
extend it directly — you only need to supply the endpoints, the default scope, and how to derive the
session subject from that provider's user-info shape. The example below uses placeholder URLs;
verify your provider's own real OAuth2 documentation before shipping — never assume a shape from a
similar provider, since a wrong `tokenUrl`/`userInfoUrl` fails silently as an opaque HTTP error far
from its actual cause:

```ts
import { OAuth2Connector, type OAuth2ConnectorOptions } from 'jsr:@zanix/auth@[version]'

type ExampleUserInfo = { id: string; email: string }

class ExampleOAuth2Connector extends OAuth2Connector<ExampleUserInfo> {
  constructor(options: OAuth2ConnectorOptions = {}) {
    super({
      authUrl: 'https://provider.example.com/oauth2/authorize',
      userInfoUrl: 'https://provider.example.com/oauth2/userinfo',
      revokeUrl: 'https://provider.example.com/oauth2/revoke',
      tokenUrl: 'https://provider.example.com/oauth2/token',
      defaultScope: 'profile email',
      responseType: 'code',
    }, options)
  }

  protected getSubject(user: ExampleUserInfo): string {
    return user.email
  }
}

// In the route handling the provider's redirect back, once it carries `?code=...`:
const { user, session } = await connector.authenticateWithCode(ctx, code)
```

`generateAuthUrl()`, `getUserInfo()`, `revokeToken()`, `authenticate()`, `exchangeCode()`,
`authenticateWithCode()`, and `validateCode()` all come for free from the base class — override one
only when the provider's own real contract genuinely doesn't match the generic implementation (see
`GitHubOAuth2Connector.revokeToken()` above for a real example: GitHub's revoke endpoint needs
`DELETE`, Basic auth, and a JSON body, not the `POST`-with-form-body shape the base class assumes).
Every endpoint URL/`defaultScope` can be overridden per-instance via the constructor's `options`, on
top of the subclass's own defaults.

Building your own session instead of `authenticate()`'s generic one (custom permissions, a custom
payload, your own DB writes)? `validateCode(code)` is `getUserInfo()`/`validateToken()`'s own
code-flow counterpart — it exchanges `code` and returns just the user info, no session built, so
it's a direct, one-line swap for `validateToken(token)` in that kind of flow.

**Prefer `responseType: 'code'` + `tokenUrl` + `authenticateWithCode()`**, shown above, over the
`responseType: 'token'` default + `authenticate()`. The code flow exchanges `code` for a token
server-side, using this connector's own `clientSecret` — so the token it hands off is provably
scoped to this app by construction. `authenticate()`'s own implicit-flow input has no such
guarantee: it trusts whatever bearer token it's given, verified only by the provider, never by this
app — a token issued for a different OAuth2 app registered with that same provider could be replayed
here. `OAuth2Connector` logs a warning at construction whenever a connector is left on the implicit
flow, as a reminder.

`responseType` doesn't have to be fixed for a connector's whole lifetime — `generateAuthUrl()` takes
it as a per-call option too, overriding the connector's own configured default just for that one
URL:

```ts
// One call site wants the code flow; another (or the connector's own default) can stay on
// whatever `responseType` was configured at construction — no second connector needed.
connector.generateAuthUrl({ responseType: 'code' })
```

`GoogleOAuth2Connector` additionally honors `GOOGLE_OAUTH2_RESPONSE_TYPE` and
`GOOGLE_OAUTH2_TOKEN_URL` as their own construction-time defaults — useful when the connector is
registered through `@zanix/auth/core`'s default env-driven setup, with no `options` object to pass a
default into directly. `GOOGLE_OAUTH2_TOKEN_URL` overrides Google's real token endpoint the same way
`GOOGLE_OAUTH2_AUTH_URL`/`GOOGLE_OAUTH2_USERINFO_URL`/`GOOGLE_OAUTH2_REVOKE_URL` do for their own
endpoints — rarely needed outside an enterprise proxy or a test double.

---

## 📟 OTP (One-Time Password)

Generate a short-lived numeric code, deliver it yourself (email, SMS, …), then verify it against the
session context — useful when you don't want to rely on an authenticator app:

```ts
class LoginInteractor extends ZanixInteractor {
  public async requestOtp(user: { email: string }) {
    const code = await this.providers.get('auth').otp.generate({
      target: user.email,
    })

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
A wrong guess counts against `maxAttempts` (default `5`) — once reached, the code is rejected and
removed even if it hasn't actually expired yet, so a fixed, small number of guesses is all an
attacker gets. Pass it as `otp.verify(target, code, { maxAttempts })`'s 3rd argument, or
`otp.authenticate(target, code, sessionOptions, { maxAttempts })`'s 4th.

---

## 🔒 Two-Factor Authentication (TOTP)

Enroll a user with an authenticator app (Google Authenticator, Microsoft Authenticator, etc.),
persist the secret on your own user record, then verify the codes it generates:

```ts
class TwoFactorInteractor extends ZanixInteractor {
  public enroll(user: { email: string }) {
    const totp = this.providers.get('auth').totp

    const secret = totp.generateSecret()
    const uri = totp.getProvisioningUri(secret, user.email, {
      issuer: 'MyApp',
    })

    // Render `uri` as a QR code for the user to scan, and persist `secret` yourself
    // (e.g. on the user record) — the library never stores it for you.
    return { uri }
  }

  public async verify(
    user: { email: string; totpSecret: string },
    code: string,
  ) {
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
