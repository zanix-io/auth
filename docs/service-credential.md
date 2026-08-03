# 🤝 Service-Credential Exchange

Machine-to-machine authentication for a service calling another service's API — no shared secret, no
human-shaped session borrowed as a stopgap.

A calling service proves its identity with a short-lived, self-signed JWT assertion (signed with its
**own** keypair, distinct from `@zanix/auth`'s own `JWK_PRI`/`JWK_PUB` pair), and exchanges it for a
real `type: 'api'` access token — the same kind of token `@AuthTokenValidation({ type: 'api' })`
already accepts everywhere else.

---

## 📋 Table of Contents

1. [Basic Usage](#-basic-usage)
2. [Registering a Trusted Service](#-registering-a-trusted-service)
3. [Permissions and Rate Limiting](#-permissions-and-rate-limiting)
4. [Mounting the Exchange Endpoint](#-mounting-the-exchange-endpoint)
5. [Rotating a Service's Key](#-rotating-a-services-key)
6. [Security Considerations](#-security-considerations)
7. [API Reference](#-api-reference)
8. [See also](#see-also)

---

## 🚀 Basic Usage

**Calling service** — signs an assertion with its own private key:

```ts
import { createServiceAssertion } from 'jsr:@zanix/auth'

// `privateKey` omitted — resolves JWK_PRI_zanix-admin automatically (see below).
const assertion = await createServiceAssertion({ serviceId: 'zanix-admin' })
```

> ℹ️ **There is no separate private-key parameter to pass by default.** Omitting `privateKey`
> resolves `JWK_PRI_<serviceId>` (or `JWK_PRI_<serviceId>_<keyId>` once `keyId` picks a specific key
> — see [Rotating a Service's Key](#-rotating-a-services-key)) automatically, the exact mirror image
> of how the _receiving_ side already resolves `JWK_PUB_<serviceId>`/ `JWK_PUB_<serviceId>_<keyId>`
> (see [Registering a Trusted Service](#-registering-a-trusted-service) below) — one naming
> convention for both directions. `resolveServiceAssertionPrivateKey(serviceId,
> keyId)` is
> exported directly if you want to check resolvability yourself (e.g. to fail fast at boot, before
> any real signing attempt — see `@zanix/notifications`'s `assertTemplatesConfigNotConflicting()`
> for a real example of this). Pass `privateKey` explicitly only when you're reading it from
> somewhere other than an env var (a secrets manager, a config file):
>
> ```ts
> const assertion = await createServiceAssertion({
>   serviceId: 'zanix-admin',
>   privateKey: await mySecretsManager.get('zanix-admin-signing-key'), // base64-encoded PEM
> })
> ```
>
> Either way, the value is **base64-encoded**, the same convention `JWK_PRI`/`JWK_PUB_<serviceId>`
> already use everywhere else in this package — `createServiceAssertion` decodes it internally
> before signing. Generate a keypair with `generateRSAKeys()` (from `@zanix/helpers`) and store
> `btoa(privateKey)` (not the raw multi-line PEM) — a raw PEM contains characters (`-`, newlines)
> that aren't valid base64 and fails to decode.
>
> **Only PKCS#8 private keys are supported** (`-----BEGIN PRIVATE KEY-----`) — the underlying
> `crypto.subtle.importKey` call always imports with `format: 'pkcs8'`. A PKCS#1 key
> (`-----BEGIN RSA PRIVATE KEY-----`, e.g. from `openssl genrsa`) fails to import.
> `generateRSAKeys()` already produces PKCS#8; convert an existing PKCS#1 key with
> `openssl pkcs8 -topk8 -nocrypt -in old.pem -out new.pem`. The matching public key
> (`JWK_PUB_<serviceId>`) must be SPKI (`-----BEGIN PUBLIC KEY-----`), which is what
> `generateRSAKeys()`/`openssl rsa -pubout` produce by default.

**Receiving service** — verifies the assertion and mints a real access token:

```ts
import { exchangeServiceCredential } from 'jsr:@zanix/auth'

const credential = await exchangeServiceCredential(assertion)
// { accessToken, expiresIn, serviceId }
```

`credential.accessToken` is sent back to the calling service, which then uses it exactly like any
other `type: 'api'` session:

```ts
fetch(url, { headers: { 'X-Znx-Authorization': `Bearer ${credential.accessToken}` } })
```

---

## 🔑 Registering a Trusted Service

There is no dynamic self-registration — a service is only ever granted a token if the receiving side
has explicitly registered its public key. The simplest form is a single, unkeyed key per service:

```env
JWK_PUB_zanix-admin=<base64-encoded PEM public key>
```

This reuses the exact same `JWK_PUB_<kid>` convention `getSecretByToken` already resolves for any
`type: 'api'` token — no new registry concept. `serviceId` doubles as the assertion's `iss` and
`sub`, so a valid signature alone can never be presented as a different service's identity:
`exchangeServiceCredential` requires `sub` to equal the same `serviceId` as `iss`.

If a service needs to rotate its own keypair with a real overlap window (no downtime, no
deploy-ordering requirement), register multiple keys instead by giving each one its own `keyId`
suffix:

```env
JWK_PUB_zanix-admin_key1=<base64-encoded PEM public key — current>
JWK_PUB_zanix-admin_key2=<base64-encoded PEM public key — incoming>
```

Pass the matching `keyId` when signing on the calling side. With `privateKey` omitted (the default —
see [Basic Usage](#-basic-usage)), `keyId` alone is enough: it also selects
`JWK_PRI_zanix-admin_key1`/ `JWK_PRI_zanix-admin_key2` on the signing side automatically, so
rotating later (see below) is a config change (which `JWK_PRI_...`/`JWK_PUB_...` pair is registered,
and which `keyId` you pass) plus a restart/redeploy, never a code change:

```ts
const assertion = await createServiceAssertion({
  serviceId: 'zanix-admin',
  keyId: Deno.env.get('SERVICE_KEY_ID')!, // e.g. 'key1' or 'key2'
})
```

`keyId` only selects _which_ registered key verifies the assertion — it never affects identity
(`iss`/`sub` are always `serviceId`) or the permissions/rate limit granted (always keyed by
`serviceId` alone, never by `keyId`). A key registered under one `serviceId` can never authenticate
as a different one, regardless of `keyId` — the lookup is always scoped by `serviceId` first. See
[Rotating a Service's Key](#-rotating-a-services-key) below for the full procedure.

---

## 🔐 Permissions and Rate Limiting

Granted permissions and rate limits come **only** from operator-configured environment variables —
never from anything the calling service requests in its assertion:

```env
SERVICE_PERMISSIONS_zanix-admin=ADMIN_ROLE,ADMIN_TRIGGERS_ROLE
SERVICE_RATE_LIMIT_zanix-admin=500
```

| Variable                          | Effect                                                                                                                                                               |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SERVICE_PERMISSIONS_<serviceId>` | Comma-separated list, set as the minted token's `permissions` claim.                                                                                                 |
| `SERVICE_RATE_LIMIT_<serviceId>`  | Sets the minted token's `rateLimit` claim. Falls back to `createAppToken`'s default (`100`), same as a `type: 'user'` session gets when its caller doesn't pass one. |

`rateLimitGuard` reads `session.rateLimit` off the JWT identically for `api` and `user` sessions —
there is no type-specific branch — so this keeps the two paths fully consistent.

---

## 🔌 Mounting the Exchange Endpoint

`exchangeServiceCredential` is exported as a plain function, not a mounted route — a consuming app
wires its own single handler around it:

```ts
@Post('service-token', { Body: ServiceExchangeRTO })
public exchange(ctx: HandlerContext<{ body: ServiceExchangeRTO }>) {
  return exchangeServiceCredential(ctx.payload.body.assertion)
}
```

No role gate belongs on this route — the caller has no session yet at the point it's calling this
endpoint; trust is established entirely by `exchangeServiceCredential`'s own verification against
`JWK_PUB_<serviceId>`. `@zanix/core` ships a ready-made version of exactly this at
`/admin/service-token` — see its README's "Admin APIs" section — reuse that instead of
re-implementing this handler if your app is already `@zanix/core`-based.

---

## 🔄 Rotating a Service's Key

Unlike the single, unkeyed `JWK_PUB_<serviceId>` form, the `_<keyId>`-suffixed form supports a real
overlap window — both the old and new keys are registered and verify successfully at the same time,
so there's no deploy-ordering requirement and no window where an in-flight assertion gets rejected.
The example below assumes the calling service reads `keyId` from its own config and leaves
`privateKey` omitted (so `JWK_PRI_<serviceId>_<keyId>` resolves automatically — the default, see
[Basic Usage](#-basic-usage)); under that setup, switching keys is a config change, not a code
change.

1. **Register the new key pair alongside the still-active one** — on the receiving side,
   `JWK_PUB_<serviceId>_key2` next to `JWK_PUB_<serviceId>_key1`; on the calling service's own side,
   `JWK_PRI_<serviceId>_key2` next to `JWK_PRI_<serviceId>_key1`. Both accept/can sign with either
   at this point; nothing on the calling service needs to switch yet:

   ```env
   # Receiving side
   JWK_PUB_zanix-admin_key1=<old public key>
   JWK_PUB_zanix-admin_key2=<new public key>

   # Calling side
   JWK_PRI_zanix-admin_key1=<old private key, base64-encoded PEM>
   JWK_PRI_zanix-admin_key2=<new private key, base64-encoded PEM>
   ```

2. **Switch the calling service's own `keyId` config, then restart/redeploy it** — no code change:

   ```diff
     # Before
   - SERVICE_KEY_ID=key1
     # After
   + SERVICE_KEY_ID=key2
   ```

   Any assertion still in flight, signed with `key1` before the restart, keeps verifying throughout
   the rollout — there's no requirement that every instance switch atomically.
3. **Wait past the max assertion expiration** — once you're certain no assertion signed with `key1`
   can still be in flight (past `createServiceAssertion`'s own `expiration`, `2m` by default), it's
   safe to move on.
4. **Remove the old key** — delete `JWK_PUB_<serviceId>_key1`. Assertions signed with it now fail;
   `key2` is unaffected.

This only rotates the calling service's own assertion-signing key. It has no effect on
already-minted access tokens: those are signed with `@zanix/auth`'s own `JWK_PRI` (a separate
mechanism — see [Configuration → Key Rotation](./configuration.md#-key-rotation)) and stay valid for
their own lifetime regardless of what happens to the calling service's keypair afterward.

---

## 🛡️ Security Considerations

- **The assertion is short-lived by design** (`createServiceAssertion`'s `expiration` defaults to
  `2m`) — it's presented once and immediately exchanged, so a leaked assertion has a very small
  window of validity.
- **The minted access token's lifetime is independent** (`exchangeServiceCredential`'s `expiration`
  defaults to `30m`) — cache and reuse it until it expires; don't re-exchange per call.
- **`JWK_PRI` here is never `@zanix/auth`'s own signing key.** `createServiceAssertion`'s
  `privateKey` is the calling service's own keypair — `@zanix/auth` never sees or stores it.
- **No refresh-token concept exists for `type: 'api'` sessions.** `SESSION_HEADERS.api.token` stays
  `undefined` on purpose — there's nothing for it to carry under this design.
- **Both keys involved rotate independently, each with its own overlap window.** The minted access
  token rides on `@zanix/auth`'s own `JWK_PRI`/`JWK_PUB` rotation unchanged (see
  [Configuration → Key Rotation](./configuration.md#-key-rotation)). The **calling service's own
  key** rotates via the `JWK_PUB_<serviceId>_<keyId>` form and `keyId` — see
  [Rotating a Service's Key](#-rotating-a-services-key) — with the same no-downtime guarantee. The
  two are entirely independent: rotating a calling service's assertion-signing key never invalidates
  an access token it already minted, and vice versa.
- **A key registered under one `serviceId` can never authenticate as a different one.** The lookup
  is always scoped by `serviceId` first, then `keyId` — a `keyId` collision between two services
  (e.g. both happening to use `key1`) can never cross-resolve, since each is namespaced under its
  own `JWK_PUB_<serviceId>_...` prefix.

---

## 📚 API Reference

### `createServiceAssertion(options)`

```ts
createServiceAssertion(options: {
  serviceId: string
  privateKey?: string
  keyId?: string
  expiration?: number | string
}): Promise<string>
```

| Option       | Description                                                                                                                                                                                                                                                                                                                                                                           |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `serviceId`  | This service's own registered identity — the assertion's `iss`/`sub`.                                                                                                                                                                                                                                                                                                                 |
| `privateKey` | **Optional.** This service's own RSA private key, **base64-encoded**, **PKCS#8 only** (same convention as `JWK_PRI`/`JWK_PUB_<serviceId>`), matching whichever public key `keyId` resolves to. Never `@zanix/auth`'s own `JWK_PRI`. Omitted, resolves `JWK_PRI_<serviceId>`/`JWK_PRI_<serviceId>_<keyId>` automatically — see the note above and `resolveServiceAssertionPrivateKey`. |
| `keyId`      | Which registered key signed this assertion (the JWT header `kid`). Defaults to `serviceId` — the bare `JWK_PUB_<serviceId>`/`JWK_PRI_<serviceId>` form. Pass explicitly to use the `_<keyId>`-suffixed form instead (see [Rotating a Service's Key](#-rotating-a-services-key)).                                                                                                      |
| `expiration` | How long the assertion itself stays valid. Defaults to `2m`.                                                                                                                                                                                                                                                                                                                          |

---

### `resolveServiceAssertionPrivateKey(serviceId, keyId)`

```ts
resolveServiceAssertionPrivateKey(serviceId: string, keyId: string): string
```

Resolves `JWK_PRI_<serviceId>` (`keyId === serviceId`) or `JWK_PRI_<serviceId>_<keyId>` otherwise —
the exact mirror image of how the _receiving_ side resolves `JWK_PUB_<serviceId>`/
`JWK_PUB_<serviceId>_<keyId>`. Used internally by `createServiceAssertion` whenever `privateKey` is
omitted; exported so a consumer that wants to validate its own config upfront (before any real
signing attempt) can check resolvability without reimplementing this naming rule itself.

@throws `InternalError` if nothing is registered under the resolved env var name.

Returns the signed assertion (a JWT string) to send to `exchangeServiceCredential`.

---

### `exchangeServiceCredential(assertion, options?)`

```ts
exchangeServiceCredential(
  assertion: string,
  options?: { expiration?: number | string },
): Promise<ServiceCredential>
```

Verifies the assertion (malformed, missing `kid`/`iss`, mismatched `iss`/`sub`, invalid signature,
expired, or wrong audience all throw `PermissionDenied`; an unregistered `serviceId`/`keyId` throws
`HttpError`) and mints a real `type: 'api'` access token via the existing `createAppToken`.

| Option       | Description                                             |
| ------------ | ------------------------------------------------------- |
| `expiration` | Lifetime of the minted access token. Defaults to `30m`. |

---

### `ServiceCredential`

```ts
type ServiceCredential = {
  accessToken: string
  expiresIn: number
  serviceId: string
}
```

| Field         | Description                                                                     |
| ------------- | ------------------------------------------------------------------------------- |
| `accessToken` | The minted `type: 'api'` token — send as `X-Znx-Authorization: Bearer <token>`. |
| `expiresIn`   | Seconds until `accessToken` expires.                                            |
| `serviceId`   | The identity the assertion proved, echoed back for convenience.                 |

---

## See also

- [Configuration Guide](./configuration.md) — JWK key rotation, other environment variables.
- [IP Allowlisting Guide](./network.md) — an additional network-level layer worth combining with
  service-to-service calls.
