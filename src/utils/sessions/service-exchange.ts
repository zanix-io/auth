import { HttpError, PermissionDenied } from '@zanix/errors'
import { parseTTL } from '@zanix/helpers'
import {
  SERVICE_ASSERTION_DEFAULT_EXP,
  SERVICE_EXCHANGE_AUDIENCE,
  SERVICE_TOKEN_DEFAULT_EXP,
} from 'utils/constants.ts'
import { createJWT } from 'utils/jwt/create.ts'
import { decodeJWT } from 'utils/jwt/decode.ts'
import { verifyJWT } from 'utils/jwt/verify.ts'
import { createAppToken } from './create.ts'

/**
 * Signs a short-lived, self-signed JWT assertion a service presents to
 * {@link exchangeServiceCredential} to obtain a real `type: 'api'` access token — the
 * client-credential/assertion side of the flow described in `docs/service-credential.md`.
 *
 * The assertion proves possession of `privateKey` (the same shape as an OAuth2
 * {@link https://datatracker.ietf.org/doc/html/rfc7523 | JWT-bearer/client-assertion grant}): it
 * is signed with the service's **own** keypair, distinct from `@zanix/auth`'s own `JWK_PRI`/
 * `JWK_PUB` pair, and never leaves this call as anything other than a token to be verified —
 * `@zanix/auth` never sees or stores `privateKey` itself.
 *
 * `serviceId` is the assertion's identity — it doubles as `iss` and `sub`. `keyId` is a separate
 * concept: which of possibly several registered keys for that service this assertion is signed
 * with (the JWT header `kid`). Defaults to `serviceId` itself when omitted, which reproduces
 * today's single-key behavior exactly (resolved against the bare `JWK_PUB_<serviceId>` env var on
 * the receiving side) — pass `keyId` explicitly only once you're rotating that service's keypair
 * and need to distinguish which key signed a given assertion (see
 * {@link exchangeServiceCredential}'s "Key rotation" section for the full overlap-window flow).
 *
 * @param options.serviceId - This service's own registered identity (`iss`/`sub`).
 * @param options.privateKey - This service's own RSA private key (PEM), matching whichever public
 * key `keyId` (or, if omitted, `serviceId` itself) resolves to on the verifying side. Never
 * `@zanix/auth`'s own `JWK_PRI`.
 * @param options.keyId - Identifies which of this service's registered keys signed this assertion
 * — the JWT header `kid`. Defaults to `serviceId` (today's behavior: a single, unkeyed
 * `JWK_PUB_<serviceId>`). Pass a distinct value (e.g. `'key2'`) during key rotation, matching
 * whatever `JWK_PUB_<serviceId>_<keyId>` the receiving side has registered for it.
 * @param options.expiration - How long the assertion itself stays valid — short by design, since
 * it's presented once and immediately exchanged. Defaults to {@link SERVICE_ASSERTION_DEFAULT_EXP}.
 *
 * @returns The signed assertion (a JWT string) to send to {@link exchangeServiceCredential}.
 *
 * @example
 * ```ts
 * const assertion = await createServiceAssertion({
 *   serviceId: 'zanix-admin',
 *   privateKey: Deno.env.get('SERVICE_PRIVATE_KEY')!,
 * })
 * ```
 *
 * @example
 * Signing with a specific, rotated key:
 * ```ts
 * const assertion = await createServiceAssertion({
 *   serviceId: 'zanix-admin',
 *   privateKey: Deno.env.get('SERVICE_PRIVATE_KEY_V2')!,
 *   keyId: 'key2',
 * })
 * ```
 */
export const createServiceAssertion = (options: {
  serviceId: string
  privateKey: string
  keyId?: string
  expiration?: number | string
}): Promise<string> => {
  const { serviceId, privateKey, keyId = serviceId, expiration = SERVICE_ASSERTION_DEFAULT_EXP } =
    options

  return createJWT(
    { iss: serviceId, sub: serviceId, aud: SERVICE_EXCHANGE_AUDIENCE },
    privateKey,
    { algorithm: 'RS256', keyID: keyId, expiration },
  )
}

/** What a successful {@link exchangeServiceCredential} call returns. */
export type ServiceCredential = {
  /** The minted `type: 'api'` access token — send it as `X-Znx-Authorization: Bearer <token>`. */
  accessToken: string
  /** Seconds until `accessToken` expires — cache and reuse it until then, don't re-exchange per call. */
  expiresIn: number
  /** The identity the assertion proved, echoed back for convenience (equals its own `iss`/`sub`). */
  serviceId: string
}

/**
 * Resolves the public key registered for `serviceId`'s `keyId`, scoped so a key registered for one
 * service can never resolve for a different one, regardless of `keyId` collisions between them.
 *
 * - `keyId === serviceId` (the default `createServiceAssertion` uses when no explicit `keyId` is
 *   passed) resolves the bare `JWK_PUB_<serviceId>` — today's single-key convention, unchanged.
 * - Any other `keyId` resolves `JWK_PUB_<serviceId>_<keyId>` — the multi-key rotation convention:
 *   register as many of these as you have concurrently-valid keys for that service.
 *
 * @throws {HttpError} If nothing is registered under the resolved env var name.
 */
function resolveServiceAssertionKey(serviceId: string, keyId: string): string {
  const keyName = keyId === serviceId ? `JWK_PUB_${serviceId}` : `JWK_PUB_${serviceId}_${keyId}`
  const secret = Deno.env.get(keyName)

  if (secret) return secret

  throw new HttpError('INTERNAL_SERVER_ERROR', {
    message: 'An error occurred during service-credential authentication.',
    cause: `Missing required JWK public key in environment variables: ${keyName}.`,
    meta: { source: 'zanix', method: 'exchangeServiceCredential', serviceId, keyId },
  })
}

/**
 * Verifies a service's self-signed assertion (see {@link createServiceAssertion}) and, if valid,
 * mints a real `type: 'api'` access token for it via the existing {@link createAppToken}
 * primitive — reused as-is, not reinvented. See `docs/service-credential.md`.
 *
 * This function only implements the verify-and-issue step — it does not expose an HTTP endpoint
 * itself. A consuming app wires it into its own route the same way `@zanix/core` wires
 * `TemplatesAdminRepository`/`Service` into its own controller: e.g. a single `@Post()` handler
 * that reads `{ assertion }` from the request body and returns this function's result as-is.
 *
 * ## Trust boundary
 * A service is only ever granted a token if a matching `JWK_PUB_<serviceId>`/
 * `JWK_PUB_<serviceId>_<keyId>` is set — there is no dynamic self-registration; whoever runs this
 * process decides which services (and which of their keys) it trusts by setting that env var per
 * service, the same static-config-first principle already used for `zanix-admin`'s own service
 * registry. Granted permissions come **only** from `SERVICE_PERMISSIONS_<serviceId>` (a
 * comma-separated list), never from anything the caller sends — an assertion only ever proves
 * identity, it never gets to request its own privileges.
 *
 * ## Rate limiting — consistent with `type: 'user'` sessions
 * `rateLimitGuard` (see `jwt-validation.guard.ts`) reads `session.rateLimit` off the JWT the exact
 * same way for `api` and `user` sessions — there is no type-specific branch anywhere in it. The
 * minted token's `rateLimit` claim comes from `SERVICE_RATE_LIMIT_<serviceId>` (a plain number, or
 * a `RATE_LIMIT_PLANS` index — see `rateLimitGuard`'s own JSDoc for that distinction) when set,
 * falling back to {@link createAppToken}'s own default (`100`) otherwise — the same default a
 * `type: 'user'` session gets from `generateSessionTokens` when its caller doesn't pass one either.
 * Like permissions, this is operator-configured per `serviceId`, never requested by the caller.
 *
 * ## Key rotation, with a real overlap window
 * A calling service's own key (unlike `@zanix/auth`'s own `JWK_PRI`/`JWK_PUB`, which already
 * rotated via versioned env vars) now rotates the same way, via `keyId`:
 *
 * 1. **Steady state** — one key registered: `JWK_PUB_<serviceId>_key1`. The service signs every
 *    assertion with `keyId: 'key1'`.
 * 2. **Prepare rotation** — register the new key **alongside** the old one, don't replace it yet:
 *    `JWK_PUB_<serviceId>_key1` (old) and `JWK_PUB_<serviceId>_key2` (new) both set. Both keys
 *    verify successfully during this window — no downtime, no deploy-ordering requirement.
 *    Registering (or later removing) `_key1` and `_key2` never touches the other: adding a `kid`
 *    this function has never seen doesn't retroactively invalidate assertions signed under a `kid`
 *    it already trusted, and vice versa.
 * 3. **Switch signing** — the calling service starts signing with `keyId: 'key2'` instead. Both
 *    old (in-flight, already-signed) and new assertions verify successfully throughout.
 * 4. **Retire the old key** — once you're certain no assertion signed with `key1` can still be
 *    in flight (past {@link createServiceAssertion}'s own `expiration`, default
 *    {@link SERVICE_ASSERTION_DEFAULT_EXP}), remove `JWK_PUB_<serviceId>_key1`.
 *
 * `keyId` only ever selects *which key verifies the assertion* — it never affects identity (`iss`/
 * `sub`, always `serviceId`) or the granted permissions/rate limit (always
 * `SERVICE_PERMISSIONS_<serviceId>`/`SERVICE_RATE_LIMIT_<serviceId>`, keyed by `serviceId` alone).
 * A key registered under one `serviceId` can never be used to authenticate as a different one,
 * regardless of `keyId` — see {@link resolveServiceAssertionKey}.
 *
 * This is independent of, and doesn't affect, **already-minted access tokens**: those are signed
 * with `@zanix/auth`'s own `JWK_PRI` (via {@link createAppToken}, unchanged by anything above) and
 * stay valid for their own lifetime regardless of what happens to the calling service's keypair
 * afterward — rotating (or even fully revoking) a service's assertion-signing key does not
 * invalidate any `type: 'api'` session it already obtained.
 *
 * @param assertion - The signed JWT assertion from {@link createServiceAssertion}.
 * @param options.expiration - Lifetime of the minted access token. Defaults to
 * {@link SERVICE_TOKEN_DEFAULT_EXP}.
 *
 * @throws {PermissionDenied} If the assertion is malformed, missing a `kid`/`iss`, has a `sub` that
 * doesn't match its own `iss`, has an invalid signature, is expired, or targets the wrong `aud`.
 * @throws {HttpError} If no matching `JWK_PUB_<serviceId>`/`JWK_PUB_<serviceId>_<keyId>` is
 * configured for the claimed service/key — see {@link resolveServiceAssertionKey}.
 *
 * @returns The minted {@link ServiceCredential}.
 *
 * @example
 * ```ts
 * @Post('service-token', { Body: ServiceExchangeRTO })
 * public async exchange(ctx: HandlerContext<{ body: ServiceExchangeRTO }>) {
 *   return exchangeServiceCredential(ctx.payload.body.assertion)
 * }
 * ```
 */
export const exchangeServiceCredential = async (
  assertion: string,
  options: { expiration?: number | string } = {},
): Promise<ServiceCredential> => {
  const { header, payload } = decodeJWT(assertion)
  const keyId = header.kid
  const serviceId = payload.iss

  if (!keyId || !serviceId || payload.sub !== serviceId) {
    throw new PermissionDenied(
      'The provided assertion does not identify a valid service.',
      {
        code: 'INVALID_SERVICE_ASSERTION',
        cause: 'The assertion is missing a `kid`/`iss`, or its `sub` does not match its own `iss`.',
        meta: { source: 'zanix', method: 'exchangeServiceCredential' },
      },
    )
  }

  const secret = resolveServiceAssertionKey(serviceId, keyId)

  await verifyJWT(assertion, atob(secret), {
    algorithm: 'RS256',
    iss: serviceId,
    sub: serviceId,
    aud: SERVICE_EXCHANGE_AUDIENCE,
  })

  const permissions = Deno.env.get(`SERVICE_PERMISSIONS_${serviceId}`)
    ?.split(',')
    .map((permission) => permission.trim())
    .filter(Boolean)

  const rawRateLimit = Deno.env.get(`SERVICE_RATE_LIMIT_${serviceId}`)
  const rateLimit = rawRateLimit ? Number(rawRateLimit) : undefined

  const expiration = options.expiration ?? SERVICE_TOKEN_DEFAULT_EXP
  const accessToken = await createAppToken({
    type: 'api',
    subject: serviceId,
    expiration,
    payload: (permissions?.length || rateLimit !== undefined)
      ? { permissions, rateLimit }
      : undefined,
  })

  return { accessToken, expiresIn: parseTTL(expiration), serviceId }
}
