import type { SessionTokens } from 'typings/sessions.ts'
import type { JWTPayload } from 'typings/jwt.ts'
import type { AuthSessionOptions } from 'typings/auth.ts'

import {
  type ScopedContext,
  SESSION_HEADERS,
  type ZanixCacheProvider,
  type ZanixKVConnector,
} from '@zanix/server'
import { HttpError, PermissionDenied } from '@zanix/errors'
import {
  addTokenToBlockListBase,
  checkTokenBlockList,
  getRotationGraceTokens,
  setRotationGraceTokens,
} from './block-list.ts'
import { getSecretByToken } from '../jwt/secrets.ts'
import { applySessionTokens, generateSessionTokens } from './create.ts'
import { invalidRefreshTokenError } from './errors.ts'
import { verifyJWT } from '../jwt/verify.ts'
import { toJwtHttpError } from '../jwt/verification-error.ts'

/**
 * A presented refresh token that resolved to an already-rotated pair still sitting in its
 * rotation-grace window (see {@link resolveVerifiedRefreshToken}'s own doc) — the caller hands
 * this pair back to its own caller as-is, exactly like a freshly rotated one.
 */
type GraceHit = { graceTokens: SessionTokens; currentRefreshToken: string; payload: JWTPayload }

/** A presented refresh token that verified cleanly and isn't blocklisted — free to reuse or rotate. */
type VerifiedMiss = { graceTokens: undefined; currentRefreshToken: string; payload: JWTPayload }

/**
 * Resolves and verifies the refresh token a caller presented (from `token`, or the session cookie
 * when omitted), shared by {@link refreshSessionTokensBase} and `deriveSessionTokenBase`
 * (`utils/sessions/derive.ts`) — both need the identical signature/blocklist/grace-window handling
 * before diverging on what happens next (a full rotation vs. a cheaper claims-only derivation).
 *
 * Checking the blocklist and, on a hit, the rotation-grace cache is gated on `options.cache` alone
 * — see {@link refreshSessionTokensBase}'s own doc for why requiring `options.kvDb` too would skip
 * this check for a caller who wired `cache` (with Redis) but not `kvDb`.
 *
 * @throws {HttpError} If no token was presented at all.
 * @throws {HttpError} If the presented token isn't a refresh token (no embedded `payload.access`).
 * @throws {PermissionDenied} If verification fails, or the token is blocklisted with no rotation-
 * grace entry to answer it (a genuine reuse, not a near-simultaneous legitimate retry).
 */
export async function resolveVerifiedRefreshToken(
  ctx: ScopedContext,
  token: string | undefined,
  options: { cache?: ZanixCacheProvider; kvDb?: ZanixKVConnector },
): Promise<GraceHit | VerifiedMiss> {
  const { token: tokenHeader } = SESSION_HEADERS['user']

  const currentRefreshToken = token || ctx.cookies[tokenHeader]

  const { metaError, error } = invalidRefreshTokenError('refreshSessionTokens')

  if (!currentRefreshToken) throw error

  const secret = getSecretByToken(currentRefreshToken)

  const payload = await verifyJWT(currentRefreshToken, secret)

  if (!payload.access) {
    throw new HttpError('FORBIDDEN', {
      code: 'INVALID_TOKEN',
      cause: 'The provided refresh token is invalid. It appears to be an access token.',
      meta: metaError,
    })
  }

  if (options.cache) {
    const isInBlockList = await checkTokenBlockList(
      payload.jti,
      options.cache,
      options.kvDb,
    )

    if (isInBlockList) {
      const graceTokens = await getRotationGraceTokens(payload.jti, options.cache, options.kvDb)

      if (graceTokens) return { graceTokens, currentRefreshToken, payload }

      throw new PermissionDenied(
        'The refresh token has been revoked or is blocklisted.',
      )
    }
  }

  return { graceTokens: undefined, currentRefreshToken, payload }
}

/**
 * Refreshes the session tokens using the provided JWT.
 *
 * Verifies the given refresh token, then generates a new set of session tokens based on the
 * access data embedded in its payload — merged with `options.sessionOptions`, when given, so a
 * caller can re-resolve fields like `permissions` (e.g. after a role change) instead of reusing
 * whatever was true at the original login. When `options.cache` is provided, the consumed refresh
 * token is blocklisted as part of this same call (single-use rotation) — a later attempt to
 * refresh with that same token is then rejected as blocklisted, the mechanism that also catches a
 * stolen token being replayed after the legitimate client already rotated past it.
 *
 * A presented token that's already blocklisted isn't rejected outright: within the rotation grace
 * window ({@link ROTATION_GRACE_WINDOW_ENV} in `utils/constants.ts`, default `5s`), the token this
 * call already rotated it into is looked up (`getRotationGraceTokens`) and returned again instead —
 * the tolerance a second, legitimately near-simultaneous request needs (a browser prefetching a
 * link on hover and then navigating it, a double click, two tabs on one session) without weakening
 * reuse detection past that short window.
 *
 * @param {ScopedContext} ctx
 *   The scoped context containing configuration and services required
 *   for token generation.
 *
 * @param {string} [token]
 *   Optional refresh token to verify. If omitted, the token will be retrieved
 *   from the current context, provided cookies are available.
 *
 * @param options - Options for check block list validation
 * @param {ZanixCacheProvider} [options.cache] - Cache provider.
 * @param {ZanixKVConnector} [options.kvDb] - Key-value store connector.
 * @param {Partial<AuthSessionOptions>} [options.sessionOptions] - Fields overriding the
 *   `AuthSessionOptions` originally embedded in the refresh token (e.g. freshly resolved
 *   `permissions`), shallow-merged over it before the new tokens are generated.
 * @returns {Promise<SessionTokens & { oldToken: string, payload: JWTPayload }>>}
 *   A promise that resolves with the newly generated session tokens and de older one.
 */
export const refreshSessionTokensBase = async (
  ctx: ScopedContext,
  token?: string,
  options: {
    cache?: ZanixCacheProvider
    kvDb?: ZanixKVConnector
    sessionOptions?: Partial<AuthSessionOptions>
  } = {},
): Promise<SessionTokens & { oldToken: string; payload: JWTPayload }> => {
  const resolved = await resolveVerifiedRefreshToken(ctx, token, options)
  const { currentRefreshToken, payload } = resolved

  if (resolved.graceTokens) {
    // `generateSessionTokens` never ran for THIS request, so `ctx.locals.session` — what every
    // downstream permission check/response interceptor actually reads — is still populated from
    // THIS pair, same as a freshly minted one would.
    applySessionTokens(ctx, resolved.graceTokens)
    return { ...resolved.graceTokens, oldToken: currentRefreshToken, payload }
  }

  const tokens = await generateSessionTokens(ctx, { ...payload.access, ...options.sessionOptions })

  // Rotate: a refresh token is single-use. Blocklisting the one just consumed — AFTER the new
  // tokens are safely generated, so a transient blocklist-write failure never strands the caller
  // without a successor — is what makes the check above actually catch reuse. Without this, the
  // same refresh token would stay valid indefinitely (up to its own `exp`): anyone who ever
  // captured it once (a leaked log line, a stolen cookie) could keep minting new sessions from it
  // forever, long after the legitimate client moved on to its rotated successor.
  //
  // Omitting `cache` entirely (no blocklist infra wired at all) means no rotation happens here —
  // the token this call issued stays live until its own `exp`; this is a real, deliberate
  // tradeoff for callers that don't have blocklist infra, not a silent gap.
  if (options.cache) {
    // Written BEFORE the blocklist entry below, not after — a concurrent request can only ever
    // observe this token as blocklisted once its grace entry already exists to answer it, closing
    // the window where that request would otherwise see "blocklisted" but find no grace entry yet
    // and get rejected regardless.
    await setRotationGraceTokens(payload.jti, tokens, options.cache, options.kvDb)
    await addTokenToBlockListBase(currentRefreshToken, options.cache, options.kvDb)
  }

  return { ...tokens, oldToken: currentRefreshToken, payload }
}

/**
 * The real, exported entry point — {@link refreshSessionTokensBase}, wrapped so its own
 * `getSecretByToken`/`verifyJWT` verification failures and its blocklisted-token check (both bare
 * `PermissionDenied`, no HTTP status of their own — see `toJwtHttpError`'s own doc) reach a caller
 * as `HttpError('UNAUTHORIZED')`, the same "you need to re-authenticate" status this function's own
 * missing-token/non-refresh-token cases already use, instead of falling through to
 * `@zanix/server`'s generic 500 default. Every other case (`invalidRefreshTokenError`, the
 * `!payload.access` check) is already an `HttpError` and passes through unchanged — only a bare
 * `PermissionDenied` gets normalized here.
 *
 * `refreshSessionTokensBase` stays the one place tested against the raw, unwrapped contract
 * (`@zanix/auth`'s own unit suite); reach for it directly only from a non-HTTP context that wants
 * the bare `PermissionDenied` instead. `ZanixAuthProvider`'s own `session.refreshTokens()` calls
 * THIS wrapper — a consumer building its own `/auth/refresh` endpoint around either one gets the
 * same safety `exchangeServiceCredential` already guarantees for credential exchange.
 */
export const refreshSessionTokens = async (
  ctx: ScopedContext,
  token?: string,
  options: {
    cache?: ZanixCacheProvider
    kvDb?: ZanixKVConnector
    sessionOptions?: Partial<AuthSessionOptions>
  } = {},
): Promise<SessionTokens & { oldToken: string; payload: JWTPayload }> => {
  try {
    return await refreshSessionTokensBase(ctx, token, options)
  } catch (e) {
    toJwtHttpError(e, 'UNAUTHORIZED')
  }
}
