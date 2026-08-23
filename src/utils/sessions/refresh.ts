import type { SessionTokens } from 'typings/sessions.ts'
import type { JWTPayload } from 'typings/jwt.ts'

import {
  type ScopedContext,
  SESSION_HEADERS,
  type ZanixCacheProvider,
  type ZanixKVConnector,
} from '@zanix/server'
import { HttpError, PermissionDenied } from '@zanix/errors'
import { addTokenToBlockListBase, checkTokenBlockList } from './block-list.ts'
import { getSecretByToken } from '../jwt/secrets.ts'
import { generateSessionTokens } from './create.ts'
import { invalidRefreshTokenError } from './errors.ts'
import { verifyJWT } from '../jwt/verify.ts'
import { toJwtHttpError } from '../jwt/verification-error.ts'

/**
 * Refreshes the session tokens using the provided JWT.
 *
 * Verifies the given refresh token, then generates a new set of session tokens based on the
 * access data embedded in its payload. When `options.cache` is provided, the consumed refresh
 * token is blocklisted as part of this same call (single-use rotation) — a later attempt to
 * refresh with that same token is then rejected as blocklisted, the mechanism that also catches a
 * stolen token being replayed after the legitimate client already rotated past it.
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
 * @returns {Promise<SessionTokens & { oldToken: string, payload: JWTPayload }>>}
 *   A promise that resolves with the newly generated session tokens and de older one.
 */
export const refreshSessionTokensBase = async (
  ctx: ScopedContext,
  token?: string,
  options: {
    cache?: ZanixCacheProvider
    kvDb?: ZanixKVConnector
  } = {},
): Promise<SessionTokens & { oldToken: string; payload: JWTPayload }> => {
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

  // Check token in block list. This is also what catches REUSE of an already-rotated token: a
  // successful refresh below always blocklists the token it consumed, so presenting that same
  // token again — e.g. a stolen cookie replayed after the legitimate client already refreshed —
  // lands here and is rejected, not silently accepted.
  //
  // Gated on `cache` alone, same as the blocklist write below — `checkTokenBlockList`'s `kvDb` is
  // optional (a fallback for the non-Redis path only; the Redis path never touches it), so
  // requiring it here would skip the check for a caller who wired `cache` (with Redis) but not
  // `kvDb`, even though the write below would still succeed and reuse would go undetected.
  if (options.cache) {
    const isInBlockList = await checkTokenBlockList(
      payload.jti,
      options.cache,
      options.kvDb,
    )

    if (isInBlockList) {
      throw new PermissionDenied(
        'The refresh token has been revoked or is blocklisted.',
      )
    }
  }

  const tokens = await generateSessionTokens(ctx, payload.access)

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
  } = {},
): Promise<SessionTokens & { oldToken: string; payload: JWTPayload }> => {
  try {
    return await refreshSessionTokensBase(ctx, token, options)
  } catch (e) {
    toJwtHttpError(e, 'UNAUTHORIZED')
  }
}
