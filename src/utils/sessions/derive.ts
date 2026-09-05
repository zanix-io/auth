import type { DerivedSession } from 'typings/sessions.ts'
import type { AuthSessionOptions } from 'typings/auth.ts'
import type { ScopedContext, ZanixCacheProvider, ZanixKVConnector } from '@zanix/server'

import { parseTTL } from '@zanix/helpers'
import { DEFAULT_ACCESS_EXPIRATION } from 'utils/constants.ts'
import { applySessionTokens, buildAccessTokenClaims } from './create.ts'
import { defineLocalSession } from './context.ts'
import { refreshSessionTokensBase, resolveVerifiedRefreshToken } from './refresh.ts'
import { toJwtHttpError } from '../jwt/verification-error.ts'

/**
 * Derives a request's session from an already-issued refresh token — verifying it and, only when
 * it's old enough to warrant it, rotating it — without ever signing a real access token. The
 * cheaper counterpart to {@link refreshSessionTokensBase} for a caller (`pageSessionGuard`) that
 * only needs `ctx.locals.session` populated for THIS request, never a real access token string:
 * every access token {@link refreshSessionTokensBase}/`generateSessionTokens` mints is decoded once
 * for its claims and discarded in the same request regardless, so signing one here would be pure
 * overhead with nothing downstream to use it.
 *
 * ## Rotation: automatic by default, overridable
 *
 * Whether the presented refresh token gets rotated is decided by comparing its own age (`now -
 * payload.iat`) against `payload.access.accessExpiration` (the access-token lifetime chosen when
 * the session was created, defaulting to `'1h'`) — a token younger than that is reused as-is, with
 * no cache write and no new cookie; a token at least that old gets a real rotation, delegated
 * whole to {@link refreshSessionTokensBase} (single-use blocklisting, the rotation-grace window,
 * all of it, unchanged). This keeps a session that's actively browsed from rotating its refresh
 * token on every single request, while still rotating it roughly as often as an access token would
 * naturally need renewing — see `MIN_REFRESH_TO_ACCESS_RATIO` (`utils/constants.ts`) for why
 * `refreshExpiration` is required to leave enough margin for this to always land before the
 * token's own absolute expiry.
 *
 * `options.rotateRefresh` overrides that decision outright: `true` forces a rotation even for a
 * fresh token (e.g. right before a sensitive action, to invalidate any other copy of the current
 * refresh token in circulation); `false` forces reuse even for a stale one. Forcing `false`
 * repeatedly for the only call site that ever presents a given refresh token means that token's
 * absolute lifetime is never renewed by this call — it lapses at its own `exp` if nothing else
 * ever rotates it, a deliberate consequence of opting out, not a bug.
 *
 * @param ctx - The scoped context whose `locals.session` gets populated.
 * @param token - Optional refresh token to derive from. If omitted, it's read from the session
 * cookie, same as {@link refreshSessionTokensBase}.
 * @param options - Options for the blocklist/rotation-grace check, and rotation overrides.
 * @param {ZanixCacheProvider} [options.cache] - Cache provider.
 * @param {ZanixKVConnector} [options.kvDb] - Key-value store connector.
 * @param {Partial<AuthSessionOptions>} [options.sessionOptions] - Fields overriding the
 * `AuthSessionOptions` embedded in the refresh token, same as {@link refreshSessionTokensBase}.
 * @param {boolean} [options.rotateRefresh] - Forces the rotation decision instead of the automatic
 * freshness check above.
 * @returns {Promise<DerivedSession>} The refresh token now backing the session (unchanged, or
 * freshly rotated), and whether a rotation actually happened.
 *
 * @throws {HttpError} If no token was presented at all, or it isn't a refresh token.
 * @throws {PermissionDenied} If verification fails, or the token is blocklisted with no rotation-
 * grace entry to answer it.
 */
export const deriveSessionTokenBase = async (
  ctx: ScopedContext,
  token?: string,
  options: {
    cache?: ZanixCacheProvider
    kvDb?: ZanixKVConnector
    sessionOptions?: Partial<AuthSessionOptions>
    rotateRefresh?: boolean
  } = {},
): Promise<DerivedSession> => {
  const resolved = await resolveVerifiedRefreshToken(ctx, token, options)
  const { currentRefreshToken, payload } = resolved

  if (resolved.graceTokens) {
    applySessionTokens(ctx, resolved.graceTokens)
    return {
      refreshToken: resolved.graceTokens.refreshToken,
      rotated: true,
      oldToken: currentRefreshToken,
      payload,
    }
  }

  const sessionOptions: AuthSessionOptions = { ...payload.access, ...options.sessionOptions }

  const age = Math.floor(Date.now() / 1000) - (payload.iat ?? 0)
  const freshnessThreshold = parseTTL(sessionOptions.accessExpiration ?? DEFAULT_ACCESS_EXPIRATION)
  const shouldRotate = options.rotateRefresh ?? age >= freshnessThreshold

  if (!shouldRotate) {
    defineLocalSession(ctx, {
      type: 'user',
      payload: buildAccessTokenClaims(sessionOptions),
      status: 'active',
    })
    Object.assign(ctx.locals.session as object, { token: currentRefreshToken })

    return {
      refreshToken: currentRefreshToken,
      rotated: false,
      oldToken: currentRefreshToken,
      payload,
    }
  }

  // A real rotation is rare enough under this freshness check (at most once per
  // `accessExpiration` window per active session) that re-running `refreshSessionTokensBase`'s own
  // verification is negligible overhead — delegating whole to it, rather than re-implementing
  // single-use blocklisting and the rotation-grace window a second time here, is what keeps this
  // module from silently drifting out of sync with that already-hardened mechanism.
  const { refreshToken, oldToken } = await refreshSessionTokensBase(
    ctx,
    currentRefreshToken,
    options,
  )

  return { refreshToken, rotated: true, oldToken, payload }
}

/**
 * The real, exported entry point — {@link deriveSessionTokenBase}, wrapped the same way
 * `refreshSessionTokens` wraps {@link refreshSessionTokensBase}: a bare `PermissionDenied`
 * (verification failure, or a blocklisted token with no rotation-grace entry) reaches a caller as
 * `HttpError('UNAUTHORIZED')` instead of `@zanix/server`'s generic 500 default. Every other case is
 * already an `HttpError` and passes through unchanged.
 *
 * `deriveSessionTokenBase` stays the one place tested against the raw, unwrapped contract;
 * `pageSessionGuard` calls this wrapper.
 */
export const deriveSessionToken = async (
  ctx: ScopedContext,
  token?: string,
  options: {
    cache?: ZanixCacheProvider
    kvDb?: ZanixKVConnector
    sessionOptions?: Partial<AuthSessionOptions>
    rotateRefresh?: boolean
  } = {},
): Promise<DerivedSession> => {
  try {
    return await deriveSessionTokenBase(ctx, token, options)
  } catch (e) {
    toJwtHttpError(e, 'UNAUTHORIZED')
  }
}
