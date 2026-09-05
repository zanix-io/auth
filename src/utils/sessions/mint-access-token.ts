import type { JWTPayload } from 'typings/jwt.ts'
import type { ScopedContext, ZanixCacheProvider, ZanixKVConnector } from '@zanix/server'

import { DEFAULT_ACCESS_EXPIRATION } from 'utils/constants.ts'
import { applySessionTokens, createAccessToken, toAccessTokenPayload } from './create.ts'
import { resolveVerifiedRefreshToken } from './refresh.ts'
import { toJwtHttpError } from '../jwt/verification-error.ts'

/**
 * The result of {@link mintAccessTokenBase} — a real, signed access token derived from an
 * already-issued refresh token.
 */
export type MintedAccessToken = {
  /** A real, signed access token — safe to use as an `Authorization: Bearer` credential. */
  accessToken: string
  /** The presented refresh token's own decoded payload. */
  payload: JWTPayload
}

/**
 * Verifies a presented refresh token and mints a real access token from it — without ever
 * rotating, blocklisting, or replacing the refresh token itself. For a caller that needs to act ON
 * BEHALF OF the current session (e.g. an SSR-side handler relaying a request to an external Zanix
 * service as `Authorization: Bearer`) but has no business deciding whether THIS session's refresh
 * token should rotate — that decision belongs to whatever already gates the surrounding page/route
 * (`pageSessionGuard`/`deriveSessionToken`), not to every downstream action that happens to need an
 * access token along the way.
 *
 * Unlike {@link deriveSessionTokenBase} (`utils/sessions/derive.ts`), this always signs a real
 * access token, never a claims-only stand-in — the entire point of calling this is a credential
 * that actually leaves the process. Unlike {@link refreshSessionTokensBase}, it never touches the
 * refresh token at all: no replacement minted, nothing blocklisted, nothing written to the
 * rotation-grace cache.
 *
 * A presented token already sitting in another rotation's grace window (rotated by a concurrent
 * request moments earlier — see {@link resolveVerifiedRefreshToken}'s own doc) hands back that
 * real access token as-is instead of minting a redundant one; the caller never needs to know or
 * branch on which case happened.
 *
 * @param ctx - The scoped context whose `locals.session` gets populated (via
 * {@link createAccessToken}/{@link applySessionTokens}), same as any other session-derivation
 * function in this package.
 * @param token - Optional refresh token to derive from. If omitted, it's read from the session
 * cookie, same as {@link refreshSessionTokensBase}.
 * @param options - Options for the blocklist/rotation-grace check.
 * @param {ZanixCacheProvider} [options.cache] - Cache provider.
 * @param {ZanixKVConnector} [options.kvDb] - Key-value store connector.
 * @returns {Promise<MintedAccessToken>} A real access token, ready to use as a `Bearer` credential.
 *
 * @throws {HttpError} If no token was presented at all, or it isn't a refresh token.
 * @throws {PermissionDenied} If verification fails, or the token is blocklisted with no rotation-
 * grace entry to answer it.
 */
export const mintAccessTokenBase = async (
  ctx: ScopedContext,
  token?: string,
  options: { cache?: ZanixCacheProvider; kvDb?: ZanixKVConnector } = {},
): Promise<MintedAccessToken> => {
  const resolved = await resolveVerifiedRefreshToken(ctx, token, options)

  if (resolved.graceTokens) {
    applySessionTokens(ctx, resolved.graceTokens)
    return { accessToken: resolved.graceTokens.accessToken, payload: resolved.payload }
  }

  const sessionOptions = resolved.payload.access

  const accessToken = await createAccessToken(ctx, {
    expiration: sessionOptions.accessExpiration ?? DEFAULT_ACCESS_EXPIRATION,
    subject: sessionOptions.subject,
    type: 'user',
    payload: toAccessTokenPayload(sessionOptions),
  })

  return { accessToken, payload: resolved.payload }
}

/**
 * The real, exported entry point — {@link mintAccessTokenBase}, wrapped the same way
 * `refreshSessionTokens` wraps `refreshSessionTokensBase`: a bare `PermissionDenied`
 * (verification failure, or a blocklisted token with no rotation-grace entry) reaches a caller as
 * `HttpError('UNAUTHORIZED')` instead of `@zanix/server`'s generic 500 default. Every other case is
 * already an `HttpError` and passes through unchanged.
 *
 * `mintAccessTokenBase` stays the one place tested against the raw, unwrapped contract; an HTTP
 * handler (the SSR-side relay this function exists for) calls this wrapper.
 */
export const mintAccessToken = async (
  ctx: ScopedContext,
  token?: string,
  options: { cache?: ZanixCacheProvider; kvDb?: ZanixKVConnector } = {},
): Promise<MintedAccessToken> => {
  try {
    return await mintAccessTokenBase(ctx, token, options)
  } catch (e) {
    toJwtHttpError(e, 'UNAUTHORIZED')
  }
}
