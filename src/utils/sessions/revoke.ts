import type { SessionTypes } from 'typings/sessions.ts'
import type { JWTPayload } from 'typings/jwt.ts'

import {
  type ScopedContext,
  SESSION_HEADERS,
  type ZanixCacheProvider,
  type ZanixKVConnector,
} from '@zanix/server'
import { addTokenToBlockListBase } from 'utils/sessions/block-list.ts'
import { defineLocalSession } from 'utils/sessions/context.ts'
import { invalidRefreshTokenError } from './errors.ts'
import { toJwtHttpError } from 'utils/jwt/verification-error.ts'

/**
 * Revokes one or multiple app token to the block list.
 *
 * This function accepts either a single token string or an array of token strings.
 * If an array is provided, all tokens are processed concurrently.
 *
 * @param {string | string[]} tokenInfo - The token or tokens to revoke. Can be a single token string or an array of tokens.
 * @param {ZanixCacheProvider} cache - Cache provider.
 * @param {ZanixKVConnector} [kvDb] - Key-value store connector.
 * @returns {Promise<JWTPayload[]>} A promise that resolves with each revoked token's decoded payload.
 *
 * @throws {PermissionDenied} If any of the given tokens is malformed — `addTokenToBlockListBase`
 * decodes each one to read its `jti`/`exp` before recording it.
 *
 * @example
 * // Revoke a single token
 * await revokeAppTokensBase("abc123token", cache)
 *
 * @example
 * // Revoke multiple tokens
 * await revokeAppTokensBase(["token1", "token2", "token3"], cache)
 */
export const revokeAppTokensBase = (
  tokenInfo: string | string[],
  cache: ZanixCacheProvider,
  kvDb?: ZanixKVConnector,
): Promise<JWTPayload[]> => {
  if (!tokenInfo) return Promise.resolve([])

  const tokens = Array.isArray(tokenInfo) ? tokenInfo : [tokenInfo]
  return Promise.all(
    tokens.map((token) => addTokenToBlockListBase(token, cache, kvDb)),
  )
}

/**
 * The real, exported entry point — {@link revokeAppTokensBase}, wrapped so a malformed token
 * reaches a caller as `HttpError('BAD_REQUEST')` (the token you asked to revoke isn't valid to
 * begin with) instead of falling through to `@zanix/server`'s generic 500 default for the bare
 * `PermissionDenied` `addTokenToBlockListBase`'s own `decodeJWT` call throws (see `toJwtHttpError`'s
 * own doc). `revokeAppTokensBase` stays the one place tested against the raw, unwrapped contract;
 * reach for it directly only from a non-HTTP context that wants the bare `PermissionDenied`
 * instead.
 */
export const revokeAppTokens = async (
  tokenInfo: string | string[],
  cache: ZanixCacheProvider,
  kvDb?: ZanixKVConnector,
): Promise<JWTPayload[]> => {
  try {
    return await revokeAppTokensBase(tokenInfo, cache, kvDb)
  } catch (e) {
    toJwtHttpError(e, 'BAD_REQUEST')
  }
}

/**
 * Revokes a session and its associated refresh token.
 *
 * Adds the provided token to a blocklist (cache and optionally KV store)
 * to prevent further use, and assigns a revoked session to the context.
 *
 * This ensures that subsequent requests using the same token are treated
 * as unauthorized.
 *
 * @param ctx - The current request context (`ScopedContext`) where the revoked session will be stored.
 * @param options - Configuration options for revoking the token.
 * @param {string} [options.token] - Optional JWT to be revoked.
 *               If omitted, the token will be retrieved from the current context, provided cookies are available.
 * @param options.cache - Cache provider used to store the token blocklist.
 * @param options.kvDb - Optional KV connector to persist the token blocklist.
 * @param options.sessionType - Optional session type (default: `"user"`) to mark in the context.
 *
 * @example
 * await revokeSessionToken(context, {
 *   token: refreshToken,
 *   cache: cacheProvider,
 *   kvDb: kvConnector,
 *   sessionType: "user",
 * });
 */
export const revokeSessionTokenBase = async (
  ctx: ScopedContext,
  options: {
    token?: string
    cache: ZanixCacheProvider
    kvDb?: ZanixKVConnector
    sessionType?: SessionTypes
  },
): Promise<JWTPayload> => {
  const { token: tokenHeader } = SESSION_HEADERS['user']
  const { token, cache, kvDb, sessionType = 'user' } = options

  const currentRefreshToken = token || ctx.cookies[tokenHeader]

  if (!currentRefreshToken) {
    const { error } = invalidRefreshTokenError('revokeSessionToken')
    throw error
  }

  const tokens = [currentRefreshToken]
  if (ctx.session?.token) tokens.push(ctx.session.token)

  const [payload] = await revokeAppTokensBase(tokens, cache, kvDb)
  defineLocalSession(ctx, {
    payload: { ...payload, exp: 0 },
    type: sessionType,
    status: 'revoked',
  })

  return payload
}

/**
 * The real, exported entry point — {@link revokeSessionTokenBase}, wrapped the same way
 * {@link revokeAppTokens} wraps {@link revokeAppTokensBase}: a malformed token reaches a caller as
 * `HttpError('BAD_REQUEST')` instead of `@zanix/server`'s generic 500 default. Every other case
 * (`invalidRefreshTokenError`) is already an `HttpError` and passes through unchanged — only a
 * bare `PermissionDenied` gets normalized here. `revokeSessionTokenBase` stays the one place
 * tested against the raw, unwrapped contract; `ZanixAuthProvider`'s own `session.revokeToken()`
 * calls THIS wrapper.
 */
export const revokeSessionToken = async (
  ctx: ScopedContext,
  options: {
    token?: string
    cache: ZanixCacheProvider
    kvDb?: ZanixKVConnector
    sessionType?: SessionTypes
  },
): Promise<JWTPayload> => {
  try {
    return await revokeSessionTokenBase(ctx, options)
  } catch (e) {
    toJwtHttpError(e, 'BAD_REQUEST')
  }
}
