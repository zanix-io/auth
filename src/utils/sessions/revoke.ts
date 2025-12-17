import type { ScopedContext, ZanixCacheProvider, ZanixKVConnector } from '@zanix/server'
import type { SessionTypes } from 'typings/sessions.ts'
import type { JWTPayload } from 'typings/jwt.ts'

import { addTokenToBlockList } from 'utils/sessions/block-list.ts'
import { defineLocalSession } from 'utils/sessions/context.ts'
import { SESSION_HEADERS } from 'utils/constants.ts'
import { invalidRefreshTokenError } from './errors.ts'

/**
 * Revokes one or multiple app token to the block list.
 *
 * This function accepts either a single token string or an array of token strings.
 * If an array is provided, all tokens are processed concurrently.
 *
 * @param {ZanixCacheProvider} cache - Cache provider.
 * @param {ZanixKVConnector} kvDb - Key-value store connector.
 * @param {string | string[]} tokenInfo - The token or tokens to revoke. Can be a single token string or an array of tokens.
 * @returns {Promise<void>} A promise that resolves once all tokens have been added to the block list.
 *
 * @example
 * // Revoke a single token
 * await revokeTokens("abc123token")
 *
 * @example
 * // Revoke multiple tokens
 * await revokeTokens(["token1", "token2", "token3"])
 */
export const revokeAppTokens = (
  tokenInfo: string | string[],
  cache: ZanixCacheProvider,
  kvDb?: ZanixKVConnector,
): Promise<JWTPayload[]> => {
  if (!tokenInfo) return Promise.resolve([])

  const tokens = Array.isArray(tokenInfo) ? tokenInfo : [tokenInfo]
  return Promise.all(tokens.map((token) => addTokenToBlockList(token, cache, kvDb)))
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
export const revokeSessionToken = async (
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

  const [payload] = await revokeAppTokens(tokens, cache, kvDb)
  defineLocalSession(ctx, {
    payload: { ...payload, exp: 0 },
    type: sessionType,
    status: 'revoked',
  })

  return payload
}
