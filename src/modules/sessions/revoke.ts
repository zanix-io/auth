import type { ScopedContext, ZanixCacheProvider, ZanixKVConnector } from '@zanix/server'
import type { SessionTypes } from 'typings/sessions.ts'
import type { JWTPayload } from 'typings/jwt.ts'

import { addTokenToBlockList } from 'utils/sessions/block-list.ts'
import { localSessionDefinition } from './create.ts'

/**
 * Revokes one or multiple sessions by adding their token(s) to the block list.
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
 * // Revoke a single session
 * await revokeSessions("abc123token")
 *
 * @example
 * // Revoke multiple sessions
 * await revokeSessions(["token1", "token2", "token3"])
 */
export const revokeSessionTokens = async (
  tokenInfo: string | string[],
  cache: ZanixCacheProvider,
  kvDb?: ZanixKVConnector,
): Promise<void> => {
  if (!tokenInfo) return

  const tokens = Array.isArray(tokenInfo) ? tokenInfo : [tokenInfo]
  await Promise.all(tokens.map((token) => addTokenToBlockList(token, cache, kvDb)))
}

/**
 * Revokes a session and its associated token.
 *
 * Adds the provided token to a blocklist (cache and optionally KV store)
 * to prevent further use, and assigns a revoked session to the context.
 *
 * This ensures that subsequent requests using the same token are treated
 * as unauthorized.
 *
 * @param ctx - The current request context (`ScopedContext`) where the revoked session will be stored.
 * @param options - Configuration options for revoking the token.
 * @param options.token - The token string to be revoked.
 * @param options.cache - Cache provider used to store the token blocklist.
 * @param options.kvDb - Optional KV connector to persist the token blocklist.
 * @param options.sessionType - Optional session type (default: `"user"`) to mark in the context.
 *
 * @example
 * await revokeSessionAndToken(context, {
 *   token: accessToken,
 *   cache: cacheProvider,
 *   kvDb: kvConnector,
 *   sessionType: "user",
 * });
 */
export const revokeSessionAndToken = async (
  ctx: ScopedContext,
  options: {
    token: string
    cache: ZanixCacheProvider
    kvDb?: ZanixKVConnector
    sessionType?: SessionTypes
  },
): Promise<JWTPayload> => {
  const { token, cache, kvDb, sessionType = 'user' } = options
  const payload = await addTokenToBlockList(token, cache, kvDb)
  localSessionDefinition(ctx, {
    payload: { ...payload, exp: 0 },
    type: sessionType,
    status: 'revoked',
  })

  return payload
}
