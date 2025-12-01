import type { ZanixCacheProvider, ZanixKVConnector } from '@zanix/server'
import type { JWTPayload } from 'typings/jwt.ts'
import { CACHE_KEYS } from 'utils/constants.ts'
import { decodeJWT } from 'utils/jwt/decode.ts'
import logger from '@zanix/logger'

/**
 * Checks whether a given token ID is present in the blocklist.
 *
 * This function queries the cache provider to determine if the token has been
 * invalidated or revoked. It is typically used to prevent the usage of
 * tokens that should no longer grant access.
 *
 * @param {string} tokenId - The ID of the token to check in the blocklist.
 * @param {ZanixCacheProvider} cache - Cache provider.
 * @param {ZanixKVConnector} kvDb - Key-value store connector.
 * @returns {Promise<boolean>} Returns `true` if the token is blocklisted, `false` otherwise.
 *
 * @example
 * ```ts
 * const isBlocklisted = await checkBlockList('token123');
 * if (isBlocklisted) {
 *   console.log('Token has been revoked.');
 * }
 * ```
 */
export async function checkTokenBlockList(
  tokenId: string,
  cache: ZanixCacheProvider,
  kvDb: ZanixKVConnector,
): Promise<boolean> {
  const key = `${CACHE_KEYS.jwtBlockList}:${tokenId}`

  if (Deno.env.has('REDIS_URI')) {
    const isInBlockList = await cache.getCachedOrFetch<boolean | undefined>('redis', key)
    return isInBlockList === true
  }
  let cacheValue = cache.local.get(key)
  if (cacheValue === undefined) {
    cacheValue = kvDb.get(key)
    if (cacheValue) {
      cache.local.set(key, cacheValue)
      return cacheValue
    }
  }

  return cacheValue
}

/**
 * Adds a token ID to the blocklist with a specified expiration time.
 *
 * This function stores the token ID in the cache provider (typically Redis)
 * marking it as invalid or revoked. The entry will automatically expire
 * after the provided number of seconds, matching the token's lifetime.
 *
 * @param {string} token - The JWT to blocklist.
 * @param {ZanixCacheProvider} cache - Cache provider.
 * @param {ZanixKVConnector} kvDb - Key-value store connector.
 *
 * @returns {Promise<string>} Token ID
 *
 * @example
 * ```ts
 * // Blocklist a token for 3600 seconds (1 hour)
 * addTokenToBlockList('token123', 3600);
 * ```
 */
export async function addTokenToBlockList(
  token: string,
  cache: ZanixCacheProvider,
  kvDb?: ZanixKVConnector,
): Promise<JWTPayload> {
  const { payload } = decodeJWT(token)
  const { jti, exp } = payload

  let ttl = exp
  if (exp !== undefined) {
    ttl = exp - Math.floor(Date.now() / 1000)
    if (ttl <= 0) return payload // already expired, should not be available
  }

  const key = `${CACHE_KEYS.jwtBlockList}:${jti}`
  if (Deno.env.has('REDIS_URI')) {
    await cache.saveToCaches({ provider: 'redis', key, value: true, exp: ttl })
  } else {
    logger.warn(
      'The JWT blocklist system is currently using the KV local storage backend. ' +
        'For distributed systems, it is recommended to enable Redis by setting the REDIS_URI environment variable.',
      'noSave',
    )
    cache.local.set(key, true, { exp: ttl })
    kvDb?.set(key, true, ttl)
  }

  return payload
}
