import type { ZanixCacheProvider, ZanixKVConnector } from '@zanix/server'
import type { JWTPayload } from 'typings/jwt.ts'
import { CACHE_KEYS, REDIS_URI_ENV } from 'utils/constants.ts'
import { decodeJWT } from 'utils/jwt/decode.ts'
import { toJwtHttpError } from 'utils/jwt/verification-error.ts'
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
 * @param {ZanixKVConnector} [kvDb] - Key-value store connector. Only consulted as a fallback when
 * `REDIS_URI` isn't set and the in-memory local cache has no entry — the Redis path never touches
 * it, matching {@link addTokenToBlockList}'s own optional `kvDb`.
 * @returns {Promise<boolean>} Returns `true` if the token is blocklisted, `false` otherwise.
 *
 * @example
 * ```ts
 * const isBlocklisted = await checkTokenBlockList('token-id', cache, kvDb);
 * if (isBlocklisted) {
 *   console.log('Token has been revoked.');
 * }
 * ```
 */
export async function checkTokenBlockList(
  tokenId: string,
  cache: ZanixCacheProvider,
  kvDb?: ZanixKVConnector,
): Promise<boolean> {
  const key = `${CACHE_KEYS.jwtBlockList}:${tokenId}`

  if (Deno.env.has(REDIS_URI_ENV)) {
    const isInBlockList = await cache.getCachedOrFetch<boolean | undefined>(
      'redis',
      key,
    )
    return isInBlockList === true
  }
  let cacheValue = cache.local.get(key)
  if (cacheValue === undefined) {
    cacheValue = kvDb?.get(key)
    if (cacheValue) {
      cache.local.set(key, cacheValue)
      return cacheValue
    }
  }

  return cacheValue ?? false
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
 * @param {ZanixKVConnector} [kvDb] - Key-value store connector.
 *
 * @returns {Promise<JWTPayload>} The blocklisted token's decoded payload.
 *
 * @throws {PermissionDenied} If `token` is malformed — this decodes it to read its own `jti`/`exp`
 * before recording it.
 *
 * @example
 * ```ts
 * // Blocklist a token until its own expiration
 * await addTokenToBlockListBase(token, cache, kvDb);
 * ```
 */
export async function addTokenToBlockListBase(
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
  if (Deno.env.has(REDIS_URI_ENV)) {
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

/**
 * The real, exported entry point — {@link addTokenToBlockListBase}, wrapped so a malformed token
 * reaches a caller as `HttpError('BAD_REQUEST')` instead of `@zanix/server`'s generic 500 default
 * for the bare `PermissionDenied` its own `decodeJWT` call throws (see `toJwtHttpError`'s own
 * doc). `addTokenToBlockListBase` stays the one place tested against the raw, unwrapped contract;
 * `revokeAppTokensBase`/`refreshSessionTokensBase` call it directly (internal, already-trusted
 * callers), never this wrapper — reach for the Base directly only from a non-HTTP context that
 * wants the bare `PermissionDenied` instead.
 */
export async function addTokenToBlockList(
  token: string,
  cache: ZanixCacheProvider,
  kvDb?: ZanixKVConnector,
): Promise<JWTPayload> {
  try {
    return await addTokenToBlockListBase(token, cache, kvDb)
  } catch (e) {
    toJwtHttpError(e, 'BAD_REQUEST')
  }
}
