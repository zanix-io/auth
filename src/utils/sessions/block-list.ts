import type { ZanixCacheProvider, ZanixKVConnector } from '@zanix/server'
import type { JWTPayload } from 'typings/jwt.ts'
import type { SessionTokens } from 'typings/sessions.ts'
import { isNumberString } from '@zanix/validator'
import { parseTTL } from '@zanix/helpers'
import { CACHE_KEYS, REDIS_URI_ENV, ROTATION_GRACE_WINDOW_ENV } from 'utils/constants.ts'
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

/**
 * Reads the rotation grace window from `ROTATION_GRACE_WINDOW` ({@link ROTATION_GRACE_WINDOW_ENV}).
 * The value is a TTL string such as `'5s'`, `'10s'`, or a bare number of seconds; a missing value
 * defaults to `'5s'`, and an explicit `'0'` disables the window.
 *
 * @returns {number} The grace window length in seconds. Returns `0` when disabled.
 */
function getRotationGraceWindowSeconds(): number {
  const windowStr = Deno.env.get(ROTATION_GRACE_WINDOW_ENV) || '5s'
  if (windowStr === '0') return 0
  return parseTTL(isNumberString(windowStr) ? Number(windowStr) : windowStr)
}

/**
 * Looks up the replacement pair a rotation already issued for the given token ID, while it's still
 * within its grace window — the short-lived companion entry {@link setRotationGraceTokens} writes
 * right after a successful rotation.
 *
 * `refreshSessionTokensBase` consults this only once a presented token is confirmed blocklisted: a
 * hit here means the token wasn't reused after the fact, it's the SAME legitimate client's request
 * arriving a moment after another request already rotated it (a browser prefetching a link on hover
 * and then navigating it, a double click, two tabs on one session, a client's own retry) — so it
 * gets the already-issued pair back instead of a rejection. A miss past the grace window is treated
 * as a genuine reuse, same as before this existed.
 *
 * @param {string} tokenId - The `jti` of the presented, already-blocklisted token.
 * @param {ZanixCacheProvider} cache - Cache provider.
 * @param {ZanixKVConnector} [kvDb] - Key-value store connector. Same optional fallback role as in
 * {@link checkTokenBlockList}.
 * @returns {Promise<SessionTokens | undefined>} The replacement pair, or `undefined` once the grace
 * window has elapsed (or when it's disabled via `ROTATION_GRACE_WINDOW=0`).
 */
export async function getRotationGraceTokens(
  tokenId: string,
  cache: ZanixCacheProvider,
  kvDb?: ZanixKVConnector,
): Promise<SessionTokens | undefined> {
  const key = `${CACHE_KEYS.jwtRotationGrace}:${tokenId}`

  if (Deno.env.has(REDIS_URI_ENV)) {
    return await cache.getCachedOrFetch<SessionTokens | undefined>('redis', key)
  }

  let cacheValue = cache.local.get<SessionTokens>(key)
  if (cacheValue === undefined) {
    cacheValue = kvDb?.get(key)
    if (cacheValue) cache.local.set(key, cacheValue)
  }

  return cacheValue
}

/**
 * Records the pair a successful rotation just issued, keyed by the `jti` of the token it consumed —
 * the companion write {@link getRotationGraceTokens} reads back. Expires after the configured
 * rotation grace window ({@link ROTATION_GRACE_WINDOW_ENV}, default `5s`); a no-op once that window
 * is disabled (`ROTATION_GRACE_WINDOW=0`).
 *
 * `refreshSessionTokensBase` calls this BEFORE {@link addTokenToBlockListBase} for the same
 * rotation, not after: a concurrent request can only ever observe the old token as blocklisted once
 * this entry already exists to answer it, never the reverse.
 *
 * @param {string} tokenId - The `jti` of the token just consumed by rotation.
 * @param {SessionTokens} tokens - The newly issued pair to hand back to a near-simultaneous retry.
 * @param {ZanixCacheProvider} cache - Cache provider.
 * @param {ZanixKVConnector} [kvDb] - Key-value store connector.
 */
export async function setRotationGraceTokens(
  tokenId: string,
  tokens: SessionTokens,
  cache: ZanixCacheProvider,
  kvDb?: ZanixKVConnector,
): Promise<void> {
  const ttl = getRotationGraceWindowSeconds()
  if (ttl <= 0) return

  const key = `${CACHE_KEYS.jwtRotationGrace}:${tokenId}`
  if (Deno.env.has(REDIS_URI_ENV)) {
    await cache.saveToCaches({ provider: 'redis', key, value: tokens, exp: ttl })
  } else {
    cache.local.set(key, tokens, { exp: ttl })
    kvDb?.set(key, tokens, ttl)
  }
}
