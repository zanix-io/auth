import type { CheckRateLimitResult } from 'typings/sessions.ts'
import type { ZanixCacheProvider } from '@zanix/server'

import { RATE_LIMIT } from 'utils/lua.ts'

let rateLimitPlanMap: Map<number, number>

/**
 * Checks and enforces a rate limit based on a unique key.
 *
 * This function tracks how many requests have been made within a given time window
 * and determines whether the maximum allowed number of requests has been reached.
 * It can be used to prevent abuse of endpoints or services that require frequency control.
 *
 * @async
 * @function checkRateLimit
 * @param {ZanixCacheProvider} cache - Cache provider.
 * @param {Object} options - Configuration options for rate limiting.
 * @param {string} options.key - A unique identifier for the rate limit (e.g., user ID or IP address).
 * @param {number} options.maxRequests - The maximum number of requests allowed within the time window.
 * @param {number} options.windowSeconds - The duration of the time window in seconds during which requests are counted.
 * @param {number} [options.maxAttemptsToSave] - Maximum number of attempts to persist the rate limit state (useful in concurrent or unstable environments).
 * @throws {Error} Throws if an error occurs while accessing or updating the rate limit data.
 */
export async function checkRateLimit(cache: ZanixCacheProvider, options: {
  key: string
  maxRequests: number
  windowSeconds: number
  maxFaildedAttempts?: number
}) {
  const { key, maxRequests, windowSeconds, maxFaildedAttempts = 3 } = options
  const failedAttemptsKey = `${key}:failed-attempts`

  if (Deno.env.get('REDIS_URI')) {
    const client = await cache.redis.getClient()

    const now = Math.floor(Date.now() / 1000)

    const result = await client.eval(RATE_LIMIT, {
      keys: [key, failedAttemptsKey],
      arguments: [
        maxRequests.toString(),
        windowSeconds.toString(),
        maxFaildedAttempts.toString(),
        now.toString(),
      ],
    })

    return JSON.parse(result as string) as CheckRateLimitResult
  }

  return cache.withLock(key, () =>
    new Promise<CheckRateLimitResult>((resolve) => {
      let data
      const localData = cache.local.get<{ count: number; createdAt: number }>(key)

      if (localData === undefined) {
        data = { count: 1, createdAt: Math.floor(Date.now() / 1000) }
        cache.local.set(key, data, { exp: windowSeconds })
      } else data = localData

      const { count, createdAt } = data

      // rate limit exceeded
      if (count > maxRequests) {
        const failedAttempts = cache.local.get(failedAttemptsKey) as number
        if (failedAttempts >= maxFaildedAttempts) cache.local.delete(failedAttemptsKey)

        return resolve({ count, createdAt, failedAttempts, canContinue: false })
      }

      // Save failedAttempts
      if (count === 1 && maxFaildedAttempts) {
        const failedAttempts = cache.local.get(failedAttemptsKey) || 0
        cache.local.set(
          failedAttemptsKey,
          failedAttempts + 1,
          { exp: windowSeconds * maxFaildedAttempts * 2 },
        )
      }

      data.count++

      setTimeout(() => {
        cache.local.set(key, data, { exp: 'KEEPTTL' })
        resolve({ count, createdAt, failedAttempts: 0, canContinue: true })
      })
    }))
}

/**
 * Retrieves the rate limit for the session based on the session's rateLimit value.
 * If RATE_LIMIT_PLANS is defined, the rateLimit value in the session is used as an index
 * to match the corresponding plan and retrieve the maximum allowed requests.
 * If RATE_LIMIT_PLANS is not defined, session.rateLimit will be used directly as the
 * number of requests allowed per RATE_LIMIT_WINDOW_SECONDS.
 *
 * @param {number} sessionRateLimit - The session rate limit information.
 * @param {number} session.rateLimit - The rate limit value that can be used as an index or as the direct limit.
 *
 * @returns {number} The maximum number of requests allowed for the session within the defined time window.
 */
export function getRateLimitForSession(sessionRateLimit: number): number {
  if (!rateLimitPlanMap) {
    const RATE_LIMIT_PLANS = Deno.env.get('RATE_LIMIT_PLANS')
    // If RATE_LIMIT_PLANS is not defined, return session.rateLimit directly
    if (!RATE_LIMIT_PLANS) return sessionRateLimit

    // Parse RATE_LIMIT_PLANS only if it is defined
    rateLimitPlanMap = new Map(
      RATE_LIMIT_PLANS.split(';').map((plan) => {
        const [index, maxRequests] = plan.split(':')
        return [parseInt(index, 10), parseInt(maxRequests, 10)]
      }),
    )
  }
  // Look up the session.rateLimit index in the plan map
  return rateLimitPlanMap.get(sessionRateLimit) || sessionRateLimit // Default to session.rateLimit if not found
}
