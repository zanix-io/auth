import type { RateLimitsOptions } from 'typings/sessions.ts'
import { errorResponses, type MiddlewareGlobalGuard } from '@zanix/server'

import { checkRateLimit, getRateLimitForSession } from 'utils/sessions/rate-limit.ts'
import { generateAnonymousSession } from 'utils/sessions/anonymous.ts'
import { CACHE_KEYS, RATE_LIMIT_HEADERS } from 'utils/constants.ts'
import { HttpError } from '@zanix/errors'

/**
 * Creates and returns a middleware guard that enforces rate limiting.
 *
 * This guard can be used in a request-handling pipeline (e.g., an API framework)
 * to automatically check and apply rate limits before allowing further processing.
 * Typically, it integrates with a rate limit checking mechanism such as `checkRateLimit()`.
 *
 * This guard ensures that `ctx.session` exists and uses it to enforce
 * request limits based on the session's `rateLimit` value.
 * The session object should conform to the `Session` type:
 *
 * ```ts
 * export type Session = {
 *   id: string
 *   type: SessionTypes
 *   rateLimit: number
 * }
 * ```
 *
 * ## Rate Limit Configuration:
 * Rate limiting can be configured using the following environment variables:
 *
 * - `RATE_LIMIT_WINDOW_SECONDS`: Specifies the time window (in seconds) for rate limiting.
 * - `RATE_LIMIT_PLANS`: Defines rate limit plans in the format `'index:maxRequests'`. For example:
 *   `RATE_LIMIT_PLANS='0:100;1:1000;2:3000'`
 *
 * When `RATE_LIMIT_PLANS` is defined:
 *   - The session's `rateLimit` value will be treated as an index to match the corresponding plan.
 *   - For example, if `session.rateLimit` is `0`, it will allow 100 requests per `RATE_LIMIT_WINDOW_SECONDS`.
 *   - If `session.rateLimit` is `1`, it will allow 1000 requests per the same time window.
 *
 * If `RATE_LIMIT_PLANS` is not defined, or if `session.rateLimit` does not match any index in the plan:
 *   - The `session.rateLimit` will directly represent the number of requests allowed per `RATE_LIMIT_WINDOW_SECONDS`.
 *
 * This configuration allows for dynamic rate limiting, where the `session.rateLimit` can either reference a plan index or directly set the limit, depending on the configuration.
 *
 * ## Rate Limit Response Headers
 * When the rate limit is applied or successfully validated, the response may include the following headers:
 *
 * - `X-Znx-RateLimit-Limit`: The maximum number of requests allowed in the current window.
 * - `X-Znx-RateLimit-Remaining`: The number of requests remaining in the current window.
 * - `X-Znx-RateLimit-Reset`: The number of **seconds remaining** until the current rate limit window resets.
 *   Clients can use this value to know how long to wait before sending the next request without being throttled.
 * - `Retry-After`: Indicates how many seconds to wait before making the next request, typically returned when the limit is exceeded.
 *
 * These headers allow clients to monitor and respect rate limits to avoid being throttled.
 *
 * @param options - The rate limit configuration options.
 * @param options.windowSeconds -  Optional duration of the time window (in seconds) over which requests are counted.
 *                                 Defaults to `60` seconds. You can also override it using the `RATE_LIMIT_WINDOW_SECONDS` environment variable.
 * @param option.anonymousLimit - Maximum number of requests allowed for anonymous users within the time window.
 *                           Defaults to `100`.
 *                           Set to `0` or `false` to disable access for anonymous users.
 * @function rateLimitGuard
 * @returns {MiddlewareGuard} A middleware guard instance that applies rate limiting logic to incoming requests.
 */
export const rateLimitGuard = (
  options: RateLimitsOptions = {},
): MiddlewareGlobalGuard => {
  const {
    windowSeconds = Number(Deno.env.get('RATE_LIMIT_WINDOW_SECONDS')) || 60,
    anonymousLimit = 100,
  } = options

  const { limitHeader, remainingHeader, resetHeader, retryAfterHeader } = RATE_LIMIT_HEADERS

  return async (ctx) => {
    const { req: { headers }, locals: { session } } = ctx
    if (!session?.rateLimit && !anonymousLimit) {
      throw new HttpError('UNAUTHORIZED', {
        message: 'Access to this resource is not allowed.',
        meta: {
          source: 'zanix',
          method: 'rateLimitGuard',
          requestId: ctx.id,
          reason: !session?.rateLimit
            ? 'No session found with a valid rate limit configuration.'
            : 'Anonymous users are not permitted',
        },
      })
    }

    ctx.locals.session = session ||
      await generateAnonymousSession(anonymousLimit as number, headers)

    Object.freeze(ctx.locals.session)

    const { id: sessionId, type: sessionType, rateLimit } = ctx.locals.session

    const key = `${CACHE_KEYS.rateLimit}:${sessionId}`

    const { count, createdAt, canContinue, failedAttempts } = await checkRateLimit(
      ctx.providers.get('cache'),
      { key, windowSeconds, maxRequests: getRateLimitForSession(rateLimit) },
    )

    const dateInSeconds = Math.floor(Date.now() / 1000) - createdAt
    const windowEnd = dateInSeconds - (dateInSeconds % windowSeconds) + windowSeconds
    const secondsUntilReset = (windowEnd - dateInSeconds).toString()

    if (!canContinue) {
      const response = errorResponses(
        new HttpError('TOO_MANY_REQUESTS', {
          shouldLog: sessionType !== 'anonymous' && failedAttempts >= 3,
          message: 'Too Many Requests',
          meta: {
            source: 'zanix',
            sessionId,
            sessionType,
            rateLimit,
            windowSeconds,
            requestId: ctx.id,
          },
        }),
        { [retryAfterHeader]: secondsUntilReset },
      )
      return { response }
    }

    return {
      headers: {
        [limitHeader]: rateLimit.toString(),
        [remainingHeader]: (rateLimit - count).toString(),
        [resetHeader]: secondsUntilReset,
      },
    }
  }
}
