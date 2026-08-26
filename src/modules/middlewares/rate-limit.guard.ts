import type { RateLimitsOptions } from 'typings/sessions.ts'
import { httpErrorResponse, type MiddlewareGlobalGuard, RATE_LIMIT_HEADERS } from '@zanix/server'
import type { ControlPlaneCacheModules } from '@zanix/datamaster/cache/types'

import { checkRateLimit, getRateLimitForSession } from 'utils/sessions/rate-limit.ts'
import {
  assertTrustProxyHeaderDecided,
  generateAnonymousSession,
} from 'utils/sessions/anonymous.ts'
import { CACHE_KEYS } from 'utils/constants.ts'
import { HttpError } from '@zanix/errors'

/**
 * Env var setting the rate-limit window (in seconds) `rateLimitGuard` counts requests over.
 * Defaults to `60` when unset — see `rateLimitGuard`'s own doc for the full configuration shape.
 */
export const RATE_LIMIT_WINDOW_SECONDS_ENV = 'RATE_LIMIT_WINDOW_SECONDS'

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
 * @param options.anonymousLimit - Maximum number of requests allowed for anonymous users within the time window.
 *                           Defaults to `100`.
 *                           Set to `0` or `false` to disable access for anonymous users.
 * @param options.trustProxyHeader - Required (no default) whenever anonymous access is enabled — must be
 *                           explicitly `true` (key each anonymous bucket off the resolved client IP; only
 *                           safe behind a trusted proxy) or `false` (every anonymous request shares ONE
 *                           bucket instead — a deliberate trade-off, not a silent default). Throws at
 *                           construction time — when this guard is built, e.g. as a `@Controller`'s
 *                           `guards` argument, not on the first request — if left unset. Same contract
 *                           `ipAllowlistGuard` already established for this exact class of decision.
 * @function rateLimitGuard
 * @returns {MiddlewareGuard} A middleware guard instance that applies rate limiting logic to incoming requests.
 * @throws {InternalError} If anonymous access is enabled (`anonymousLimit` isn't `false`/`0`) but
 * `trustProxyHeader` isn't explicitly `true` or `false`.
 */
export const rateLimitGuard = (
  options: RateLimitsOptions = {},
): MiddlewareGlobalGuard => {
  const {
    app,
    windowSeconds = Number(Deno.env.get(RATE_LIMIT_WINDOW_SECONDS_ENV)) || 60,
    anonymousLimit = 100,
    trustProxyHeader,
    trustedHeaders,
  } = options

  // `anonymousLimit` disables anonymous access via `false` OR `0` (see this function's own doc) —
  // a plain truthy check matches that same semantics, unlike a strict `!== false` would. Delegates
  // the actual check/throw to `assertTrustProxyHeaderDecided` — the single source of truth for
  // this rule, shared with `getAnonymousSessionId`'s own defensive call — called eagerly HERE
  // (before this function returns its guard closure) so misconfiguration fails at construction
  // time, not on the first request.
  if (anonymousLimit) assertTrustProxyHeaderDecided(trustProxyHeader, 'rateLimitGuard')

  const { limitHeader, remainingHeader, resetHeader, retryAfterHeader } = RATE_LIMIT_HEADERS

  return async (ctx) => {
    const { req: { headers }, locals: { session } } = ctx
    const sessionRateLimit = session?.rateLimit
    if (!sessionRateLimit && !anonymousLimit) {
      throw new HttpError('UNAUTHORIZED', {
        message: 'Access to this resource is not allowed.',
        meta: {
          source: 'zanix',
          method: 'rateLimitGuard',
          requestId: ctx.id,
          reason: !session
            ? 'Anonymous users are not permitted'
            : 'No session found with a valid rate limit configuration.',
        },
      })
    }

    ctx.locals.session = sessionRateLimit
      ? session
      : await generateAnonymousSession(anonymousLimit as number, headers, {
        trustProxyHeader,
        trustedHeaders,
      })

    Object.freeze(ctx.locals.session.rateLimit)

    const { id: sessionId, type: sessionType, rateLimit } = ctx.locals.session

    const key = `${CACHE_KEYS.rateLimit}:${app ? `${app}-${sessionId}` : sessionId}`

    const { count, createdAt, canContinue, failedAttempts } = await checkRateLimit(
      ctx.providers.get<ControlPlaneCacheModules>('cache'),
      { key, windowSeconds, maxRequests: getRateLimitForSession(rateLimit) },
    )

    const dateInSeconds = Math.floor(Date.now() / 1000) - createdAt
    const windowEnd = dateInSeconds - (dateInSeconds % windowSeconds) +
      windowSeconds
    const secondsUntilReset = (windowEnd - dateInSeconds).toString()

    if (!canContinue) {
      const response = httpErrorResponse(
        new HttpError('TOO_MANY_REQUESTS', {
          shouldLog: sessionType !== 'anonymous' && failedAttempts >= 3,
          message: 'Too Many Requests',
          meta: {
            source: 'zanix',
            sessionRef: sessionId,
            sessionType,
            rateLimit,
            windowSeconds,
            requestId: ctx.id,
          },
          exposeMeta: true,
        }),
        {
          headers: { [retryAfterHeader]: secondsUntilReset },
          contextId: ctx.id,
        },
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
