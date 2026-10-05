import type { RateLimitsOptions } from 'typings/sessions.ts'
import {
  httpErrorResponse,
  type MiddlewareGlobalGuard,
  RATE_LIMIT_HEADERS,
  type Session,
} from '@zanix/server'
import type { ControlPlaneCacheModules } from '@zanix/datamaster/cache/types'

import {
  checkRateLimit,
  getRateLimitForSession,
  getRateLimitIdentity,
} from 'utils/sessions/rate-limit.ts'
import {
  assertTrustProxyHeaderDecided,
  generateAnonymousSession,
} from 'utils/sessions/anonymous.ts'
import { CACHE_KEYS } from 'utils/constants.ts'
import { HttpError, InternalError } from '@zanix/errors'

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
 * - `X-Znx-RateLimit-Limit`: The maximum number of requests allowed in the current window, as
 *   applied (the explicit `limit`, the limit resolved from `RATE_LIMIT_PLANS`, or `session.rateLimit`
 *   itself), never the plan index.
 * - `X-Znx-RateLimit-Remaining`: The number of requests remaining in the current window (never negative).
 * - `X-Znx-RateLimit-Reset`: The number of **seconds remaining** until the current rate limit window resets.
 *   Clients can use this value to know how long to wait before sending the next request without being throttled.
 * - `Retry-After`: Indicates how many seconds to wait before making the next request, typically returned when the limit is exceeded.
 *
 * These headers allow clients to monitor and respect rate limits to avoid being throttled.
 *
 * @param options - The rate limit configuration options.
 * @param options.app - Optional cache-key scope. Left unset here, every guard built directly by
 *                       this function (as opposed to via the `@RateLimitGuard` decorator, which
 *                       auto-derives one from the decorated method's name — see its own doc) shares
 *                       ONE global bucket per session with every other guard that also leaves it
 *                       unset. See `RateLimitsOptions.app`'s own doc for the full contract.
 * @param options.windowSeconds -  Optional duration of the time window (in seconds) over which requests are counted.
 *                                 Defaults to `60` seconds. You can also override it using the `RATE_LIMIT_WINDOW_SECONDS` environment variable.
 * @param options.limit - Optional explicit maximum of requests per window for authenticated
 *                           sessions, in absolute value. It replaces the limit derived from
 *                           `session.rateLimit` and is never looked up in `RATE_LIMIT_PLANS`.
 *                           Must be a positive integer. See `RateLimitsOptions.limit`.
 * @param options.key - Identity the counter is keyed on: `'session'` (default, one bucket per token)
 *                           or `'subject'` (one bucket per `session.subject`, shared by all of its
 *                           tokens; falls back to the session id without a subject). See
 *                           `RateLimitsOptions.key`.
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
 * `trustProxyHeader` isn't explicitly `true` or `false`, or if `limit` isn't a positive integer.
 *
 * @example
 * ```ts
 * // 10 requests per minute per operator, shared by all of that operator's tokens.
 * rateLimitGuard({ app: 'admin:mutations', limit: 10, key: 'subject', anonymousLimit: false })
 * ```
 */
export const rateLimitGuard = (
  options: RateLimitsOptions = {},
): MiddlewareGlobalGuard => {
  const {
    app,
    limit,
    key: keyBy = 'session',
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

  if (limit !== undefined && (!Number.isInteger(limit) || limit < 1)) {
    throw new InternalError('rateLimitGuard `limit` must be a positive integer.', {
      code: 'RATE_LIMIT_INVALID_LIMIT',
      meta: { source: 'zanix', method: 'rateLimitGuard', limit },
    })
  }

  const { limitHeader, remainingHeader, resetHeader, retryAfterHeader } = RATE_LIMIT_HEADERS

  return async (ctx) => {
    const { req: { headers }, locals: { session } } = ctx
    // An explicit `limit` makes any non-anonymous session limitable, whether or not it carries a
    // `rateLimit` plan value.
    const sessionRateLimit = session?.rateLimit ||
      (limit !== undefined && session && session.type !== 'anonymous' ? limit : undefined)
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
      ? session as Session
      : await generateAnonymousSession(anonymousLimit as number, headers, {
        trustProxyHeader,
        trustedHeaders,
      })

    Object.freeze(ctx.locals.session.rateLimit)

    const currentSession = ctx.locals.session
    const { id: sessionId, type: sessionType, rateLimit: planRateLimit } = currentSession
    const explicitLimit = sessionType === 'anonymous' ? undefined : limit
    // The one place the applied maximum is resolved: the counter and the headers both use it.
    const maxRequests = explicitLimit ?? getRateLimitForSession(planRateLimit)
    const identity = sessionType === 'anonymous'
      ? sessionId
      : getRateLimitIdentity(currentSession, keyBy)

    const key = `${CACHE_KEYS.rateLimit}:${app ? `${app}-${identity}` : identity}`

    const { count, createdAt, canContinue, failedAttempts } = await checkRateLimit(
      ctx.providers.get<ControlPlaneCacheModules>('cache'),
      { key, windowSeconds, maxRequests },
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
            rateLimit: maxRequests,
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
        [limitHeader]: maxRequests.toString(),
        [remainingHeader]: Math.max(0, maxRequests - count).toString(),
        [resetHeader]: secondsUntilReset,
      },
    }
  }
}
