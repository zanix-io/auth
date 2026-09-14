import type { RateLimitsOptions } from 'typings/sessions.ts'

import { defineMiddlewareDecorator, type ZanixGenericDecorator } from '@zanix/server'
import { rateLimitGuard } from '../rate-limit.guard.ts'

/**
 * A method-level decorator that enforces a rate limit on a handler or method.
 *
 * This decorator applies rate limiting to specific methods, such as API endpoints,
 * based on the provided configuration options.
 *
 * It ensures that the `ctx.session` object exists and uses its `rateLimit` value
 * to enforce the rate limit. If the `ctx.session` does not exist, it will create
 * an anonymous session with default properties.
 *
 * The session object must adhere to the following `Session` type:
 *
 * ```ts
 * export type Session = {
 *   id: string
 *   type: SessionTypes
 *   rateLimit: number
 * }
 * ```
 *
 * @see {@link rateLimitGuard} for additional context on rate limiting.
 *
 * ## Default cache-key isolation (per decorated method)
 * Unlike calling `rateLimitGuard()` directly (which shares ONE global bucket per session unless
 * `options.app` is set explicitly), this decorator auto-derives `app` from the decorated method's
 * own name when `options.app` is left unset — so two `@RateLimitGuard`-decorated methods on the
 * same class/controller never share a counter by accident, even if neither one ever passes `app`.
 * This is what actually fixed a real incident: ten sibling anonymous-guarded routes (`login`,
 * `login/otp`, `pwd/recovery`, ...) mixing different limits all shared ONE counter per client
 * identity, because none of them set `app` — exhausting one route's tight limit silently
 * exhausted an unrelated route's separate budget too.
 *
 * This default isolates by METHOD NAME, not by class: two different classes/controllers that
 * happen to both have a `@RateLimitGuard`-decorated method with the identical name (e.g. two
 * unrelated controllers each defining a `login` method) WOULD still collide on the same default
 * key. Pass `app` explicitly (e.g. a `'<Controller>:<method>'` string) to fully disambiguate across
 * classes, or to deliberately opt back into a single shared bucket across several methods.
 *
 * @param options - Configuration object for the rate limit, including:
 *                  - `anonymousLimit`: Maximum number of requests for anonymous users.
 *                  - `windowSeconds`: Time window (in seconds) within which the limit applies.
 *                  - `app`: Optional explicit cache-key scope — overrides the method-name default
 *                    described above. See `RateLimitsOptions.app`'s own doc.
 *
 *                  These options are defined in the `RateLimitsOptions` type.
 *
 * @returns A method decorator (`ZanixGenericDecorator`) that applies the rate limit logic
 *          to the decorated method.
 *
 * @example
 * ```ts
 * @RateLimitGuard({ anonymousLimit: 200, windowSeconds: 120 }) // 200 requests within a 2-minute window
 * async function handleRequest(ctx: HandlerContext) {
 *   // handler logic here
 * }
 * ```
 */
/**
 * Resolves the effective `app` cache-key scope for a `RateLimitGuard`-decorated target: the
 * caller's own explicit `options.app` when given, otherwise the decorated member's own name
 * (falling back to `undefined` — the pre-existing "global" behavior — when neither is available,
 * e.g. an anonymous class expression). Exported as a pure function specifically so this resolution
 * rule is unit-testable on its own, without needing to reach into `@zanix/server`'s own internal
 * decorator-registration machinery (deliberately not part of its public surface).
 */
export function resolveRateLimitApp(
  options: Pick<RateLimitsOptions, 'app'>,
  context?: ClassDecoratorContext | ClassMethodDecoratorContext,
): string | undefined {
  return options.app ?? (context?.name ? String(context.name) : undefined)
}

export function RateLimitGuard(
  options: RateLimitsOptions = {},
): ZanixGenericDecorator {
  return function (target, context) {
    // Deferred on purpose: `rateLimitGuard(options)` is only constructed HERE, once `context` (and
    // therefore the decorated method's own name) is available — not eagerly in `RateLimitGuard`'s
    // own factory call, the way every other guard decorator in this file builds its middleware.
    // This still runs synchronously at class-definition time (decorator application), so the
    // "throws at construction, not on first request" contract (`assertTrustProxyHeaderDecided`)
    // is unaffected — it just resolves one step later than before, still long before any request.
    const app = resolveRateLimitApp(options, context)
    return defineMiddlewareDecorator('guard', rateLimitGuard({ ...options, app }))(
      target,
      context,
    )
  }
}
