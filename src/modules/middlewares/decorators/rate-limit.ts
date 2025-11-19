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
 * @param options - Configuration object for the rate limit, including:
 *                  - `anonymousLimit`: Maximum number of requests for anonymous users.
 *                  - `windowSeconds`: Time window (in seconds) within which the limit applies.
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
export function RateLimitGuard(options: RateLimitsOptions): ZanixGenericDecorator {
  return defineMiddlewareDecorator('guard', rateLimitGuard(options))
}
