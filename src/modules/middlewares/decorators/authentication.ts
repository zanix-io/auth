import type { JWTValidationOpts } from 'typings/auth.ts'

import { defineMiddlewareDecorator, type ZanixGenericDecorator } from '@zanix/server'
import { jwtValidationGuard } from '../jwt-validation.guard.ts'

/**
 * A method-level decorator that performs JWT validation on incoming requests.
 *
 * Use this decorator to authenticate requests by verifying the provided access token,
 * checking the cache blocklist, applying rate limiting, and setting session context if
 * the validation succeeds.
 *
 * This guard supports both **HMAC** and **RSA** JWT verification, with the `user` mode
 * enabled by default. Depending on the selected mode, it extracts the JWT from different
 * authorization headers:
 *
 * - `type: "user"` → `Authorization: Bearer <token>` (**HS256**)
 * - `type: "api"`  → `X-Znx-Authorization: Bearer <token>` (**RS256**)
 *
 * If the JWT is valid and the session passes all checks, the session context is set.
 * If any validation fails, the request is denied.
 *
 * @see {@link jwtValidationGuard} for more details on how JWT validation works.
 *
 * @param options - Optional configuration for the JWT validation, including:
 *                  - `permissions`: An array of required permissions for access.
 *                  - `iss`: The expected issuer of the token.
 *                  - `type`: The authorization header type, either `"user"` or `"api"`.
 *                  - `rateLimitOptions`: Configuration for rate limiting, defined in `RateLimitsOptions`.
 *
 * @returns A method decorator (`ZanixGenericDecorator`) that applies the JWT validation logic
 *          and rate limiting to the decorated method.
 *
 * @example
 * ```ts
 * @AuthTokenValidation({ permissions: ['admin'], iss: 'znx' })
 * async function handleRequest(ctx: HandlerContext) {
 *   // Request is authenticated and rate-limited based on the provided configuration.
 * }
 * ```
 */
export function AuthTokenValidation(options?: JWTValidationOpts): ZanixGenericDecorator {
  return defineMiddlewareDecorator('guard', jwtValidationGuard(options))
}
