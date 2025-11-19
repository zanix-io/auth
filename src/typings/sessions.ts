import type { JWTPayload } from './jwt.ts'

/**
 * The rate limit configuration options.
 */
export type RateLimitsOptions = {
  /**
   * The optional duration of the time window in seconds during which requests are counted.
   * Defaults to `60s`.
   */
  windowSeconds?: number
  /**
   * Maximum number of requests allowed for anonymous users within the time window.
   * Defaults to `100`.
   * Set to `0` or `false` to disable access for anonymous users.
   */
  anonymousLimit?: false | number
}

export type CheckRateLimitResult = {
  count: number
  createdAt: number
  failedAttempts: number
  canContinue: boolean
}

/**
 * Represents the possible states of a user session.
 *
 * - **active**: The user is authenticated and the session is valid.
 * - **failed**: Authentication failed or session validation did not succeed.
 * - **unconfirmed**: Anonymous or unauthenticated session, typically a guest user.
 * - **blocked**: The session has been blocked, usually due to security policies or rate limiting.
 * - **revoked**: The session was revoked or added to the blocklist.
 */
export type SessionStatus = 'active' | 'failed' | 'unconfirmed' | 'blocked' | 'revoked'

/**
 * Session types.
 * Depending on the selected `type`, the corresponding algorithm is assigned for JWT verification:
 *
 * - `type: "user"` → **HS256**
 * - `type: "api"`  → **RS256**
 *
 * Also, extracts the token from different authorization headers:
 * - `type: "user"` → Header: `Authorization: Bearer <token>`
 * - `type: "api"`  → Header: `X-Znx-Authorization: Bearer <token>`
 */
export type SessionTypes = 'user' | 'api'

export type SessionTokenOptions<T extends SessionTypes> = {
  /** User or API Id. */
  subject: string
  /**
   * The expiration type, either as a human-readable
   * string (e.g., `"1h"`, `"15m"`, `"7d"`) or a numeric value in seconds.The expiration time in seconds (from now), or a `Date` object.
   */
  expiration: number | string
  /**
   * The JWT data payload.
   */
  payload?: Omit<Partial<JWTPayload>, 'sub' | 'exp' | 'jit'> & {
    /** Permissions required to access the protected resource.
     * Can be roles, scopes, permissions, or audience claims.
     * This can be a single string or an array of strings.
     * For example, `['admin', 'write:user']`.
     */
    permissions?: JWTPayload['aud']
    /**
     * Number of request per rate limit, or rate limit plan index. Defaults to `100`.
     *
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
     */
    rateLimit?: number
  }

  /**
   * Session types.
   * Depending on the selected `type`, the corresponding algorithm is assigned for JWT verification
   * and the Authentication headers are extracted.
   */
  type: T
  /**
   * The key used to encrypt or protect the payload's sensitive data.
   * Required on 'api' type.
   */
  encryptionKey?: 'api' extends T ? string : never
}

export type AccessTokenOptions<T extends SessionTypes> =
  & Omit<SessionTokenOptions<T>, 'expiration'>
  & {
    expiration: '30m' | '1h' | number
  }

export type RefreshTokenOptions<T extends SessionTypes> =
  & Omit<SessionTokenOptions<T>, 'expiration'>
  & {
    expiration: '1w' | '1mo' | '6mo' | '1y'
  }

/**
 * Represents a user's session tokens.
 */
export type SessionTokens = {
  /**
   * The access token used for API calls or authentication.
   */
  accessToken: string
  /**
   * The refresh token used to obtain new access tokens.
   */
  refreshToken: string
}
