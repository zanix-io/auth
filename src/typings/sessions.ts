import type { JWTPayload } from './jwt.ts'
import type { ProxyTrustOptions } from '@zanix/helpers'

/**
 * The rate limit configuration options. `trustProxyHeader`/`trustedHeaders` are `@zanix/helpers`'s
 * shared {@linkcode ProxyTrustOptions} contract — see that type's own doc for the general shape;
 * this option's own doc below covers what happens HERE specifically when it's `false` (one shared
 * anonymous bucket, same as `AnonymousSessionOptions`' own resolution) vs. left unset (a
 * construction-time throw — `rateLimitGuard` requires an explicit decision, same as
 * `ipAllowlistGuard` does for this identical class of decision).
 */
export type RateLimitsOptions = ProxyTrustOptions & {
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
  /**
   * App this validation applies to.
   * - If undefined, the validation is considered global.
   * - If defined, it only applies to the specified app.
   */
  app?: string
  // Redeclares `ProxyTrustOptions.trustProxyHeader` (same `boolean | undefined` type — this does
  // NOT change what's accepted) purely so hovering it on `RateLimitsOptions` specifically shows
  // THIS doc instead of `ProxyTrustOptions`'s generic one. `trustedHeaders` is deliberately NOT
  // redeclared below: "headers considered trustworthy" means the same thing in every consumer, so
  // the shared doc is already the right one.
  /**
   * Required (no default) whenever anonymous access is enabled (`anonymousLimit` isn't `false`/
   * `0`) — must be explicitly `true` or `false`, never left unset:
   * - `true`: each anonymous request's rate-limit bucket is keyed off its resolved client IP
   *   (`x-forwarded-for`/`cf-connecting-ip`/`x-real-ip`) — only meaningful if your own
   *   infrastructure guarantees a trusted proxy overwrites those headers before they reach this
   *   process; otherwise a client can mint unlimited distinct buckets by spoofing them.
   * - `false`: every anonymous request shares ONE rate-limit bucket instead — a deliberate,
   *   explicit trade-off for deployments that can't guarantee a trusted proxy: closes the
   *   spoofing bypass, at the cost of one abusive (or just busy) anonymous client being able to
   *   exhaust the shared quota for every other anonymous client too.
   * - unset: `rateLimitGuard` throws at construction time (when the guard is built, not on the
   *   first request) rather than picking either behavior silently.
   *
   * Same contract `ipAllowlistGuard`'s own `trustProxyHeader` already established for this exact
   * class of decision — see that guard's doc.
   */
  trustProxyHeader?: boolean
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
export type SessionStatus =
  | 'active'
  | 'failed'
  | 'unconfirmed'
  | 'blocked'
  | 'revoked'

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

/** Common access-control fields shared by session/app token creation options. */
export type AppTokenBaseAccess = {
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

export type AppTokenOptions<T extends SessionTypes> = {
  /** User or API Id. */
  subject: string
  /**
   * The expiration, either as a human-readable
   * string (e.g., `"1h"`, `"15m"`, `"7d"`) or a numeric value in seconds.
   */
  expiration?: number | string
  /**
   * The JWT data payload.
   */
  payload?:
    & Omit<Partial<JWTPayload>, 'sub' | 'exp' | 'jit'>
    & AppTokenBaseAccess

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

/**
 * A duration string `parseTTL` (`@zanix/helpers`) accepts: a run of digits followed by one of its
 * supported unit suffixes — `s`/`m`/`h`/`d`/`w`/`mo`/`y` for seconds/minutes/hours/days/weeks/
 * months/years (e.g. `'45m'`, `'7d'`, `'6mo'`). `${number}` also matches shapes `parseTTL`'s own
 * digits-only pattern rejects (a decimal, a negative sign, scientific notation) — those still
 * reach `parseTTL` and throw there; TypeScript has no integer-only primitive to narrow this
 * further at the type level.
 */
export type TTLDuration = `${number}${'s' | 'm' | 'h' | 'd' | 'w' | 'mo' | 'y'}`

export type AccessTokenOptions<T extends SessionTypes> =
  & Omit<AppTokenOptions<T>, 'expiration'>
  & {
    expiration: TTLDuration | number
  }

export type RefreshTokenOptions<T extends SessionTypes> =
  & Omit<AppTokenOptions<T>, 'expiration'>
  & {
    expiration: TTLDuration | number
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

/**
 * The result of `deriveSessionTokenBase` (`utils/sessions/derive.ts`) — a cheaper alternative to
 * {@link SessionTokens} for a caller that only needs a request's session claims derived from an
 * already-issued refresh token, never a freshly signed access token string.
 */
export type DerivedSession = {
  /**
   * The refresh token now backing this session — the same one presented, reused as-is, when
   * `rotated` is `false`; a freshly minted replacement when `rotated` is `true`.
   */
  refreshToken: string
  /** Whether this call minted a new refresh token (and blocklisted the old one), or reused the
   * presented one unchanged. */
  rotated: boolean
  /** The refresh token presented to this call, before any rotation. */
  oldToken: string
  /** The presented refresh token's own decoded payload (before rotation). */
  payload: JWTPayload
}
