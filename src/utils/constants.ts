import type { HashAlgorithm } from '@zanix/types'
import type { JWTAlgorithm } from 'typings/jwt.ts'

export const JWT_ALGTHM: Record<
  JWTAlgorithm,
  { algthm: 'RSA' | 'HMAC'; hash: Exclude<HashAlgorithm, 'SHA-1'> }
> = {
  'HS256': { algthm: 'HMAC', hash: 'SHA-256' },
  'HS384': { algthm: 'HMAC', hash: 'SHA-384' },
  'HS512': { algthm: 'HMAC', hash: 'SHA-512' },
  'RS256': { algthm: 'RSA', hash: 'SHA-256' },
  'RS384': { algthm: 'RSA', hash: 'SHA-384' },
  'RS512': { algthm: 'RSA', hash: 'SHA-512' },
}

export const IP_REGEX = /^(\d{1,3}\.){3}\d{1,3}$/

/**
 * Default `iss` claim used by {@link createJWT}/{@link verifyJWT} when a caller doesn't pass one,
 * and default `issuer` used by {@link getTOTPProvisioningUri} for the authenticator-app label.
 */
export const DEFAULT_AUTH_ISSUER = 'zanix-auth'

export const CACHE_KEYS = {
  jwtBlockList: 'zanix:jwt-block-list',
  jwtRotationGrace: 'zanix:jwt-rotation-grace',
  rateLimit: 'zanix:rate-limit',
  otp: 'zanix:otp',
}

/**
 * Fixed `aud` claim every service-credential assertion/exchange (see
 * `utils/sessions/service-exchange.ts`) is scoped to — prevents a self-signed assertion crafted
 * for this exchange from being replayed as some other kind of token, and vice versa.
 */
export const SERVICE_EXCHANGE_AUDIENCE = 'zanix:auth:service-exchange'

/** Default lifetime of a self-signed service assertion — kept short since it's presented once. */
export const SERVICE_ASSERTION_DEFAULT_EXP = '2m'

/** Default lifetime of the `type: 'api'` access token minted by a successful exchange. */
export const SERVICE_TOKEN_DEFAULT_EXP = '30m'

/**
 * Base env var name for the primary HMAC secret signing/verifying `type: 'user'` sessions (see
 * `utils/jwt/keys-rotation.ts#getRotatingKey`, `utils/jwt/secrets.ts#getSecretByToken`). Combined
 * with a `_V{n}` suffix for versioned rotation (`JWT_KEY_V1`, `JWT_KEY_V2`, ...), or with a
 * `_<kid>` suffix when a token's header already carries one.
 */
export const JWT_KEY_ENV = 'JWT_KEY'

/**
 * Base env var name for the RSA private key signing `type: 'api'` sessions (see
 * `utils/jwt/keys-rotation.ts#getRotatingKey`). Combined with a `_V{n}` suffix the same way as
 * {@link JWT_KEY_ENV}.
 */
export const JWK_PRI_ENV = 'JWK_PRI'

/**
 * Base env var name for the RSA public key verifying `type: 'api'` sessions (see
 * `utils/jwt/secrets.ts#getSecretByToken`). Combined with a `_<kid>` suffix when the token's
 * header already carries one.
 */
export const JWK_PUB_ENV = 'JWK_PUB'

/**
 * Env var controlling how often `getRotatingKey` (`utils/jwt/keys-rotation.ts`) rotates among the
 * versioned `JWT_KEY_V{n}`/`JWK_PRI_V{n}` keys — a TTL string (e.g. `'30d'`, `'12h'`), or the
 * literal `'0'` to disable rotation. Defaults to `'30d'` when unset.
 */
export const JWK_ROTATION_CYCLE_ENV = 'JWK_ROTATION_CYCLE'

/**
 * Base env var prefix identifying which of a calling service's registered keys signed a
 * self-signed assertion — combined with `_<serviceId>` (see
 * `utils/sessions/service-exchange.ts#resolveServiceAssertionKeyId`).
 */
export const JWK_ID_ENV = 'JWK_ID'

/**
 * Base env var prefix granting permissions to a service-credential exchange — combined with
 * `_<serviceId>` (see `utils/sessions/service-exchange.ts#exchangeServiceCredential`). A
 * comma-separated list; never derived from anything the calling service itself sends.
 */
export const SERVICE_PERMISSIONS_ENV = 'SERVICE_PERMISSIONS'

/**
 * Base env var prefix setting the rate-limit claim minted for a service-credential exchange —
 * combined with `_<serviceId>` (see `utils/sessions/service-exchange.ts#exchangeServiceCredential`).
 */
export const SERVICE_RATE_LIMIT_ENV = 'SERVICE_RATE_LIMIT'

/**
 * Env var naming the Redis connection URI. Its mere presence (not its value) selects the
 * Redis-backed path over the in-memory local cache across OTP (`utils/otp.ts`), the JWT block
 * list (`utils/sessions/block-list.ts`), and rate limiting (`utils/sessions/rate-limit.ts`).
 */
export const REDIS_URI_ENV = 'REDIS_URI'

/**
 * Env var controlling the rotation grace window: how long, in seconds, a just-rotated refresh
 * token keeps its already-issued replacement pair retrievable instead of outright rejecting a
 * second presentation of that same token as blocklisted (`utils/sessions/block-list.ts#{@link
 * getRotationGraceTokens}`/`{@link setRotationGraceTokens}`, consulted from
 * `utils/sessions/refresh.ts#refreshSessionTokensBase`). A TTL string (e.g. `'5s'`, `'10s'`) or a
 * bare number of seconds; `'0'` disables the grace window outright, making rotation strictly
 * single-use with no tolerance window. Defaults to `'5s'` when unset.
 *
 * This exists because a single-use refresh token has no tolerance, by itself, for two legitimate
 * requests that both present the same still-valid token within a short window of each other — a
 * browser prefetching a link on hover and then navigating it, a double click, two tabs sharing one
 * session, or a client's own retry after a slow response. Without this window, whichever of the two
 * requests reaches the blocklist check second is rejected outright, even though it carried the same
 * legitimate token as the one that won.
 */
export const ROTATION_GRACE_WINDOW_ENV = 'ROTATION_GRACE_WINDOW'

/**
 * Default `accessExpiration` (`AuthSessionOptions`) whenever a caller doesn't provide one —
 * shared by every place that needs this default: `generateSessionTokens`, `buildAccessTokenClaims`,
 * `deriveSessionTokenBase`, and `mintAccessTokenBase`. Centralized so those can't silently drift
 * apart on what "the default" actually is.
 */
export const DEFAULT_ACCESS_EXPIRATION = '1h'

/**
 * Default `refreshExpiration` (`AuthSessionOptions`) whenever a caller doesn't provide one — see
 * {@link DEFAULT_ACCESS_EXPIRATION}'s own doc for why this lives here instead of as a repeated
 * literal at each call site.
 */
export const DEFAULT_REFRESH_EXPIRATION = '1y'

/**
 * Minimum multiple `refreshExpiration` must be over `accessExpiration` (`AuthSessionOptions`,
 * enforced by `generateSessionTokens`). Exists to leave real margin between the refresh token's
 * own absolute lifetime and the cadence `deriveSessionTokenBase` (`utils/sessions/derive.ts`)
 * rotates it at — which is itself driven by `accessExpiration`, the "how old is too old" freshness
 * threshold a presented refresh token gets checked against before deciding whether to reuse it or
 * mint a replacement.
 *
 * Without this margin, a session that goes quiet right around the moment it crosses that freshness
 * threshold can have its refresh token expire for real — a `verifyJWT` rejection, which runs
 * BEFORE any rotation decision ever gets a chance to run — instead of rotating cleanly on its next
 * use. A margin of `MIN_REFRESH_TO_ACCESS_RATIO` guarantees at least one full `accessExpiration`
 * window of slack past the freshness threshold before that can happen, so a session that returns
 * at any point before its refresh token's own absolute expiry always gets a clean rotation instead
 * of a forced re-login.
 */
export const MIN_REFRESH_TO_ACCESS_RATIO = 3
