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
