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
