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

export const AUTH_HEADERS = {
  api: 'X-Znx-Authorization',
  user: 'Authorization',
}

export const SESSION_HEADERS = {
  api: {
    sub: 'X-Znx-Api-Id',
    session: 'X-Znx-Api-Session-Status',
    token: undefined,
  },
  user: {
    sub: 'X-Znx-User-Id',
    session: 'X-Znx-User-Session-Status',
    token: 'X-Znx-App-Token',
  },
}

export const RATE_LIMIT_HEADERS = {
  limitHeader: 'X-Znx-RateLimit-Limit',
  remainingHeader: 'X-Znx-RateLimit-Remaining',
  resetHeader: 'X-Znx-RateLimit-Reset',
  retryAfterHeader: 'Retry-After',
}

export const GENERAL_HEADERS = {
  cookiesAcceptedHeader: 'X-Znx-Cookies-Accepted',
}

export const DEFAULT_JWT_ISSUER = 'zanix-auth'

export const CACHE_KEYS = {
  jwtBlockList: 'zanix:jwt-block-list',
  rateLimit: 'zanix:rate-limit',
  otp: 'zanix:otp',
}
