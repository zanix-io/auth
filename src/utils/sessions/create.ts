import type { ScopedContext } from '@zanix/server'
import type { AuthSessionOptions } from 'typings/auth.ts'
import type { JWTPayload } from 'typings/jwt.ts'
import type {
  AccessTokenOptions,
  AppTokenOptions,
  RefreshTokenOptions,
  SessionTokens,
  SessionTypes,
} from 'typings/sessions.ts'

import { getRotatingKey } from 'utils/jwt/keys-rotation.ts'
import { HttpError, InternalError } from '@zanix/errors'
import { defineLocalSession } from './context.ts'
import { createJWT } from 'utils/jwt/create.ts'
import { decodeJWT } from 'utils/jwt/decode.ts'
import { parseTTL } from '@zanix/helpers'
import {
  DEFAULT_ACCESS_EXPIRATION,
  DEFAULT_AUTH_ISSUER,
  DEFAULT_REFRESH_EXPIRATION,
  JWK_PRI_ENV,
  JWT_KEY_ENV,
  MIN_REFRESH_TO_ACCESS_RATIO,
} from 'utils/constants.ts'

/** Get JWT secret */
const getCurrentSecret = (
  type: SessionTypes,
): { value: string; version?: `V${number}` } => {
  const isRSA = type === 'api'
  const keyName = isRSA ? JWK_PRI_ENV : JWT_KEY_ENV

  const secret = getRotatingKey(keyName)

  if (secret.value) return { ...secret, value: secret.value }

  throw new InternalError(
    `An error occurred while creating the ${type} session.`,
    {
      code: 'AUTH_SESSION_JWT_KEY_MISSING',
      cause: `Missing required JWT key in environment variables: ${keyName}.`,
      meta: {
        source: 'zanix',
        method: 'getJWTKey',
        keyType: type,
        keyName: keyName,
      },
    },
  )
}

/**
 * Resolves the final claims `createAppToken` signs from its raw `subject`/`payload` inputs —
 * `aud` from `payload.permissions` (falling back to an already-set `payload.aud`), `rateLimit`
 * defaulted to `100`, and `sub` from `subject`. Extracted so `deriveSessionTokenBase`
 * (`utils/sessions/derive.ts`) can build the exact same claims shape a real access token would
 * carry — for populating a local session — without signing anything, keeping the two derivations
 * from silently drifting apart.
 *
 * @param payload - The raw payload passed to {@link createAppToken}.
 * @param subject - The token subject.
 * @returns The resolved claims, ready to sign (or, for a claims-only caller, to use as-is).
 */
function resolveAppTokenClaims(
  payload: AppTokenOptions<SessionTypes>['payload'],
  subject: string,
): Partial<JWTPayload> {
  const aud = payload?.permissions || payload?.aud
  const rateLimit = payload?.rateLimit || 100
  const rest = { ...payload }
  delete rest.permissions

  return { ...rest, aud, rateLimit, sub: subject }
}

/**
 * Builds the `payload` a user access token mints from an `AuthSessionOptions` — the `jit`/
 * `permissions`/`rateLimit` merge every access-token-for-a-session call applies before either
 * signing one ({@link generateSessionTokens}, `mintAccessTokenBase` in
 * `utils/sessions/mint-access-token.ts`) or building the equivalent claims without signing
 * ({@link buildAccessTokenClaims}). Extracted so these three call sites share one definition
 * instead of maintaining three copies that can silently drift apart on which fields carry over.
 *
 * @param options - The `AuthSessionOptions` to derive an access token's payload from.
 * @returns The `payload` to pass into {@link createAccessToken}/{@link resolveAppTokenClaims}.
 */
export function toAccessTokenPayload(
  options: AuthSessionOptions,
): AppTokenOptions<'user'>['payload'] {
  const { id, rateLimit, permissions, payload } = options
  return { ...payload, jit: id || payload?.jit, permissions, rateLimit }
}

/**
 * Creates a signed app JWT token for a given user or API subject.
 *
 * Depending on the provided `type`, the function selects the appropriate
 * signing algorithm and key source. It also supports optional payload data
 * and encryption for sensitive content.
 *
 * This function relies on {@link getRotatingKey} to automatically resolve the
 * currently active signing key, enabling seamless key rotation without
 * disrupting token issuance.
 *
 * ### ⚠️ Security Recommendations
 * - Always set a reasonable expiration time for issued tokens.
 * - During key rotation, ensure all previous key versions remain available
 *   for verification until all tokens signed with them have expired.
 *
 * @template T extends SessionTypes
 * @param {Object} options - Token creation options.
 * @param {string} options.subject - User or API identifier (`sub` claim).
 * @param {number|string} options.expiration - Expiration time as a human-readable
 * string (e.g., `"1h"`, `"15m"`, `"7d"`) or as a number in seconds.
 * @param {Omit<Partial<JWTPayload>, 'sub' | 'exp' | 'jit'>} [options.payload] -
 * Additional JWT payload fields (excluding reserved claims).
 * @param {T} options.type - Session type; determines algorithm selection,
 * expected environment keys, and authentication header extraction.
 * @param {('api' extends T ? string : never)} [options.encryptionKey] -
 * Key used to encrypt/protect sensitive payload fields. **Required for `api` sessions.**
 *
 * @returns {Promise<string>} A promise that resolves to the generated JWT token.
 *
 * @throws {InternalError} If the required signing key is missing in environment variables.
 * @throws {HttpError} If token creation fails due to invalid payload, expiration, or signing issues.
 *
 * @example
 * // Create a user session token (HS256)
 * const token = await createAppToken({
 *   subject: "user_123",
 *   type: "user",
 *   expiration: "1h",
 *   payload: { permissions: "admin" },
 * });
 *
 * @example
 * // Create an API session token (RS256)
 * const token = await createAppToken({
 *   subject: "service_abc",
 *   type: "api",
 *   expiration: 3600,
 *   encryptionKey: Deno.env.get('API_ENCRYPTION_KEY'),
 * });
 */
export const createAppToken = async <T extends SessionTypes>(
  options: AppTokenOptions<T>,
): Promise<string> => {
  const { subject, expiration, type, payload, encryptionKey } = options

  const isRSA = type === 'api'
  const algorithm = isRSA ? 'RS256' : 'HS256'

  const { value: secret, version } = getCurrentSecret(type)

  try {
    const token = await createJWT(
      resolveAppTokenClaims(payload, subject),
      isRSA ? atob(secret) : secret,
      {
        keyID: version,
        expiration,
        algorithm,
        encryptionKey,
      },
    )
    return token
  } catch (e) {
    throw new HttpError('INTERNAL_SERVER_ERROR', {
      message: `An error occurred while creating the ${type} session token.`,
      cause: e,
      meta: {
        source: 'zanix',
        method: 'createJWT',
        sessionType: type,
      },
    })
  }
}

/**
 * Creates an access token with a maximum expiration time of 1 hour.
 *
 * This function relies on {@link getRotatingKey} to automatically resolve the
 * currently active signing key, enabling seamless key rotation without
 * disrupting token issuance.
 *
 * ### ⚠️ Security Recommendations
 * - Always set a reasonable expiration time for issued tokens.
 * - During key rotation, ensure all previous key versions remain available
 *   for verification until all tokens signed with them have expired.
 *
 * @template T - Session type extending `SessionTypes`.
 *
 * @param {ScopedContext} ctx Request scoped context
 * @param {AccessTokenOptions<T>} options
 * Options used to generate the token.
 * - `expiration`: The expiration time, either as a human-readable string
 *   (e.g., `'30m'`, `'1h'`) or a numeric value in seconds.
 *
 * @throws {InternalError} If the expiration exceeds 1 hour.
 *
 * @returns {Promise<SessionTokens['accessToken']>} The generated access token.
 */
export const createAccessToken = async <T extends SessionTypes>(
  ctx: ScopedContext,
  options: AccessTokenOptions<T>,
): Promise<SessionTokens['accessToken']> => {
  const exp = parseTTL(options.expiration)

  if (exp > 3600) {
    throw new InternalError(
      'Access token expiration should not exceed 1 hour',
      {
        code: 'ACCESS_TOKEN_EXP_TOO_LONG',
        meta: {
          source: 'zanix',
          expiration: exp,
        },
      },
    )
  }

  const token = await createAppToken(options)
  const { payload } = decodeJWT(token)

  defineLocalSession(ctx, { type: options.type, payload, status: 'active' })

  return token
}

/**
 * Creates a refresh token with long-term expiration options.
 *
 * This function relies on {@link getRotatingKey} to automatically resolve the
 * currently active signing key, enabling seamless key rotation without
 * disrupting token issuance.
 *
 * ### ⚠️ Security Recommendations
 * - Always set a reasonable expiration time for issued tokens.
 * - During key rotation, ensure all previous key versions remain available
 *   for verification until all tokens signed with them have expired.
 *
 * @template T - Session type extending `SessionTypes`.
 *
 * @param {RefreshTokenOptions<T>} options
 * Options used to generate the token.
 * - `expiration`: The allowed expiration time for a refresh token.
 *
 * @returns {Promise<SessionTokens['refreshToken']>} The generated refresh token.
 */
export const createRefreshToken = <T extends SessionTypes>(
  options: RefreshTokenOptions<T>,
): Promise<SessionTokens['refreshToken']> => {
  return createAppToken(options)
}

/**
 * Generates a pair of session tokens (access and refresh) for a given user and context.
 *
 * @param {ScopedContext} ctx - The scoped request context in which the access token will be created.
 * @param {AuthSessionOptions} options
 *   Configuration for the session tokens:
 *   - `subject`: The identifier (e.g., user email or ID) for which the tokens are generated.
 *   - `rateLimit`: Optional custom configuration for the token rate limit. Defaults to `100`
 *   - `permissions`: Optional custom configuration for the token aud.
 *   - `accessExpiration`: Optional access token lifetime. Defaults to `'1h'`.
 *   - `refreshExpiration`: Optional refresh token lifetime. Defaults to `'1y'`. Must be at least
 *     `MIN_REFRESH_TO_ACCESS_RATIO` times `accessExpiration`.
 *
 * `options` (including `accessExpiration`/`refreshExpiration`) is embedded whole into the refresh
 * token's own payload (`payload.access`, below) — so a session's chosen expiration policy carries
 * forward automatically into every later `deriveSessionTokenBase`/`refreshSessionTokensBase` call
 * for that same session, without a caller having to re-specify it on each rotation.
 *
 * @returns {Promise<{ accessToken: string; refreshToken: string;}>}
 * A promise resolving to an object containing:
 *   - `accessToken`: The generated access token.
 *   - `refreshToken`: The generated refresh token.
 *
 * @throws {InternalError} If `refreshExpiration` isn't at least `MIN_REFRESH_TO_ACCESS_RATIO`
 * times `accessExpiration` — a configuration mistake, not something a request could trigger.
 *
 * @example
 * ```ts
 * const tokens = await generateSessionTokens(ctx, {
 *   subject: 'user@example.com',
 * });
 *
 * console.log(tokens.accessToken); // JWT access token
 * console.log(tokens.refreshToken); // JWT refresh token
 * ```
 */
export const generateSessionTokens = async (
  ctx: ScopedContext,
  options: AuthSessionOptions,
): Promise<SessionTokens> => {
  const {
    subject,
    accessExpiration = DEFAULT_ACCESS_EXPIRATION,
    refreshExpiration = DEFAULT_REFRESH_EXPIRATION,
  } = options

  const accessExp = parseTTL(accessExpiration)
  const refreshExp = parseTTL(refreshExpiration)

  if (refreshExp < accessExp * MIN_REFRESH_TO_ACCESS_RATIO) {
    throw new InternalError(
      `refreshExpiration must be at least ${MIN_REFRESH_TO_ACCESS_RATIO} times accessExpiration`,
      {
        code: 'AUTH_SESSION_INVALID_EXPIRATION',
        meta: {
          source: 'zanix',
          accessExpiration: accessExp,
          refreshExpiration: refreshExp,
          minRatio: MIN_REFRESH_TO_ACCESS_RATIO,
        },
      },
    )
  }

  const sessionAccessToken = await createAccessToken(ctx, {
    expiration: accessExpiration,
    subject,
    type: 'user',
    payload: toAccessTokenPayload(options),
  })

  const sessionRefreshToken = await createRefreshToken({
    expiration: refreshExpiration,
    subject,
    type: 'user',
    payload: { access: options },
  })

  Object.assign(ctx.locals.session as object, { token: sessionRefreshToken })

  return {
    accessToken: sessionAccessToken,
    refreshToken: sessionRefreshToken,
  }
}

/**
 * Builds the exact claims shape a real user access token would carry for `options` — same `aud`/
 * `rateLimit`/`jit` derivation {@link generateSessionTokens} applies before signing one — without
 * signing anything. For `deriveSessionTokenBase` (`utils/sessions/derive.ts`), which only needs a
 * {@link defineLocalSession}-ready payload to populate a request's local session from an
 * already-verified refresh token's own embedded `payload.access`, never a real JWT string.
 *
 * @param options - The `AuthSessionOptions` embedded in an already-verified refresh token
 * (`payload.access`), optionally merged with a caller's own overrides.
 * @returns Claims shaped exactly like a freshly decoded access token's payload, including a fresh
 * `jti` and an `exp` computed from `options.accessExpiration` (default `'1h'`) — so a consumer of
 * `ctx.locals.session.payload` sees the same shape regardless of whether a real access token was
 * ever minted for this request.
 */
export function buildAccessTokenClaims(options: AuthSessionOptions): JWTPayload {
  const { subject, accessExpiration = DEFAULT_ACCESS_EXPIRATION } = options

  const claims = resolveAppTokenClaims(toAccessTokenPayload(options), subject)

  return {
    ...claims,
    jti: crypto.randomUUID(),
    iss: claims.iss ?? DEFAULT_AUTH_ISSUER,
    exp: Math.floor(Date.now() / 1000) + parseTTL(accessExpiration),
  } as JWTPayload
}

/**
 * Applies an already-issued session token pair onto `ctx.locals.session`, decoding `tokens.accessToken`
 * to derive the same fields {@link defineLocalSession} sets when a pair is freshly minted by
 * {@link generateSessionTokens} — `type` is always `'user'`, matching what `generateSessionTokens`
 * itself always mints.
 *
 * Exists for `refreshSessionTokensBase`'s rotation grace window: when it hands back a pair
 * `generateSessionTokens` already issued for an earlier request instead of minting a new one, the
 * CURRENT request's `ctx.locals.session` still needs populating exactly as it would have been the
 * first time — permission checks and response interceptors downstream (e.g. `permissionsPipe`,
 * `sessionHeadersInterceptor`) read it unconditionally, with no awareness that this pair came from
 * the grace cache rather than a fresh `generateSessionTokens` call.
 *
 * @param {ScopedContext} ctx - The scoped context whose `locals.session` gets populated.
 * @param {SessionTokens} tokens - The already-issued pair to apply.
 */
export const applySessionTokens = (ctx: ScopedContext, tokens: SessionTokens): void => {
  const { payload } = decodeJWT(tokens.accessToken)

  defineLocalSession(ctx, { type: 'user', payload, status: 'active' })
  Object.assign(ctx.locals.session as object, { token: tokens.refreshToken })
}
