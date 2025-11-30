import type { ScopedContext, ZanixCacheProvider, ZanixKVConnector } from '@zanix/server'
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
import { HttpError, InternalError, PermissionDenied } from '@zanix/errors'
import { SESSION_HEADERS } from 'utils/constants.ts'
import { defineLocalSession } from './context.ts'
import { createJWT } from 'utils/jwt/create.ts'
import { decodeJWT } from 'utils/jwt/decode.ts'
import { verifyJWT } from '../jwt/verify.ts'
import { parseTTL } from '@zanix/helpers'
import { checkTokenBlockList } from './block-list.ts'

/** Get JWT secret */
const getSecret = (type: SessionTypes) => {
  const isRSA = type === 'api'
  const keyName = isRSA ? 'JWK_PRI' : 'JWT_KEY'

  const secret = getRotatingKey(keyName)

  if (secret) return secret

  throw new InternalError(`An error occurred while creating the ${type} session.`, {
    cause: `Missing required JWT key in environment variables: ${keyName}.`,
    meta: {
      source: 'zanix',
      method: 'getJWTKey',
      keyType: type,
      keyName: keyName,
    },
  })
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

  const secret = getSecret(type)

  try {
    const aud = payload?.permissions || payload?.aud
    const rateLimit = payload?.rateLimit || 100

    delete payload?.permissions

    const token = await createJWT(
      { ...payload, aud, rateLimit, sub: subject },
      isRSA ? atob(secret) : secret,
      {
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
    throw new InternalError('Access token expiration should not exceed 1 hour', {
      code: 'ACCESS_TOKEN_EXP_TOO_LONG',
      meta: {
        source: 'zanix',
        expiration: exp,
      },
    })
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
 *
 * @returns {Promise<{ accessToken: string; refreshToken: string;}>}
 * A promise resolving to an object containing:
 *   - `accessToken`: The generated access token.
 *   - `refreshToken`: The generated refresh token.
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
  const { subject, id, rateLimit, permissions, payload } = options

  const sessionAccessToken = await createAccessToken(ctx, {
    expiration: '1h',
    subject,
    type: 'user',
    payload: { ...payload, jit: id || payload?.jit, permissions, rateLimit },
  })

  const sessionRefreshToken = await createRefreshToken({
    expiration: '1y',
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
 * Refreshes the session tokens using the provided JWT.
 *
 * Decodes the given token to extract its payload and generates a new
 * set of session tokens based on the existing access data.
 *
 * @param {ScopedContext} ctx
 *   The scoped context containing configuration and services required
 *   for token generation.
 *
 * @param {string} [token]
 *   Optional JWT whose payload will be decoded to refresh the session.
 *   If omitted, the token will be retrieved from the current context, provided cookies are available.
 *
 * @param options - Options for check block list validation
 * @param {ZanixCacheProvider} [options.cache] - Cache provider.
 * @param {ZanixKVConnector} [options.kvDb] - Key-value store connector.
 * @returns {Promise<SessionTokens & { oldToken: string, payload: JWTPayload }>>}
 *   A promise that resolves with the newly generated session tokens and de older one.
 */
export const refreshSessionTokens = async (
  ctx: ScopedContext,
  token?: string,
  options: {
    cache?: ZanixCacheProvider
    kvDb?: ZanixKVConnector
  } = {},
): Promise<SessionTokens & { oldToken: string; payload: JWTPayload }> => {
  const { token: tokenHeader } = SESSION_HEADERS['user']
  const secret = getSecret('user')

  const currentRefreshToken = token || ctx.cookies[tokenHeader]

  if (!currentRefreshToken) {
    throw new HttpError('INTERNAL_SERVER_ERROR', {
      code: 'INVALID_TOKEN',
      cause: 'Refresh token is undefined and cannot be used to refresh the session.',
      meta: {
        source: 'zanix',
        method: 'refreshSessionTokens',
        suggestion:
          'Provide a valid token to this method or ensure that the required cookies are available.',
      },
    })
  }

  const payload = await verifyJWT(currentRefreshToken, secret)

  // check token in block list
  if (options.cache && options.kvDb) {
    const isInBlockList = await checkTokenBlockList(
      payload.jti,
      options.cache,
      options.kvDb,
    )

    if (isInBlockList) {
      throw new PermissionDenied('The refresh token has been revoked or is blocklisted.')
    }
  }

  const tokens = await generateSessionTokens(ctx, payload.access)

  return { ...tokens, oldToken: currentRefreshToken, payload }
}
