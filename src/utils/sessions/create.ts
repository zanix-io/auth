import type { HandlerContext, ScopedContext } from '@zanix/server'
import type { AuthSessionOptions } from 'typings/auth.ts'
import type { JWTPayload } from 'typings/jwt.ts'
import type {
  AccessTokenOptions,
  AppTokenOptions,
  RefreshTokenOptions,
  SessionStatus,
  SessionTokens,
  SessionTypes,
} from 'typings/sessions.ts'

import { getRotatingKey } from 'utils/jwt/keys-rotation.ts'
import { HttpError, InternalError } from '@zanix/errors'
import { createJWT } from 'utils/jwt/create.ts'
import { parseTTL } from '@zanix/helpers'
import { decodeJWT } from 'utils/jwt/decode.ts'

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

  const algorithm = type === 'api' ? 'RS256' : 'HS256'

  const keyName = type === 'user' ? `JWT_KEY` : `JWK_PRI`
  const secret = getRotatingKey(keyName)

  if (!secret) {
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

  try {
    const aud = payload?.permissions || payload?.aud
    const rateLimit = payload?.rateLimit || 100

    const token = await createJWT({ aud, rateLimit, ...payload, sub: subject }, secret, {
      expiration,
      algorithm,
      encryptionKey,
    })
    return token
  } catch (e) {
    throw new HttpError('BAD_REQUEST', {
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
      code: 'ERR_ACCESS_TOKEN_TOO_LONG',
      meta: {
        source: 'zanix',
        expiration: exp,
      },
    })
  }

  const token = await createAppToken(options)
  const { payload } = decodeJWT(token)

  localSessionDefinition(ctx, { type: options.type, payload, status: 'active' })

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
 * Generates a pair of session tokens (access and refresh) for a given subject and context.
 *
 * @template T - The session type, extending `SessionTypes` (e.g., 'user', 'admin', etc.).
 *
 * @param {ScopedContext} ctx - The scoped request context in which the access token will be created.
 * @param {AuthSessionOptions<T> & { subject: string; type?: T }} sessionTokens
 *   Configuration for the session tokens:
 *   - `subject`: The identifier (e.g., user email or ID) for which the tokens are generated.
 *   - `type`: Optional type of session, defaults to `'user'`.
 *   - `access`: Optional custom configuration for the access token.
 *   - `refresh`: Optional custom configuration for the refresh token.
 *
 * @returns {Promise<{
 *   accessToken: string;
 *   refreshToken: string;
 *   subject: string;
 * }>} A promise resolving to an object containing:
 *   - `accessToken`: The generated access token.
 *   - `refreshToken`: The generated refresh token.
 *   - `subject`: The subject for whom the tokens were generated.
 *
 * @example
 * ```ts
 * const tokens = await generateSessionTokens(ctx, {
 *   subject: 'user@example.com',
 *   type: 'user',
 *   access: { expiration: '2h' },
 *   refresh: { expiration: '30d' },
 * });
 *
 * console.log(tokens.accessToken); // JWT access token
 * console.log(tokens.refreshToken); // JWT refresh token
 * ```
 */
export const generateSessionTokens = async <T extends SessionTypes>(
  ctx: ScopedContext,
  sessionTokens: AuthSessionOptions<T> & { subject: string; type?: T },
): Promise<SessionTokens> => {
  const { access, refresh, subject, type = 'user' as T } = sessionTokens

  const sessionAccessToken = await createAccessToken<T>(ctx, {
    expiration: '1h',
    subject,
    type,
    ...access,
  })

  const sessionRefreshToken = await createRefreshToken<T>({
    expiration: '1y',
    subject,
    type,
    ...refresh,
  })

  return {
    accessToken: sessionAccessToken,
    refreshToken: sessionRefreshToken,
  }
}

/**
 * Assigns a session object to the `locals` of the given context.
 *
 * Extracts relevant fields from the provided JWT payload and stores
 * them as a structured session in `context.locals.session`.
 *
 * This allows middlewares, handlers, or extensions to access
 * the session during the lifetime of the request.
 *
 * @param context - The current request context, either a `HandlerContext` or a `ScopedContext`.
 * @param {SessionTypes} options.type - The type of session being created (from `SessionTypes`).
 * @param {JWTPayload} options.payload - The JWT payload containing session information.
 * @param {SessionStatus} [options.status] - The optional session status.
 */
export const localSessionDefinition = (
  context: HandlerContext | ScopedContext,
  options: { type: SessionTypes; payload: JWTPayload; status?: SessionStatus },
) => {
  const { type, payload, status } = options
  const { jti, rateLimit: trl, sub: subject, aud, ...rest } = payload

  // Assign a session to the context
  context.locals.session = {
    type,
    id: jti,
    rateLimit: trl,
    scope: typeof aud === 'string' ? [aud] : aud,
    payload: rest,
    subject,
    status,
  }
}
