import type { ScopedContext, ZanixCacheProvider, ZanixKVConnector } from '@zanix/server'
import type { SessionTokens } from 'typings/sessions.ts'
import type { JWTPayload } from 'typings/jwt.ts'

import { HttpError, PermissionDenied } from '@zanix/errors'
import { SESSION_HEADERS } from 'utils/constants.ts'
import { checkTokenBlockList } from './block-list.ts'
import { getSecretByToken } from '../jwt/secrets.ts'
import { generateSessionTokens } from './create.ts'
import { invalidRefreshTokenError } from './errors.ts'
import { verifyJWT } from '../jwt/verify.ts'

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

  const currentRefreshToken = token || ctx.cookies[tokenHeader]
  const secret = getSecretByToken(currentRefreshToken)

  const { metaError, error } = invalidRefreshTokenError('refreshSessionTokens')

  if (!currentRefreshToken) throw error

  const payload = await verifyJWT(currentRefreshToken, secret)

  if (!payload.access) {
    throw new HttpError('FORBIDDEN', {
      code: 'INVALID_TOKEN',
      cause: 'The provided refresh token is invalid. It appears to be an access token.',
      meta: metaError,
    })
  }

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
