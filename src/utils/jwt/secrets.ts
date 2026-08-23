import type { SessionTypes } from 'typings/sessions.ts'

import { decodeJWT } from './decode.ts'
import { HttpError } from '@zanix/errors'
import { JWK_PUB_ENV, JWT_KEY_ENV } from 'utils/constants.ts'

/**
 * Retrieves the secret key associated with a token and session type.
 *
 * This function decodes the provided JWT token, extracts the `kid` (key ID) from the header,
 * and determines the appropriate key name based on the session type ('user' or another type).
 * It then retrieves the secret from the environment variables.
 *
 * @param {string} token - The JWT token to decode and extract the `kid` from.
 * @param {SessionTypes} [type] - The type of session, typically 'user' or another value,
 *                               which influences the key name. Defaults to `'user'`.
 * @returns {string} The secret key resolved for the session type.
 *
 * @throws {HttpError} If the resolved environment variable for the key is missing.
 */
export const getSecretByToken = (
  token: string,
  type: SessionTypes = 'user',
): string => {
  const { header: { kid } } = decodeJWT(token)

  const keySuffix = kid ? `_${kid}` : ''

  const keyName = type === 'user' ? `${JWT_KEY_ENV}${keySuffix}` : `${JWK_PUB_ENV}${keySuffix}`
  const secret = Deno.env.get(keyName)

  if (secret) return secret

  throw new HttpError('INTERNAL_SERVER_ERROR', {
    message: `An error occurred during ${type} authentication.`,
    cause: `Missing required JWT key in environment variables: ${keyName}.`,
    meta: {
      source: 'zanix',
      method: 'getJWTKey',
      keyType: type,
      keyName: keyName,
    },
    exposeMeta: true,
    exposeCause: true,
  })
}
