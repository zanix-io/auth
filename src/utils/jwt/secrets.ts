import type { SessionTypes } from 'typings/sessions.ts'

import { decodeJWT } from './decode.ts'
import { HttpError } from '@zanix/errors'

/**
 * Retrieves the secret key associated with a token and session type.
 *
 * This function decodes the provided JWT token, extracts the `kid` (key ID) from the header,
 * and determines the appropriate key name based on the session type ('user' or another type).
 * It then retrieves the secret from the environment variables.
 *
 * @param {string} token - The JWT token to decode and extract the `kid` from.
 * @param {SessionTypes} type - The type of session, typically 'user' or another value,
 *                               which influences the key name.
 * @returns {string | undefined} - The secret key for the session type, or `undefined`
 *                                  if the key is not found in the environment.
 *
 * @throws {Error} - If the `token` cannot be decoded or the `kid` is invalid.
 */
export const getSecretByToken = (token: string, type: SessionTypes = 'user'): string => {
  const { header: { kid } } = decodeJWT(token)

  const keySuffix = kid ? `_${kid}` : ''

  const keyName = type === 'user' ? `JWT_KEY${keySuffix}` : `JWK_PUB${keySuffix}`
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
  })
}
