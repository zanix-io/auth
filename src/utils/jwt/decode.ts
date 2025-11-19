import type { JWT, JWTHeader, JWTPayload } from 'typings/jwt.ts'

import { base64UrlDecode } from '@zanix/helpers'
import { PermissionDenied } from '@zanix/errors'

/**
 * Decodes a JSON Web Token (JWT) without verifying its signature.
 *
 * This function parses a JWT string and returns its header, payload, and signature
 * as a structured object. Note that this does not validate the token's signature
 * or expiration; it only decodes the token's contents.
 *
 * @param {string} token - The JWT string to decode.
 * @returns {JWT} The decoded JWT containing `header`, `payload`, and `signature`.
 *
 * @example
 * ```ts
 * const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
 * const decoded = decodeJWT(token);
 * console.log(decoded.header);
 * console.log(decoded.payload);
 * console.log(decoded.signature);
 * ```
 */
export const decodeJWT = (
  token: string,
): JWT => {
  try {
    const [encodedHeader, encodedPayload, encodedSignature] = token.split('.')
    // Decode the payload
    const payload: JWTPayload = JSON.parse(base64UrlDecode(encodedPayload, true))
    const header: JWTHeader = JSON.parse(base64UrlDecode(encodedHeader, true))

    return {
      payload,
      header,
      signature: encodedSignature,
    }
  } catch {
    throw new PermissionDenied('The provided token has an invalid format', {
      code: 'INVALID_TOKEN',
      meta: { source: 'zanix' },
    })
  }
}
