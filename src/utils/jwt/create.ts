import type { JWTHeader, JWTOptions, JWTPayload } from 'typings/jwt.ts'

import { DEFAULT_JWT_ISSUER, JWT_ALGTHM } from 'utils/constants.ts'
import {
  base64UrlEncode,
  encryptAES,
  generateHash,
  generateUUID,
  parseTTL,
  signHMAC,
  signRSA,
} from '@zanix/helpers'
import logger from '@zanix/logger'

/**
 * Create a signed JWT token with expiration and claim validation.
 *
 * @param payload - The payload to include in the JWT. Can contain custom claims (e.g., `exp`, `iss`, `aud`).
 * @param secret - The secret key used to sign the JWT.
 * @param options - The JWT configuration options.
 * @param {string} [options.jwtID] -Optional JWT unique identifier (jti). If not provided, the system will automatically generate one.
 * @param {string} [options.keyID] - Optional key ID or Version (if using multiple keys).
 * @param {number | Date} [options.expiration] - The expiration time in seconds (from now), or a `Date` object.
 * @param {JWTOptions['algorithm']} [options.algorithm] - The expected signing algorithm of the token (e.g., 'RS256', 'HS256', 'HS384'). Defaults to `HS256`
 * @param {JWTOptions['encryptionKey']} [options.encryptionKey] - The key used to encrypt or protect the payload's sensitive data. Required on RSA.
 * @returns The generated JWT string.
 *
 * @example
 * ```ts
 * const payload = { userId: 123, role: 'admin' };
 * const secret = 'your-secret-key';
 * const token = await createJWT(payload, secret, { expiration: 3600 });  // Token expires in 1 hour
 * console.log(token);
 * ```
 */
export const createJWT = async (
  { ...payload }: Partial<JWTPayload>,
  secret: string,
  options: {
    /**
     * Optional JWT unique identifier (jti).
     * If not provided, the system will automatically generate one.
     */
    jwtID?: string
    /** Optional key ID or Version (if using multiple keys). */
    keyID?: string
    /**
     * Expiration time as a human-readable
     * string (e.g., `"1h"`, `"15m"`, `"7d"`) or as a number in seconds.
     */
    expiration?: number | string
  } & JWTOptions = {},
): Promise<string> => {
  const { expiration, jwtID, encryptionKey, keyID, algorithm = 'HS256' } = options

  // Set expiration if not provided
  if (expiration) {
    const current = Math.floor(Date.now() / 1000)
    const exp = parseTTL(expiration)
    if (exp <= 0) {
      throw new Error('Expiration time must be greater than 0')
    }

    // Add expiration to payload
    payload.exp = current + exp
  }

  // Header (indicates the algorithm used)
  const header: JWTHeader = {
    alg: algorithm,
    typ: 'JWT',
    kid: keyID,
  }

  payload.jti = jwtID || generateUUID()
  payload.iss = payload.iss || DEFAULT_JWT_ISSUER

  const { hash, algthm } = JWT_ALGTHM[algorithm]
  const isRSA = algthm === 'RSA'

  const { secureData } = payload
  if (secureData) {
    if (isRSA && !encryptionKey) {
      logger.warn(
        'An encryption key is required to encrypt the secure data. This property should be omitted from the payload.',
        'noSave',
      )
      delete payload.secureData
    } else {
      const secretToEncrypt = await generateHash(
        (encryptionKey || secret) + payload.jti,
        'medium',
        false,
      )

      payload.secureData = await encryptAES(secureData, secretToEncrypt)
    }
  }

  // Encode header and payload to Base64 URL-safe strings
  const encodedHeader = base64UrlEncode(JSON.stringify(header))
  const encodedPayload = base64UrlEncode(JSON.stringify(payload))

  // Create the signature using the header, payload, and secret
  const data = `${encodedHeader}.${encodedPayload}`

  const signature = isRSA ? await signRSA(data, secret, hash) : await signHMAC(data, secret, hash)

  return `${data}.${base64UrlEncode(signature)}`
}
