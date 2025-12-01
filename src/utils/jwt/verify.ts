import type { JWTPayload, JWTVerifyOptions } from 'typings/jwt.ts'

import { base64UrlDecode, decryptAES, generateHash, verifyHMAC, verifyRSA } from '@zanix/helpers'
import { PermissionDenied } from '@zanix/errors'
import { scopeValidation } from 'utils/scope.ts'
import { DEFAULT_JWT_ISSUER, JWT_ALGTHM } from 'utils/constants.ts'
import logger from '@zanix/logger'

/**
 * Verify the JWT token and validate its claims, including expiration (`exp`), issuer (`iss`), and audience (`aud`).
 *
 * @param token - The JWT string to verify.
 * @param secret - The secret key used to verify the JWT.
 * @param options - Optional verification options (e.g., `iss`, `aud`, `algotithm`).
 * @param {string} [options.iss] - The expected token issuer. If provided, it validates that the iss claim matches this value; otherwise, it uses the system's default issuer.
 * @param {string} [options.aud] - The expected audience of the token. If provided, it will validate that the `aud` claim in the token matches this value.
 * @param {JWTOptions['algorithm']} [options.algorithm] - The expected signing algorithm of the token (e.g., 'RS256', 'HS256', 'HS384'). Defaults to `HS256`
 * @param {JWTOptions['encryptionKey']} [options.encryptionKey] - The key used to encrypt or protect the payload's sensitive data. Required on RSA.
 *
 * @throws {Error} Throws an error if the JWT is not valid.
 *
 * @returns the token decoded payload if the JWT is valid.
 *
 * @example
 * ```ts
 * const token = 'your.jwt.token';
 * const secret = 'your-secret-key';
 * const options = { iss: 'your-issuer', aud: 'your-audience' };
 * const isValid = await verifyJWT(token, secret, options);
 * console.log(isValid); // true or false
 * ```
 */
export const verifyJWT = async (
  token: string,
  secret: string,
  options: JWTVerifyOptions = {},
): Promise<JWTPayload> => {
  const { algorithm = 'HS256', iss = DEFAULT_JWT_ISSUER, aud, sub, encryptionKey } = options
  const [encodedHeader, encodedPayload, encodedSignature] = token.split('.')

  // Recreate the data part (header + payload) to check against the signature
  const data = `${encodedHeader}.${encodedPayload}`

  const signature = base64UrlDecode(encodedSignature)

  const { hash, algthm } = JWT_ALGTHM[algorithm]
  const isRSA = algthm === 'RSA'

  // Verify the signature
  const isSignatureValid = isRSA
    ? await verifyRSA(data, signature, secret, hash)
    : await verifyHMAC(data, signature, secret, hash)

  if (!isSignatureValid) {
    throw new PermissionDenied('Token signature is invalid', {
      code: 'INVALID_TOKEN_SIGNATURE',
      cause: 'The provided token signature does not match the expected signature',
      meta: { source: 'zanix' },
    })
  }

  // Decode the payload
  const payload: JWTPayload = JSON.parse(base64UrlDecode(encodedPayload, true))

  // Decrypt encrypted data
  if (payload.secureData) {
    if (isRSA && !encryptionKey) {
      logger.warn('Encryption key is required to decrypt the secure data', 'noSave')
    } else {
      const secretToDecrypt = await generateHash(
        (encryptionKey || secret) + payload.jti,
        'medium',
        false,
      )
      payload.secureData = await decryptAES(payload.secureData, secretToDecrypt).catch(() => {
        logger.warn(
          "Failed to decrypt payload's secure data. Please verify the encryption key",
          'noSave',
        )

        return payload.secureData
      })
    }
  }

  // Check for expiration (exp)
  const currentTime = Math.floor(Date.now() / 1000)

  if (payload.exp && currentTime > payload.exp) {
    throw new PermissionDenied('Token has expired', {
      code: 'EXPIRED_TOKEN',
      cause: 'The token expiration time has passed.',
      meta: {
        source: 'zanix',
        currentTime,
        expirationTime: payload.exp,
      },
    })
  }

  // Validate optional claims (issuer and audience)
  if (payload.iss && payload.iss !== iss) {
    throw new PermissionDenied('Invalid issuer', {
      code: 'INVALID_TOKEN_ISSUER',
      cause: 'The issuer of the token does not match the expected value.',
      meta: {
        source: 'zanix',
        expectedIssuer: iss,
        tokenIssuer: payload.iss,
      },
    })
  }

  if (aud) {
    const uniqueAud = typeof aud === 'string' ? new Set([aud]) : new Set(aud)
    const uniqueUserAud = typeof payload.aud === 'string'
      ? new Set([payload.aud])
      : new Set(payload.aud)

    const audValidation = scopeValidation(uniqueAud, uniqueUserAud)
    if (audValidation !== 'OK') {
      throw new PermissionDenied('Invalid audience', {
        code: 'INVALID_TOKEN_PERMISSIONS',
        cause: audValidation,
        meta: {
          source: 'zanix',
          expectedAudience: aud,
          tokenAudience: payload.aud,
        },
      })
    }
  }

  if (sub && payload.sub !== sub) {
    throw new PermissionDenied('Invalid subject', {
      code: 'INVALID_TOKEN_SUBJECT',
      cause: 'The subject of the token does not match the expected value.',
      meta: {
        source: 'zanix',
        expectedSubject: sub,
        tokenSubject: payload.sub,
      },
    })
  }

  return payload
}
