import type { JWTPayload } from 'typings/jwt.ts'

import { assert, assertEquals, assertNotEquals, assertRejects } from '@std/assert'
import { createJWT } from 'utils/jwt/create.ts'
import { verifyJWT } from 'utils/jwt/verify.ts'
import { generateRSAKeys } from '@zanix/helpers'
import { PermissionDenied } from '@zanix/errors'
import { isUUID } from '@zanix/validator'

// mocks
console.warn = () => {}

Deno.test('Create JWT test case HMAC-SHA256', async () => {
  const secret = 'my-secret'
  const payload: Partial<JWTPayload> = { secureData: 'encrypted data' }
  const jwt = await createJWT(payload, secret)

  const verifiedEnc = await verifyJWT(jwt, secret, { encryptionKey: 'key' })
  assertNotEquals(verifiedEnc.secureData, 'encrypted data')

  const verified = await verifyJWT(jwt, secret)
  assert(verified)

  assertEquals(verified.secureData, 'encrypted data')
  assert(isUUID(verified.jti))

  const error = await assertRejects(
    () => verifyJWT(jwt, 'secret'),
    PermissionDenied,
    'Token signature is invalid',
  )

  assertEquals(error.code, 'INVALID_TOKEN_SIGNATURE')
})

Deno.test('Create JWT test case HMAC-SHA384 and case HMAC-SHA512', async () => {
  const secret = 'my-secret'
  const payload = {}
  const jwt = await createJWT(payload, secret, { algorithm: 'HS384' })
  const verified = await verifyJWT(jwt, secret, { algorithm: 'HS384' })
  assert(verified)

  const jwt512 = await createJWT(payload, secret, { algorithm: 'HS512' })
  const verified512 = await verifyJWT(jwt512, secret, { algorithm: 'HS512' })
  assert(verified512)
})

Deno.test('Create JWT test case HMAC-SHA256 with aud and iss', async () => {
  const secret = 'my-secret'
  const payload = { aud: 'my-aud', iss: 'my-iss' }
  const jwt = await createJWT(payload, secret)

  const verified = await verifyJWT(jwt, secret, {
    aud: ['my-aud'],
    iss: 'my-iss',
  })
  assert(verified)

  const issError = await assertRejects(
    () => verifyJWT(jwt, secret, { iss: 'my-new-iss' }),
    PermissionDenied,
  )
  assertEquals(issError.code, 'INVALID_TOKEN_ISSUER')
  assertEquals(issError.meta?.expectedIssuer, 'my-new-iss')
  assertEquals(issError.meta?.tokenIssuer, 'my-iss')

  const audError = await assertRejects(
    () => verifyJWT(jwt, secret, { iss: 'my-iss', aud: 'my-new-aud' }),
    PermissionDenied,
  )
  assertEquals(audError.code, 'INVALID_TOKEN_PERMISSIONS')
  assertEquals(audError.meta?.expectedAudience, 'my-new-aud')
  assertEquals(audError.meta?.tokenAudience, 'my-aud')

  const subError = await assertRejects(
    () => verifyJWT(jwt, secret, { sub: 'my-sub' }),
    PermissionDenied,
  )
  assertEquals(subError.code, 'INVALID_TOKEN_SUBJECT')
  assertEquals(subError.meta?.expectedSubject, 'my-sub')
  assertEquals(subError.meta?.tokenSubject, undefined)
})

Deno.test('Create JWT test case HMAC-SHA256 with expiration', async () => {
  const secret = 'my-secret'
  const payload = {}
  const jwt = await createJWT(payload, secret, {
    expiration: '1s',
  })

  const verified = await verifyJWT(jwt, secret)
  assert(verified)

  await new Promise((resolve) => setTimeout(resolve, 2000)) // wait until expire

  const error = await assertRejects(
    () => verifyJWT(jwt, secret),
    PermissionDenied,
    'Token has expired',
  )

  assertEquals(error.code, 'EXPIRED_TOKEN')
  assert(error.meta?.currentTime)
  assert(error.meta?.expirationTime)
})

Deno.test('Create JWT test case RS256', async () => {
  const { publicKey, privateKey } = await generateRSAKeys()
  const payload: Partial<JWTPayload> = {
    iss: 'my-iss',
    secureData: 'encrypted data',
  }

  const jwt = await createJWT(payload, privateKey, { algorithm: 'RS256' })

  const verified = await verifyJWT(jwt, publicKey, {
    algorithm: 'RS256',
    iss: 'my-iss',
  })
  assertEquals(verified.secureData, undefined)

  const jwtSecure = await createJWT(payload, privateKey, {
    algorithm: 'RS256',
    encryptionKey: 'my secret',
  })

  const verifiedSecure = await verifyJWT(jwtSecure, publicKey, {
    algorithm: 'RS256',
  })

  assert(verifiedSecure.secureData)
  assertNotEquals(verifiedSecure.secureData, 'encrypted data')

  const verifiedSecureDec = await verifyJWT(jwtSecure, publicKey, {
    algorithm: 'RS256',
    encryptionKey: 'my secret',
  })
  assertEquals(verifiedSecureDec.secureData, 'encrypted data')

  const error = await assertRejects(
    () => verifyJWT(jwt, 'secret'),
    PermissionDenied,
    'Token signature is invalid',
  )

  assertEquals(error.code, 'INVALID_TOKEN_SIGNATURE')
})

Deno.test('Create JWT test case RSA-SHA384 and case RSA-SHA512', async () => {
  const { privateKey, publicKey } = await generateRSAKeys({ hash: 'SHA-384' })
  const payload = {}
  const jwt = await createJWT(payload, privateKey, {
    algorithm: 'RS384',
    keyID: 'v1',
  })
  const verified = await verifyJWT(jwt, publicKey, { algorithm: 'RS384' })
  assert(verified)

  const jwt512 = await createJWT(payload, privateKey, { algorithm: 'RS512' })
  const verified512 = await verifyJWT(jwt512, publicKey, {
    algorithm: 'RS512',
  })
  assert(verified512)
})
