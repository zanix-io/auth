import type { JWTPayload } from 'typings/jwt.ts'

import { assert, assertEquals, assertNotEquals, assertRejects, assertThrows } from '@std/assert'
import { createJWT } from 'utils/jwt/create.ts'
import { verifyJWT } from 'utils/jwt/verify.ts'
import { base64UrlDecode, base64UrlEncode, generateRSAKeys } from '@zanix/helpers'
import { HttpError, InternalError, PermissionDenied } from '@zanix/errors'
import { isUUID } from '@zanix/validator'
import { isJwtVerificationFailure, toJwtHttpError } from 'utils/jwt/verification-error.ts'

// mocks
console.warn = () => {}
console.error = () => {}

Deno.test('Create JWT test case HMAC-SHA256', async () => {
  const secret = 'my-secret'
  // No `expiration` — this test is about encryption/signing, not expiration, so `requireExp:
  // false` opts out of the (default-on) exp requirement below rather than adding an unrelated
  // concern.
  const payload: Partial<JWTPayload> = { secureData: 'encrypted data' }
  const jwt = await createJWT(payload, secret)

  const verifiedEnc = await verifyJWT(jwt, secret, { encryptionKey: 'key', requireExp: false })
  assertNotEquals(verifiedEnc.secureData, 'encrypted data')

  const verified = await verifyJWT(jwt, secret, { requireExp: false })
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

Deno.test('createJWT rejects a zero/negative expiration with InternalError', async () => {
  // No prior coverage of this branch at all — added while auditing this exact throw site (was a
  // plain `Error` before; see `create.ts`'s own comment on why `InternalError` fits: a config
  // value the calling app passed, not something a token's own subject could have caused).
  const error = await assertRejects(
    () => createJWT({}, 'my-secret', { expiration: 0 }),
    InternalError,
    'Expiration time must be greater than 0',
  )
  assertEquals(error.code, 'JWT_INVALID_EXPIRATION')
})

Deno.test('Create JWT test case HMAC-SHA384 and case HMAC-SHA512', async () => {
  const secret = 'my-secret'
  // No `expiration` — this test is about the HS384/HS512 algorithms themselves, so `requireExp:
  // false` opts out of the (default-on) exp requirement rather than adding an unrelated concern.
  const payload = {}
  const jwt = await createJWT(payload, secret, { algorithm: 'HS384' })
  const verified = await verifyJWT(jwt, secret, { algorithm: 'HS384', requireExp: false })
  assert(verified)

  const jwt512 = await createJWT(payload, secret, { algorithm: 'HS512' })
  const verified512 = await verifyJWT(jwt512, secret, { algorithm: 'HS512', requireExp: false })
  assert(verified512)
})

Deno.test('Create JWT test case HMAC-SHA256 with aud and iss', async () => {
  const secret = 'my-secret'
  // No `expiration` — this test is about iss/aud/sub validation, so `requireExp: false` opts out
  // of the (default-on) exp requirement everywhere below, rather than adding an unrelated concern
  // (and rather than the exp check masking the iss/aud/sub mismatch each assertion below expects).
  const payload = { aud: 'my-aud', iss: 'my-iss' }
  const jwt = await createJWT(payload, secret)

  const verified = await verifyJWT(jwt, secret, {
    aud: ['my-aud'],
    iss: 'my-iss',
    requireExp: false,
  })
  assert(verified)

  const issError = await assertRejects(
    () => verifyJWT(jwt, secret, { iss: 'my-new-iss', requireExp: false }),
    PermissionDenied,
  )
  assertEquals(issError.code, 'INVALID_TOKEN_ISSUER')
  assertEquals(issError.meta?.expectedIssuer, 'my-new-iss')
  assertEquals(issError.meta?.tokenIssuer, 'my-iss')

  const audError = await assertRejects(
    () => verifyJWT(jwt, secret, { iss: 'my-iss', aud: 'my-new-aud', requireExp: false }),
    PermissionDenied,
  )
  assertEquals(audError.code, 'INVALID_TOKEN_PERMISSIONS')
  assertEquals(audError.meta?.expectedAudience, 'my-new-aud')
  assertEquals(audError.meta?.tokenAudience, 'my-aud')

  const subError = await assertRejects(
    () => verifyJWT(jwt, secret, { sub: 'my-sub', iss: payload.iss, requireExp: false }),
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

/**
 * Regression coverage for a confirmed risk: `verifyJWT` used to only ever enforce expiration
 * against a token that actually carried an `exp` claim (`payload.exp && currentTime >
 * payload.exp`) — a token with no `exp` at all had nothing to compare against, so it was accepted
 * as valid forever. `requireExp` (default `true`) closes that gap.
 */
Deno.test('verifyJWT rejects a token with no exp claim by default', async () => {
  const secret = 'my-secret'
  const jwt = await createJWT({}, secret) // no `expiration` option -> no `exp` claim

  const error = await assertRejects(
    () => verifyJWT(jwt, secret),
    PermissionDenied,
  )
  assertEquals(error.code, 'MISSING_TOKEN_EXPIRATION')
})

Deno.test('verifyJWT accepts a token with no exp claim when requireExp: false', async () => {
  const secret = 'my-secret'
  const jwt = await createJWT({}, secret)

  const verified = await verifyJWT(jwt, secret, { requireExp: false })
  assert(verified)
})

Deno.test('verifyJWT still enforces expiration normally when requireExp: false', async () => {
  const secret = 'my-secret'
  const jwt = await createJWT({}, secret, { expiration: '1s' })

  await new Promise((resolve) => setTimeout(resolve, 2000))

  const error = await assertRejects(
    () => verifyJWT(jwt, secret, { requireExp: false }),
    PermissionDenied,
  )
  assertEquals(error.code, 'EXPIRED_TOKEN')
})

/**
 * Regression coverage for a confirmed defense: `verifyJWT` never reads/trusts the `alg` field in
 * the token's own header — it fixes the algorithm from ITS OWN `options.algorithm` (default
 * `HS256`) and uses that alone to pick the verification function. An attacker forging a header
 * that claims `alg: 'none'` (with no signature at all) can't force a weaker/no-signature
 * verification path — it's still verified as if it were HS256, and an empty signature fails that
 * check, so the forged token is rejected outright.
 */
Deno.test('verifyJWT rejects a forged token with alg: none and an empty signature', async () => {
  const secret = 'my-secret'
  const forgedHeader = base64UrlEncode(JSON.stringify({ alg: 'none', typ: 'JWT' }))
  const forgedPayload = base64UrlEncode(
    JSON.stringify({ sub: 'attacker', exp: Math.floor(Date.now() / 1000) + 3600 }),
  )
  // Classic `alg: none` forgery — the third (signature) segment is empty.
  const forgedToken = `${forgedHeader}.${forgedPayload}.`

  const error = await assertRejects(
    () => verifyJWT(forgedToken, secret),
    PermissionDenied,
    'Token signature is invalid',
  )
  assertEquals(error.code, 'INVALID_TOKEN_SIGNATURE')
})

/**
 * Regression coverage for a confirmed defense: `verifyJWT` checks the signature BEFORE ever
 * decoding the payload for other claims (see `verify.ts`'s code order — signature check, then
 * `JSON.parse` of the payload). A payload tampered with after signing — even while keeping the
 * ORIGINAL, still-valid-looking signature — must be rejected as a signature mismatch, never
 * silently trusted for its tampered claims.
 */
Deno.test({
  name: 'verifyJWT rejects a tampered payload even with the original signature intact',
  fn: async () => {
    const secret = 'my-secret'
    const jwt = await createJWT({ sub: 'real-user' }, secret, { expiration: '1h' })
    const [encodedHeader, encodedPayload, encodedSignature] = jwt.split('.')

    const realPayload = JSON.parse(base64UrlDecode(encodedPayload, true))
    const tamperedPayload = base64UrlEncode(
      JSON.stringify({ ...realPayload, sub: 'attacker' }),
    )
    // Original signature kept as-is — it was computed over the untampered payload.
    const tamperedToken = `${encodedHeader}.${tamperedPayload}.${encodedSignature}`

    const error = await assertRejects(
      () => verifyJWT(tamperedToken, secret),
      PermissionDenied,
      'Token signature is invalid',
    )
    assertEquals(error.code, 'INVALID_TOKEN_SIGNATURE')
  },
})

Deno.test('Create JWT test case RS256', async () => {
  const { publicKey, privateKey } = await generateRSAKeys()
  const myIss = 'my-iss'
  // No `expiration` — this test is about RS256 signing/encryption, so `requireExp: false` opts
  // out of the (default-on) exp requirement below rather than adding an unrelated concern.
  const payload: Partial<JWTPayload> = {
    iss: myIss,
    secureData: 'encrypted data',
  }

  const jwt = await createJWT(payload, privateKey, { algorithm: 'RS256' })

  const verified = await verifyJWT(jwt, publicKey, {
    algorithm: 'RS256',
    iss: myIss,
    requireExp: false,
  })
  assertEquals(verified.secureData, undefined)

  const jwtSecure = await createJWT(payload, privateKey, {
    algorithm: 'RS256',
    encryptionKey: 'my secret',
  })

  const verifiedSecure = await verifyJWT(jwtSecure, publicKey, {
    iss: myIss,
    algorithm: 'RS256',
    requireExp: false,
  })

  assert(verifiedSecure.secureData)
  assertNotEquals(verifiedSecure.secureData, 'encrypted data')

  const verifiedSecureDec = await verifyJWT(jwtSecure, publicKey, {
    algorithm: 'RS256',
    encryptionKey: 'my secret',
    iss: myIss,
    requireExp: false,
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
  // No `expiration` — this test is about the RS384/RS512 algorithms themselves, so `requireExp:
  // false` opts out of the (default-on) exp requirement rather than adding an unrelated concern.
  const payload = {}
  const jwt = await createJWT(payload, privateKey, {
    algorithm: 'RS384',
    keyID: 'v1',
  })
  const verified = await verifyJWT(jwt, publicKey, { algorithm: 'RS384', requireExp: false })
  assert(verified)

  const jwt512 = await createJWT(payload, privateKey, { algorithm: 'RS512' })
  const verified512 = await verifyJWT(jwt512, publicKey, {
    algorithm: 'RS512',
    requireExp: false,
  })
  assert(verified512)
})

Deno.test('isJwtVerificationFailure: true only for a bare PermissionDenied', () => {
  assertEquals(isJwtVerificationFailure(new PermissionDenied('bad token')), true)
  assertEquals(isJwtVerificationFailure(new Error('unrelated')), false)
  assertEquals(isJwtVerificationFailure(new HttpError('INTERNAL_SERVER_ERROR')), false)
})

Deno.test('toJwtHttpError: converts a JWT verify failure into an HttpError w/ that status', () => {
  const original = new PermissionDenied('Token has expired', {
    code: 'EXPIRED_TOKEN',
    meta: { currentTime: 1, expirationTime: 0 },
  })

  const error = assertThrows(
    () => toJwtHttpError(original, 'UNAUTHORIZED'),
    HttpError,
  )

  assertEquals(error.status.value, 401)
  assertEquals(error.message, 'Token has expired')
  assertEquals(error.code, 'EXPIRED_TOKEN')
  assertEquals(error.meta, { currentTime: 1, expirationTime: 0 })
  assertEquals(error.cause, original)
})

/**
 * Regression coverage: `toJwtHttpError` must re-throw anything that ISN'T a JWT verification
 * failure completely unchanged — never masking a genuine, unrelated server-side fault as if it
 * were a client-facing JWT error.
 */
Deno.test('toJwtHttpError: rethrows a non-JWT-verification error unchanged', () => {
  const original = new Error('unrelated infra failure')

  const error = assertThrows(
    () => toJwtHttpError(original, 'BAD_REQUEST'),
  )

  assertEquals(error, original)
})
