// deno-lint-ignore-file no-explicit-any
import { assert, assertAlmostEquals, assertEquals, assertRejects } from '@std/assert'
import { createAccessToken, createAppToken, generateSessionTokens } from 'utils/sessions/create.ts'
import { decodeJWT } from 'utils/jwt/decode.ts'
import { generateRSAKeys, parseTTL } from '@zanix/helpers'
import { HttpError, InternalError } from '@zanix/errors'
import { jwtKeys } from 'utils/jwt/keys-rotation.ts'

console.error = () => {}

Deno.test('Create access token with correct local session', async () => {
  const locals: any = {}
  Deno.env.set('JWT_KEY', 'my secret')
  const token = await createAccessToken({ locals } as any, {
    subject: 'mock@example.com',
    type: 'user',
    expiration: 10,
    payload: {
      rateLimit: 60,
      permissions: 'user',
    },
  })

  assert(token)
  assertEquals(locals.session.type, 'user')
  assertEquals(locals.session.status, 'active')
  assertEquals(locals.session.scope, ['user'])
  assertEquals(locals.session.rateLimit, 60)
  assertEquals(locals.session.subject, 'mock@example.com')
  assert(locals.session.payload.exp)
  assert(locals.session.payload.iss)
})

Deno.test('Create session token shoud return correct refresn and access', async () => {
  const tokens = await generateSessionTokens(
    { locals: {} } as never,
    {} as never,
  )

  const refresh = decodeJWT(tokens.refreshToken)
  assert(refresh.payload.exp)
  assertEquals(31536000, parseTTL('1y'))
  assertAlmostEquals(
    refresh.payload.exp,
    Math.floor(Date.now() / 1000) + parseTTL('1y'),
    10,
  )
})

Deno.test('generateSessionTokens forwards a provided id as the access token jit', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  const tokens = await generateSessionTokens({ locals: {} } as never, {
    subject: 'user@example.com',
    id: 'custom-jit',
  } as never)

  const { payload } = decodeJWT(tokens.accessToken)
  assertEquals(payload.jit, 'custom-jit')

  Deno.env.delete('JWT_KEY')
})

Deno.test('generateSessionTokens falls back to payload.jit when no id is provided', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  const tokens = await generateSessionTokens({ locals: {} } as never, {
    subject: 'user@example.com',
    payload: { jit: 'payload-jit' },
  } as never)

  const { payload } = decodeJWT(tokens.accessToken)
  assertEquals(payload.jit, 'payload-jit')

  Deno.env.delete('JWT_KEY')
})

Deno.test('createAppToken uses the RSA key and algorithm for api sessions', async () => {
  jwtKeys.JWK_PRI.clear()
  Deno.env.delete('JWK_PRI_V1')
  Deno.env.delete('JWK_PRI_V2')
  const { privateKey } = await generateRSAKeys()
  Deno.env.set('JWK_PRI', btoa(privateKey))

  const token = await createAppToken({
    subject: 'service-account',
    type: 'api',
    expiration: 10,
  })

  const { header } = decodeJWT(token)
  assertEquals(header.alg, 'RS256')

  Deno.env.delete('JWK_PRI')
  jwtKeys.JWK_PRI.clear()
})

Deno.test('createAppToken throws InternalError when the signing key is missing', async () => {
  jwtKeys.JWT_KEY.clear()
  Deno.env.delete('JWT_KEY')

  const error = await assertRejects(
    () =>
      createAppToken({
        subject: 'user@example.com',
        type: 'user',
        expiration: 10,
      }),
    InternalError,
  )
  assertEquals(error.code, 'AUTH_SESSION_JWT_KEY_MISSING')
})

Deno.test('createAppToken wraps signing failures in an HttpError', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  await assertRejects(
    () =>
      createAppToken({
        subject: 'user@example.com',
        type: 'user',
        expiration: -10,
      }),
    HttpError,
  )

  Deno.env.delete('JWT_KEY')
})

Deno.test('createAccessToken throws InternalError when expiration exceeds 1 hour', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  await assertRejects(
    () =>
      createAccessToken({ locals: {} } as never, {
        subject: 'user@example.com',
        type: 'user',
        expiration: 7200,
      }),
    InternalError,
  )

  Deno.env.delete('JWT_KEY')
})
