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

Deno.test('createAppToken sets iat alongside exp, from the same timestamp', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  const before = Math.floor(Date.now() / 1000)
  const token = await createAppToken({
    subject: 'user@example.com',
    type: 'user',
    expiration: '1h',
  })
  const { payload } = decodeJWT(token)

  assert(payload.iat)
  assert(payload.exp)
  assertAlmostEquals(payload.iat, before, 2)
  assertEquals(payload.exp - payload.iat, parseTTL('1h'))

  Deno.env.delete('JWT_KEY')
})

Deno.test('generateSessionTokens forwards custom accessExpiration/refreshExpiration', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  const tokens = await generateSessionTokens({ locals: {} } as never, {
    subject: 'user@example.com',
    accessExpiration: '30m',
    refreshExpiration: '6mo',
  })

  const access = decodeJWT(tokens.accessToken)
  const refresh = decodeJWT(tokens.refreshToken)

  assert(access.payload.exp)
  assert(access.payload.iat)
  assert(refresh.payload.exp)
  assert(refresh.payload.iat)
  assertAlmostEquals(access.payload.exp - access.payload.iat, parseTTL('30m'), 2)
  assertAlmostEquals(refresh.payload.exp - refresh.payload.iat, parseTTL('6mo'), 2)

  Deno.env.delete('JWT_KEY')
})

Deno.test(
  'generateSessionTokens accepts any duration string parseTTL understands, not just the ' +
    'commonly used literals',
  async () => {
    Deno.env.set('JWT_KEY', 'my secret')

    const tokens = await generateSessionTokens({ locals: {} } as never, {
      subject: 'user@example.com',
      accessExpiration: '45m',
      refreshExpiration: '7d',
    })

    const access = decodeJWT(tokens.accessToken)
    const refresh = decodeJWT(tokens.refreshToken)

    assert(access.payload.exp)
    assert(access.payload.iat)
    assert(refresh.payload.exp)
    assert(refresh.payload.iat)
    assertAlmostEquals(access.payload.exp - access.payload.iat, parseTTL('45m'), 2)
    assertAlmostEquals(refresh.payload.exp - refresh.payload.iat, parseTTL('7d'), 2)

    Deno.env.delete('JWT_KEY')
  },
)

Deno.test(
  'generateSessionTokens throws InternalError when refreshExpiration is not at least ' +
    'MIN_REFRESH_TO_ACCESS_RATIO times accessExpiration',
  async () => {
    Deno.env.set('JWT_KEY', 'my secret')

    const error = await assertRejects(
      () =>
        generateSessionTokens({ locals: {} } as never, {
          subject: 'user@example.com',
          accessExpiration: '1h',
          // Only 2x accessExpiration (in seconds) — below the required 3x margin.
          refreshExpiration: 7200,
        }),
      InternalError,
    )
    assertEquals(error.code, 'AUTH_SESSION_INVALID_EXPIRATION')

    Deno.env.delete('JWT_KEY')
  },
)

Deno.test(
  'generateSessionTokens accepts refreshExpiration exactly at the MIN_REFRESH_TO_ACCESS_RATIO boundary',
  async () => {
    Deno.env.set('JWT_KEY', 'my secret')

    const tokens = await generateSessionTokens({ locals: {} } as never, {
      subject: 'user@example.com',
      accessExpiration: '1h',
      // Exactly 3x accessExpiration (in seconds) — the required minimum, not below it.
      refreshExpiration: 10800,
    })

    assert(tokens.refreshToken)

    Deno.env.delete('JWT_KEY')
  },
)
