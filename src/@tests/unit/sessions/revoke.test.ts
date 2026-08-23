// deno-lint-ignore-file no-explicit-any
import { assert, assertEquals, assertFalse, assertRejects } from '@std/assert'
import { HttpError } from '@zanix/errors'
import {
  revokeAppTokens,
  revokeAppTokensBase,
  revokeSessionToken,
  revokeSessionTokenBase,
} from 'utils/sessions/revoke.ts'
import { createJWT } from '@zanix/auth'

console.warn = () => {}

Deno.test('Create access token with correct local session', async () => {
  const locals: any = {}
  Deno.env.set('JWT_KEY', 'my secret')
  Deno.env.delete('REDIS_URI')
  const token = await createJWT({
    exp: 10,
    sub: 'mock@example.com',
    rateLimit: 100,
    aud: ['admin'],
  }, 'my-secret')
  const payload = await revokeSessionTokenBase({ locals } as any, {
    token,
    cache: { local: { set: () => {} } } as any,
  })

  assert(payload.exp)
  assert(payload.iss)
  assert(payload.sub)
  assert(payload.rateLimit)
  assert(payload.jti)

  assertEquals(locals.session.type, 'user')
  assertEquals(locals.session.status, 'revoked')
  assertEquals(locals.session.scope, ['admin'])
  assertEquals(locals.session.rateLimit, 100)
  assertEquals(locals.session.subject, 'mock@example.com')
  assertFalse(locals.session.payload.exp) // set max age in 0
  assert(locals.session.payload.iss)
})

Deno.test('revokeAppTokensBase returns an empty array when tokenInfo is falsy', async () => {
  const result = await revokeAppTokensBase(
    undefined as unknown as string,
    {} as any,
  )
  assertEquals(result, [])
})

Deno.test('revokeAppTokensBase accepts a single token string (non-array branch)', async () => {
  Deno.env.set('JWT_KEY', 'my secret')
  Deno.env.delete('REDIS_URI')

  const token = await createJWT(
    { exp: 10, sub: 'mock@example.com' },
    'my secret',
  )
  const cache = { local: { set: () => {} } } as any

  const [payload] = await revokeAppTokensBase(token, cache)

  assert(payload.jti)

  Deno.env.delete('JWT_KEY')
})

Deno.test('revokeSessionTokenBase reads the refresh token from cookies when omitted', async () => {
  Deno.env.set('JWT_KEY', 'my secret')
  Deno.env.delete('REDIS_URI')

  const token = await createJWT(
    { exp: 10, sub: 'mock@example.com' },
    'my secret',
  )
  const cache = { local: { set: () => {} } } as any

  const payload = await revokeSessionTokenBase(
    { locals: {}, cookies: { 'X-Znx-App-Token': token } } as any,
    { cache },
  )

  assert(payload.jti)

  Deno.env.delete('JWT_KEY')
})

Deno.test('revokeSessionTokenBase throws when there is no token to revoke', async () => {
  await assertRejects(
    () =>
      revokeSessionTokenBase({ locals: {}, cookies: {} } as any, {
        cache: {} as any,
      }),
    HttpError,
  )
})

Deno.test('revokeSessionTokenBase also revokes the token stored in ctx.session', async () => {
  Deno.env.set('JWT_KEY', 'my secret')
  Deno.env.delete('REDIS_URI')

  const futureExp = Math.floor(Date.now() / 1000) + 100
  const token = await createJWT(
    { exp: futureExp, sub: 'mock@example.com' },
    'my secret',
  )
  const sessionToken = await createJWT({
    exp: futureExp,
    sub: 'other@example.com',
  }, 'my secret')

  const revokedKeys: string[] = []
  const cache = {
    local: {
      set: (key: string) => {
        revokedKeys.push(key)
      },
    },
  } as any

  const payload = await revokeSessionTokenBase(
    { locals: {}, cookies: {}, session: { token: sessionToken } } as any,
    { token, cache },
  )

  assert(payload.jti)
  assertEquals(revokedKeys.length, 2)

  Deno.env.delete('JWT_KEY')
})

// ── The real, exported entry points: revokeAppTokens/revokeSessionToken wrap the Bases above ──

Deno.test(
  'revokeAppTokens: a malformed token rejects with HttpError(BAD_REQUEST), never a bare ' +
    'PermissionDenied',
  async () => {
    const error = await assertRejects(
      () => revokeAppTokens('not-a-real-token', {} as any),
      HttpError,
    )
    assertEquals(error.status.value, 400)
  },
)

Deno.test('revokeAppTokens: a valid token revokes, same as the Base', async () => {
  Deno.env.set('JWT_KEY', 'my secret')
  Deno.env.delete('REDIS_URI')

  const token = await createJWT({ exp: 10, sub: 'mock@example.com' }, 'my secret')
  const cache = { local: { set: () => {} } } as any

  const [payload] = await revokeAppTokens(token, cache)
  assert(payload.jti)

  Deno.env.delete('JWT_KEY')
})

Deno.test(
  'revokeSessionToken: a malformed token rejects with HttpError(BAD_REQUEST), never a bare ' +
    'PermissionDenied',
  async () => {
    const error = await assertRejects(
      () =>
        revokeSessionToken({ locals: {}, cookies: {} } as any, {
          token: 'not-a-real-token',
          cache: {} as any,
        }),
      HttpError,
    )
    assertEquals(error.status.value, 400)
  },
)
