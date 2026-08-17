// deno-lint-ignore-file no-explicit-any
import { assert, assertEquals, assertFalse, assertRejects } from '@std/assert'
import { HttpError } from '@zanix/errors'
import { revokeAppTokens, revokeSessionToken } from 'utils/sessions/revoke.ts'
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
  const payload = await revokeSessionToken({ locals } as any, {
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

Deno.test('revokeAppTokens returns an empty array when tokenInfo is falsy', async () => {
  const result = await revokeAppTokens(
    undefined as unknown as string,
    {} as any,
  )
  assertEquals(result, [])
})

Deno.test('revokeAppTokens accepts a single token string (non-array branch)', async () => {
  Deno.env.set('JWT_KEY', 'my secret')
  Deno.env.delete('REDIS_URI')

  const token = await createJWT(
    { exp: 10, sub: 'mock@example.com' },
    'my secret',
  )
  const cache = { local: { set: () => {} } } as any

  const [payload] = await revokeAppTokens(token, cache)

  assert(payload.jti)

  Deno.env.delete('JWT_KEY')
})

Deno.test('revokeSessionToken reads the refresh token from cookies when omitted', async () => {
  Deno.env.set('JWT_KEY', 'my secret')
  Deno.env.delete('REDIS_URI')

  const token = await createJWT(
    { exp: 10, sub: 'mock@example.com' },
    'my secret',
  )
  const cache = { local: { set: () => {} } } as any

  const payload = await revokeSessionToken(
    { locals: {}, cookies: { 'X-Znx-App-Token': token } } as any,
    { cache },
  )

  assert(payload.jti)

  Deno.env.delete('JWT_KEY')
})

Deno.test('revokeSessionToken throws when there is no token to revoke', async () => {
  await assertRejects(
    () =>
      revokeSessionToken({ locals: {}, cookies: {} } as any, {
        cache: {} as any,
      }),
    HttpError,
  )
})

Deno.test('revokeSessionToken also revokes the token already stored in ctx.session', async () => {
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

  const payload = await revokeSessionToken(
    { locals: {}, cookies: {}, session: { token: sessionToken } } as any,
    { token, cache },
  )

  assert(payload.jti)
  assertEquals(revokedKeys.length, 2)

  Deno.env.delete('JWT_KEY')
})
