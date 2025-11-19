// deno-lint-ignore-file no-explicit-any
import { assert, assertEquals, assertFalse } from '@std/assert'
import { revokeSessionAndToken } from 'modules/sessions/revoke.ts'
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
  const payload = await revokeSessionAndToken({ locals } as any, {
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
