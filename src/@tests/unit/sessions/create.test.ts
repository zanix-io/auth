// deno-lint-ignore-file no-explicit-any
import { assert, assertEquals } from '@std/assert'
import { createAccessToken } from 'modules/sessions/create.ts'

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
