// deno-lint-ignore-file no-explicit-any
import { assert, assertAlmostEquals, assertEquals } from '@std/assert'
import { createAccessToken, generateSessionTokens } from 'utils/sessions/create.ts'
import { decodeJWT } from 'utils/jwt/decode.ts'
import { parseTTL } from '@zanix/helpers'

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
  const tokens = await generateSessionTokens({ locals: {} } as never, {} as never)

  const refresh = decodeJWT(tokens.refreshToken)
  assert(refresh.payload.exp)
  assertEquals(31536000, parseTTL('1y'))
  assertAlmostEquals(refresh.payload.exp, Math.floor(Date.now() / 1000) + parseTTL('1y'), 10)
})
