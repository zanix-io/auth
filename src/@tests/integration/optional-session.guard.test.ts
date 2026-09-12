// deno-lint-ignore-file no-explicit-any
import { assertEquals, assertNotEquals } from '@std/assert'

import { optionalSessionGuard } from 'modules/middlewares/optional-session.guard.ts'
import { createRefreshToken, generateSessionTokens } from 'utils/sessions/create.ts'

// `optionalSessionGuard` is pure composition over `deriveSessionToken` — already covered on its
// own — plus a try/catch that turns every failure into "no session" instead of a throw. What's
// under test HERE is that composition itself (never throwing, and resolving a real session when
// one exists), so this suite lives in `integration/`, not `unit/`, per `zanix-test-tier-conventions`
// — the same reasoning `page-session.guard.test.ts` documents for its own sibling guard.

function createCtx(cookies: Record<string, string> = {}, cache: unknown = undefined) {
  return {
    id: 'req-1',
    locals: {},
    cookies,
    providers: { get: () => cache },
  } as any
}

async function mintRefreshToken(permissions?: string[]) {
  const mintCtx = createCtx()
  const { refreshToken } = await generateSessionTokens(mintCtx, {
    subject: 'visitor@example.com',
    permissions,
  })
  return refreshToken
}

/** Same forging technique `page-session.guard.test.ts` uses to exercise the "stale, must rotate"
 * path deterministically — see that file's own doc for why. */
async function mintStaleRefreshToken(permissions?: string[]) {
  const subject = 'visitor@example.com'
  const staleIat = Math.floor(Date.now() / 1000) - 3700
  return await createRefreshToken({
    expiration: '1y',
    subject,
    type: 'user',
    payload: { access: { subject, permissions }, iat: staleIat },
  })
}

Deno.test('optionalSessionGuard: resolves with no session, never throwing, when there is no cookie at all', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  const guard = optionalSessionGuard()
  const ctx = createCtx()
  const result = await guard(ctx)

  assertEquals(result, {})
  assertEquals(ctx.locals.session, undefined)

  Deno.env.delete('JWT_KEY')
})

Deno.test('optionalSessionGuard: resolves with no session, never throwing, for an invalid/garbage refresh token', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  const guard = optionalSessionGuard()
  const ctx = createCtx({ 'X-Znx-App-Token': 'not-a-real-token' })
  const result = await guard(ctx)

  assertEquals(result, {})
  assertEquals(ctx.locals.session, undefined)

  Deno.env.delete('JWT_KEY')
})

Deno.test('optionalSessionGuard: resolves a real session onto ctx.locals.session for a valid cookie, reusing a fresh one unchanged', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  const refreshToken = await mintRefreshToken(['viewer'])
  const ctx = createCtx({ 'X-Znx-App-Token': refreshToken })

  const guard = optionalSessionGuard()
  const result = await guard(ctx)

  assertEquals(result, {})
  assertEquals(ctx.locals.session.token, refreshToken)
  assertEquals(ctx.locals.session.scope, ['viewer'])

  Deno.env.delete('JWT_KEY')
})

Deno.test('optionalSessionGuard: rotates the cookie once the session is stale, exactly like pageSessionGuard', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  const refreshToken = await mintStaleRefreshToken(['viewer'])
  const ctx = createCtx({ 'X-Znx-App-Token': refreshToken })

  const guard = optionalSessionGuard()
  const result = await guard(ctx)

  assertEquals(result, {})
  assertNotEquals(ctx.locals.session.token, refreshToken)
  assertEquals(ctx.locals.session.scope, ['viewer'])

  Deno.env.delete('JWT_KEY')
})

Deno.test(
  'optionalSessionGuard: { rotateRefresh: false } forces reuse even for a stale token',
  async () => {
    Deno.env.set('JWT_KEY', 'my secret')

    const refreshToken = await mintStaleRefreshToken(['viewer'])
    const ctx = createCtx({ 'X-Znx-App-Token': refreshToken })

    const guard = optionalSessionGuard({ rotateRefresh: false })
    const result = await guard(ctx)

    assertEquals(result, {})
    assertEquals(ctx.locals.session.token, refreshToken)

    Deno.env.delete('JWT_KEY')
  },
)
