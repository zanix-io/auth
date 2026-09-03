// deno-lint-ignore-file no-explicit-any
import {
  assert,
  assertEquals,
  assertNotEquals,
  assertRejects,
  assertStringIncludes,
} from '@std/assert'
import { HttpError } from '@zanix/errors'

import { pageSessionGuard } from 'modules/middlewares/page-session.guard.ts'
import { recoverRotatedSessionCookie } from 'utils/sessions/rotation-recovery.ts'
import { generateSessionTokens } from 'utils/sessions/create.ts'

// `pageSessionGuard` is pure composition of `refreshSessionTokens`/`permissionsPipe`/
// `attachRotatedSessionToError` — each already has its own dedicated unit coverage. What's under
// test HERE is the real interaction between them (the composition itself), so this suite lives in
// `integration/`, not `unit/`, per `zanix-test-tier-conventions`.

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
    subject: 'operator@example.com',
    permissions,
  })
  return refreshToken
}

Deno.test('pageSessionGuard: rejects with UNAUTHORIZED when there is no session cookie at all', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  const guard = pageSessionGuard(['admin'])
  const error = await assertRejects(async () => await guard(createCtx()), HttpError)
  assertEquals(error.status.value, 401)

  Deno.env.delete('JWT_KEY')
})

Deno.test('pageSessionGuard: rejects with UNAUTHORIZED for an invalid/garbage refresh token', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  const guard = pageSessionGuard(['admin'])
  const error = await assertRejects(
    async () => await guard(createCtx({ 'X-Znx-App-Token': 'not-a-real-token' })),
    HttpError,
  )
  assertEquals(error.status.value, 401)

  Deno.env.delete('JWT_KEY')
})

Deno.test('pageSessionGuard: allows a session carrying one of the required roles through, rotating the cookie', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  const refreshToken = await mintRefreshToken(['admin'])
  const ctx = createCtx({ 'X-Znx-App-Token': refreshToken })

  const guard = pageSessionGuard(['admin', 'admin:triggers'])
  const result = await guard(ctx)

  assertEquals(result, {})
  // Rotation actually ran: the session now carries a NEW refresh token, distinct from the one
  // presented — the same single-use rotation `refreshSessionTokens` guarantees on its own.
  assertNotEquals(ctx.locals.session.token, refreshToken)
  assertEquals(ctx.locals.session.scope, ['admin'])

  Deno.env.delete('JWT_KEY')
})

Deno.test(
  'pageSessionGuard: throws FORBIDDEN when the rotated session carries none of the required roles, ' +
    'and the rotated cookie is still recoverable via attachRotatedSessionToError',
  async () => {
    Deno.env.set('JWT_KEY', 'my secret')

    const refreshToken = await mintRefreshToken(['viewer'])
    const ctx = createCtx({ 'X-Znx-App-Token': refreshToken })

    const guard = pageSessionGuard(['admin'])
    const error = await assertRejects(async () => await guard(ctx), HttpError)
    assertEquals(error.status.value, 403)

    // The 403 above must not strand the client on the now-blocklisted cookie: the rotated one
    // `refreshSessionTokens` already minted before the permission check ran must still be
    // recoverable off the thrown error — see `docs/configuration.md`'s "Guard-Stage Rotation
    // Recovery" section for why this matters.
    const response = await recoverRotatedSessionCookie()(error)
    assert(response instanceof Response, 'expected a real Response, not undefined')

    const setCookies = response.headers.getSetCookie()
    const appToken = setCookies.find((c) => c.startsWith('X-Znx-App-Token='))
    assert(appToken, `expected an X-Znx-App-Token cookie among: ${setCookies.join(' | ')}`)
    assertStringIncludes(appToken, `X-Znx-App-Token=${ctx.locals.session.token}`)
    assert(
      !appToken.includes(refreshToken),
      'the recovered cookie must carry the ROTATED token, never the one that was just consumed',
    )

    Deno.env.delete('JWT_KEY')
  },
)

Deno.test('pageSessionGuard: matches when the session carries any one of several required roles (OR, not AND)', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  const refreshToken = await mintRefreshToken(['admin:triggers'])
  const ctx = createCtx({ 'X-Znx-App-Token': refreshToken })

  const guard = pageSessionGuard(['admin', 'admin:triggers'])
  const result = await guard(ctx)

  assertEquals(result, {})

  Deno.env.delete('JWT_KEY')
})

Deno.test('pageSessionGuard: single-use rotation — a consumed refresh token is rejected on reuse when a cache is wired', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  const refreshToken = await mintRefreshToken(['admin'])
  const blocklisted = new Map<string, boolean>()
  // Backs BOTH the local-cache path and the Redis path (`getCachedOrFetch`/`saveToCaches`) off the
  // SAME underlying map — `checkTokenBlockList`/`addTokenToBlockListBase` branch on whether
  // `REDIS_URI` happens to be set, and another test file running earlier in this same process may
  // have left it set (see `jwt-validation.test.ts`'s own `stubBlockListLookup` for the identical
  // concern), so this double stays correct either way instead of assuming one path.
  const cache = {
    local: {
      get: (key: string) => blocklisted.get(key),
      set: (key: string, value: boolean) => blocklisted.set(key, value),
    },
    getCachedOrFetch: (_provider: string, key: string) => Promise.resolve(blocklisted.get(key)),
    saveToCaches: ({ key, value }: { key: string; value: boolean }) => {
      blocklisted.set(key, value)
      return Promise.resolve()
    },
  }

  const guard = pageSessionGuard(['admin'])

  const firstCtx = createCtx({ 'X-Znx-App-Token': refreshToken }, cache)
  await guard(firstCtx)

  // The SAME (now-consumed) refresh token, presented again — must be rejected, not silently
  // accepted a second time.
  const secondCtx = createCtx({ 'X-Znx-App-Token': refreshToken }, cache)
  const error = await assertRejects(async () => await guard(secondCtx), HttpError)
  assertEquals(error.status.value, 401)

  Deno.env.delete('JWT_KEY')
})
