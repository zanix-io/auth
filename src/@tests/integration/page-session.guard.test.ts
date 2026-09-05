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
import { createRefreshToken, generateSessionTokens } from 'utils/sessions/create.ts'
import { ROTATION_GRACE_WINDOW_ENV } from 'utils/constants.ts'

// `pageSessionGuard` is pure composition of `deriveSessionToken`/`permissionsPipe`/
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

/**
 * Mints a refresh token whose `iat` is forged well past the default `accessExpiration` (`'1h'`)
 * freshness threshold `deriveSessionToken` checks it against — everything else (`exp`, signature)
 * stays real and valid. Lets a test exercise the "stale, must rotate" path deterministically,
 * without waiting an hour of real time for a freshly minted token to actually age.
 */
async function mintStaleRefreshToken(permissions?: string[]) {
  const subject = 'operator@example.com'
  const staleIat = Math.floor(Date.now() / 1000) - 3700
  return await createRefreshToken({
    expiration: '1y',
    subject,
    type: 'user',
    payload: { access: { subject, permissions }, iat: staleIat },
  })
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

Deno.test('pageSessionGuard: allows a session carrying one of the required roles through, reusing a fresh cookie unchanged', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  const refreshToken = await mintRefreshToken(['admin'])
  const ctx = createCtx({ 'X-Znx-App-Token': refreshToken })

  const guard = pageSessionGuard(['admin', 'admin:triggers'])
  const result = await guard(ctx)

  assertEquals(result, {})
  // A just-minted token is well within the default freshness threshold — `deriveSessionToken`
  // reuses it as-is, no rotation, same cookie the client already had.
  assertEquals(ctx.locals.session.token, refreshToken)
  assertEquals(ctx.locals.session.scope, ['admin'])

  Deno.env.delete('JWT_KEY')
})

Deno.test('pageSessionGuard: rotates the cookie once the session is stale', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  const refreshToken = await mintStaleRefreshToken(['admin'])
  const ctx = createCtx({ 'X-Znx-App-Token': refreshToken })

  const guard = pageSessionGuard(['admin', 'admin:triggers'])
  const result = await guard(ctx)

  assertEquals(result, {})
  // Past the freshness threshold: rotation actually ran, the session now carries a NEW refresh
  // token, distinct from the one presented — the same single-use rotation guarantee, just applied
  // at a coarser cadence than every single page load.
  assertNotEquals(ctx.locals.session.token, refreshToken)
  assertEquals(ctx.locals.session.scope, ['admin'])

  Deno.env.delete('JWT_KEY')
})

Deno.test(
  'pageSessionGuard: throws FORBIDDEN when the rotated session carries none of the required roles, ' +
    'and the rotated cookie is still recoverable via attachRotatedSessionToError',
  async () => {
    Deno.env.set('JWT_KEY', 'my secret')

    // Stale on purpose: recovery only has anything to recover when a rotation actually happened.
    const refreshToken = await mintStaleRefreshToken(['viewer'])
    const ctx = createCtx({ 'X-Znx-App-Token': refreshToken })

    const guard = pageSessionGuard(['admin'])
    const error = await assertRejects(async () => await guard(ctx), HttpError)
    assertEquals(error.status.value, 403)

    // The 403 above must not strand the client on the now-blocklisted cookie: the rotated one
    // `deriveSessionToken` already minted before the permission check ran must still be
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
  // Disables the rotation grace window: this test asserts strict, no-tolerance reuse rejection —
  // the near-simultaneous-retry case the grace window is FOR gets its own dedicated coverage below.
  Deno.env.set(ROTATION_GRACE_WINDOW_ENV, '0')

  // Stale on purpose: a fresh token is reused as-is by `deriveSessionToken` (no rotation, nothing
  // to blocklist), so a stale one is what's needed to exercise single-use rotation at all here.
  const refreshToken = await mintStaleRefreshToken(['admin'])
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
  Deno.env.delete(ROTATION_GRACE_WINDOW_ENV)
})

/**
 * Covers the rotation grace window through the full `pageSessionGuard` composition, not just
 * `deriveSessionTokenBase`/`refreshSessionTokensBase` in isolation: a near-simultaneous second
 * request presenting the SAME
 * token must pass the guard (not a 401), AND must leave `ctx.locals.session` correctly populated —
 * `permissionsPipe` reads it right after, unconditionally, with no awareness that this request's
 * pair came from the grace cache rather than a fresh rotation.
 */
Deno.test(
  'pageSessionGuard: a near-simultaneous re-presentation within the grace window passes the ' +
    'guard, with ctx.locals.session correctly populated',
  async () => {
    Deno.env.set('JWT_KEY', 'my secret')

    // Stale on purpose: the grace window only matters once a real rotation has actually happened
    // and blocklisted a token — a fresh token is reused as-is, never touching the blocklist at all.
    const refreshToken = await mintStaleRefreshToken(['admin'])
    const blocklisted = new Map<string, unknown>()
    // Backs BOTH the local-cache path and the Redis path off the SAME underlying map — see the
    // identical concern noted on the regression test above: another test file running earlier in
    // this same process may have left `REDIS_URI` set, so this double stays correct either way.
    const cache = {
      local: {
        get: (key: string) => blocklisted.get(key),
        set: (key: string, value: unknown) => blocklisted.set(key, value),
      },
      getCachedOrFetch: (_provider: string, key: string) => Promise.resolve(blocklisted.get(key)),
      saveToCaches: ({ key, value }: { key: string; value: unknown }) => {
        blocklisted.set(key, value)
        return Promise.resolve()
      },
    }

    const guard = pageSessionGuard(['admin'])

    const firstCtx = createCtx({ 'X-Znx-App-Token': refreshToken }, cache)
    await guard(firstCtx)

    // The SAME token, presented again immediately after — within the default grace window, this
    // must pass the guard just like the first request did.
    const secondCtx = createCtx({ 'X-Znx-App-Token': refreshToken }, cache)
    await guard(secondCtx)

    assertEquals(secondCtx.locals.session.scope, ['admin'])
    assertEquals(secondCtx.locals.session.token, firstCtx.locals.session.token)

    Deno.env.delete('JWT_KEY')
  },
)

Deno.test(
  'pageSessionGuard: { rotateRefresh: false } forces reuse even for a stale token',
  async () => {
    Deno.env.set('JWT_KEY', 'my secret')

    // Stale on purpose: without the override, `deriveSessionToken`'s own automatic freshness check
    // would rotate this one — the override must win over that default.
    const refreshToken = await mintStaleRefreshToken(['admin'])
    const ctx = createCtx({ 'X-Znx-App-Token': refreshToken })

    const guard = pageSessionGuard(['admin'], { rotateRefresh: false })
    const result = await guard(ctx)

    assertEquals(result, {})
    assertEquals(ctx.locals.session.token, refreshToken)
    assertEquals(ctx.locals.session.scope, ['admin'])

    Deno.env.delete('JWT_KEY')
  },
)

Deno.test(
  'pageSessionGuard: { rotateRefresh: true } forces rotation even for a fresh token',
  async () => {
    Deno.env.set('JWT_KEY', 'my secret')

    // Fresh on purpose: without the override, `deriveSessionToken`'s own automatic freshness check
    // would reuse this one as-is — the override must win over that default, in the other direction.
    const refreshToken = await mintRefreshToken(['admin'])
    const ctx = createCtx({ 'X-Znx-App-Token': refreshToken })

    const guard = pageSessionGuard(['admin'], { rotateRefresh: true })
    const result = await guard(ctx)

    assertEquals(result, {})
    assertNotEquals(ctx.locals.session.token, refreshToken)
    assertEquals(ctx.locals.session.scope, ['admin'])

    Deno.env.delete('JWT_KEY')
  },
)
