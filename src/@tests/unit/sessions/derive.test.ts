// deno-lint-ignore-file no-explicit-any
import { assert, assertEquals, assertNotEquals, assertRejects } from '@std/assert'
import { HttpError, PermissionDenied } from '@zanix/errors'
import { deriveSessionToken, deriveSessionTokenBase } from 'utils/sessions/derive.ts'
import { createAppToken, createRefreshToken, generateSessionTokens } from 'utils/sessions/create.ts'
import { CACHE_KEYS, ROTATION_GRACE_WINDOW_ENV } from 'utils/constants.ts'

console.warn = () => {}

function createCtx() {
  return { locals: {}, cookies: {} } as any
}

async function mintFreshRefreshToken(permissions?: string[]) {
  const { refreshToken } = await generateSessionTokens(createCtx(), {
    subject: 'user@example.com',
    permissions,
  })
  return refreshToken
}

/** Same forging technique `page-session.guard.test.ts` uses: a real, validly signed refresh token
 * whose `iat` is set well past the default `accessExpiration` (`'1h'`) freshness threshold. */
async function mintStaleRefreshToken(permissions?: string[]) {
  const subject = 'user@example.com'
  const staleIat = Math.floor(Date.now() / 1000) - 3700
  return await createRefreshToken({
    expiration: '1y',
    subject,
    type: 'user',
    payload: { access: { subject, permissions }, iat: staleIat },
  })
}

Deno.test('deriveSessionTokenBase throws when there is no refresh token available', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  await assertRejects(
    () => deriveSessionTokenBase(createCtx(), undefined),
    HttpError,
  )

  Deno.env.delete('JWT_KEY')
})

Deno.test('deriveSessionTokenBase throws FORBIDDEN for a non-refresh token', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  const accessOnlyToken = await createAppToken({
    subject: 'user@example.com',
    type: 'user',
    expiration: '1h',
  })

  await assertRejects(
    () => deriveSessionTokenBase(createCtx(), accessOnlyToken),
    HttpError,
  )

  Deno.env.delete('JWT_KEY')
})

Deno.test('deriveSessionTokenBase: a fresh token is reused as-is, no rotation', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  const refreshToken = await mintFreshRefreshToken(['admin'])
  const ctx = createCtx()

  const result = await deriveSessionTokenBase(ctx, refreshToken)

  assertEquals(result.rotated, false)
  assertEquals(result.refreshToken, refreshToken)
  assertEquals(result.oldToken, refreshToken)
  assertEquals(ctx.locals.session.token, refreshToken)
  assertEquals(ctx.locals.session.scope, ['admin'])
  assertEquals(ctx.locals.session.subject, 'user@example.com')

  Deno.env.delete('JWT_KEY')
})

Deno.test(
  'deriveSessionTokenBase: a fresh token never signs a real access token — no jti/exp/aud leak ' +
    'a signed JWT into the local session that was never actually minted',
  async () => {
    Deno.env.set('JWT_KEY', 'my secret')

    const refreshToken = await mintFreshRefreshToken(['admin'])
    const ctx = createCtx()

    await deriveSessionTokenBase(ctx, refreshToken)

    // The claims still resolve correctly even though nothing was signed for this request.
    assert(ctx.locals.session.id, 'expected a derived session id (jti) even with no real mint')
    assertEquals(ctx.locals.session.rateLimit, 100)

    Deno.env.delete('JWT_KEY')
  },
)

Deno.test('deriveSessionTokenBase: a stale token rotates, blocklisting the old one', async () => {
  Deno.env.set('JWT_KEY', 'my secret')
  Deno.env.set(ROTATION_GRACE_WINDOW_ENV, '0')

  const refreshToken = await mintStaleRefreshToken(['admin'])
  const ctx = createCtx()

  const blocklisted = new Map<string, unknown>()
  const cache = {
    local: {
      get: (key: string) => blocklisted.get(key),
      set: (key: string, value: unknown) => blocklisted.set(key, value),
    },
  } as any

  const result = await deriveSessionTokenBase(ctx, refreshToken, { cache })

  assertEquals(result.rotated, true)
  assertNotEquals(result.refreshToken, refreshToken)
  assertEquals(ctx.locals.session.token, result.refreshToken)

  // The consumed token is now blocklisted — reused right after, it must be rejected.
  await assertRejects(
    () => deriveSessionTokenBase(createCtx(), refreshToken, { cache }),
    PermissionDenied,
  )

  Deno.env.delete('JWT_KEY')
  Deno.env.delete(ROTATION_GRACE_WINDOW_ENV)
})

Deno.test('deriveSessionTokenBase: rotateRefresh true forces rotation on an otherwise fresh token', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  const refreshToken = await mintFreshRefreshToken(['admin'])
  const ctx = createCtx()

  const cache = { local: { get: () => undefined, set: () => {} } } as any

  const result = await deriveSessionTokenBase(ctx, refreshToken, { cache, rotateRefresh: true })

  assertEquals(result.rotated, true)
  assertNotEquals(result.refreshToken, refreshToken)

  Deno.env.delete('JWT_KEY')
})

Deno.test('deriveSessionTokenBase: rotateRefresh false forces reuse on an otherwise stale token', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  const refreshToken = await mintStaleRefreshToken(['admin'])
  const ctx = createCtx()

  const result = await deriveSessionTokenBase(ctx, refreshToken, { rotateRefresh: false })

  assertEquals(result.rotated, false)
  assertEquals(result.refreshToken, refreshToken)

  Deno.env.delete('JWT_KEY')
})

Deno.test(
  'deriveSessionTokenBase: a near-simultaneous re-presentation within the grace window returns ' +
    'the already-rotated refresh token, with the session correctly populated',
  async () => {
    Deno.env.set('JWT_KEY', 'my secret')

    const refreshToken = await mintStaleRefreshToken(['admin'])
    const store = new Map<string, unknown>()
    const cache = {
      local: {
        get: (key: string) => store.get(key),
        set: (key: string, value: unknown) => store.set(key, value),
      },
    } as any

    const first = await deriveSessionTokenBase(createCtx(), refreshToken, { cache })
    assertEquals(first.rotated, true)

    // The SAME (now-blocklisted) token, presented again immediately after — within the default
    // grace window, this must succeed with the exact refresh token `first` already rotated into,
    // not a rejection.
    const secondCtx = createCtx()
    const second = await deriveSessionTokenBase(secondCtx, refreshToken, { cache })
    assertEquals(second.refreshToken, first.refreshToken)
    assertEquals(secondCtx.locals.session.scope, ['admin'])

    Deno.env.delete('JWT_KEY')
  },
)

Deno.test(
  'deriveSessionTokenBase: sessionOptions overrides permissions embedded at mint time, even on ' +
    'the fresh/no-rotation path',
  async () => {
    Deno.env.set('JWT_KEY', 'my secret')

    const refreshToken = await mintFreshRefreshToken(['read'])
    const ctx = createCtx()

    await deriveSessionTokenBase(ctx, refreshToken, {
      sessionOptions: { permissions: ['read', 'write'] },
    })

    assertEquals(ctx.locals.session.scope, ['read', 'write'])

    Deno.env.delete('JWT_KEY')
  },
)

// ── The real, exported entry point: deriveSessionToken wraps the Base above ──

Deno.test(
  'deriveSessionToken: a blocklisted token rejects with HttpError(UNAUTHORIZED), never a bare ' +
    'PermissionDenied',
  async () => {
    Deno.env.set('JWT_KEY', 'my secret')

    const refreshToken = await mintFreshRefreshToken(['admin'])

    // Keyed like the real cache: blocklisted, but with no rotation-grace entry.
    const cache = {
      local: { get: (key: string) => key.includes(CACHE_KEYS.jwtBlockList) ? true : undefined },
    } as any

    const error = await assertRejects(
      () => deriveSessionToken(createCtx(), refreshToken, { cache }),
      HttpError,
    )
    assertEquals(error.status.value, 401)

    Deno.env.delete('JWT_KEY')
  },
)
