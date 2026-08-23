// deno-lint-ignore-file no-explicit-any
import { assert, assertEquals, assertRejects } from '@std/assert'
import { HttpError, PermissionDenied } from '@zanix/errors'
import { refreshSessionTokens, refreshSessionTokensBase } from 'utils/sessions/refresh.ts'
import { createAppToken, generateSessionTokens } from 'utils/sessions/create.ts'

console.warn = () => {}

function createCtx() {
  return { locals: {}, cookies: {} } as any
}

Deno.test('refreshSessionTokensBase throws when there is no refresh token available', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  await assertRejects(
    () => refreshSessionTokensBase(createCtx(), undefined),
    HttpError,
  )

  Deno.env.delete('JWT_KEY')
})

Deno.test('refreshSessionTokensBase reads refresh token from cookies when omitted', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  const { refreshToken } = await generateSessionTokens(createCtx(), {
    subject: 'user@example.com',
  })

  const ctx = {
    locals: {},
    cookies: { 'X-Znx-App-Token': refreshToken },
  } as any
  const result = await refreshSessionTokensBase(ctx, undefined)

  assert(result.accessToken)
  assert(result.refreshToken)

  Deno.env.delete('JWT_KEY')
})

Deno.test('refreshSessionTokensBase throws FORBIDDEN for a non-refresh token', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  const accessOnlyToken = await createAppToken({
    subject: 'user@example.com',
    type: 'user',
    expiration: '1h',
  })

  await assertRejects(
    () => refreshSessionTokensBase(createCtx(), accessOnlyToken),
    HttpError,
  )

  Deno.env.delete('JWT_KEY')
})

Deno.test('refreshSessionTokensBase returns new tokens for a valid refresh token', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  const { refreshToken } = await generateSessionTokens(createCtx(), {
    subject: 'user@example.com',
  })

  const result = await refreshSessionTokensBase(createCtx(), refreshToken)

  assert(result.accessToken)
  assert(result.refreshToken)
  assertEquals(result.oldToken, refreshToken)
  assert(result.payload)

  Deno.env.delete('JWT_KEY')
})

Deno.test('refreshSessionTokensBase throws PermissionDenied for a blocklisted token', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  const { refreshToken } = await generateSessionTokens(createCtx(), {
    subject: 'user@example.com',
  })

  const cache = { local: { get: () => true } } as any
  const kvDb = { get: () => undefined } as any

  await assertRejects(
    () => refreshSessionTokensBase(createCtx(), refreshToken, { cache, kvDb }),
    PermissionDenied,
  )

  Deno.env.delete('JWT_KEY')
})

Deno.test('refreshSessionTokensBase succeeds when the token is not in the block list', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  const { refreshToken } = await generateSessionTokens(createCtx(), {
    subject: 'user@example.com',
  })

  const cache = { local: { get: () => undefined, set: () => {} } } as any
  const kvDb = { get: () => undefined, set: () => {} } as any

  const result = await refreshSessionTokensBase(createCtx(), refreshToken, {
    cache,
    kvDb,
  })

  assert(result.accessToken)

  Deno.env.delete('JWT_KEY')
})

/**
 * Regression coverage for a confirmed vulnerability: `refreshSessionTokensBase` used to return
 * `oldToken` without ever blocklisting it — the same refresh token stayed valid indefinitely,
 * letting it be replayed to mint new sessions forever, even after the legitimate client had
 * already rotated past it. Proven end to end: refresh once, blocklist `oldToken` the way a real
 * caller would (matching `revokeSessionToken`'s own `addTokenToBlockList` usage), then confirm
 * `checkTokenBlockList` — the exact function `refreshSessionTokensBase` itself consults — now reports
 * it blocklisted.
 */
Deno.test('refreshSessionTokensBase: rotation blocklists the consumed token', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  const { refreshToken } = await generateSessionTokens(createCtx(), {
    subject: 'user@example.com',
  })

  const blocklisted = new Map<string, boolean>()
  const cache = {
    local: {
      get: (key: string) => blocklisted.get(key),
      set: (key: string, value: boolean) => blocklisted.set(key, value),
    },
  } as any
  const kvDb = { get: () => undefined, set: () => {} } as any

  const result = await refreshSessionTokensBase(createCtx(), refreshToken, { cache, kvDb })
  assert(result.accessToken)

  // The SAME token, presented again — must now be rejected as blocklisted, not accepted a
  // second time.
  await assertRejects(
    () => refreshSessionTokensBase(createCtx(), refreshToken, { cache, kvDb }),
    PermissionDenied,
  )
})

/**
 * Regression coverage for a confirmed inconsistency: the reuse CHECK used to require both
 * `cache` and `kvDb` (`checkTokenBlockList`'s `kvDb` param was mandatory), while the blocklist
 * WRITE only ever required `cache` (`addTokenToBlockList`'s `kvDb` was already optional). A
 * caller wiring only `cache` — a fully valid, documented configuration — got writes with no
 * check: every refresh still blocklisted the consumed token, but nothing ever looked it up, so a
 * replayed token was silently accepted again instead of rejected. Both functions now gate on
 * `cache` alone; proven end to end with no `kvDb` passed at all.
 */
Deno.test('refreshSessionTokensBase: rotation detects reuse via cache alone, no kvDb', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  const { refreshToken } = await generateSessionTokens(createCtx(), {
    subject: 'user@example.com',
  })

  const blocklisted = new Map<string, boolean>()
  const cache = {
    local: {
      get: (key: string) => blocklisted.get(key),
      set: (key: string, value: boolean) => blocklisted.set(key, value),
    },
  } as any

  const result = await refreshSessionTokensBase(createCtx(), refreshToken, { cache })
  assert(result.accessToken)

  // The SAME token, presented again — must be rejected as blocklisted, even with no `kvDb`
  // configured at all.
  await assertRejects(
    () => refreshSessionTokensBase(createCtx(), refreshToken, { cache }),
    PermissionDenied,
  )

  Deno.env.delete('JWT_KEY')
})

// ── The real, exported entry point: refreshSessionTokens wraps the Base above ──

Deno.test(
  'refreshSessionTokens: a valid refresh token returns new tokens, same as the Base',
  async () => {
    Deno.env.set('JWT_KEY', 'my secret')

    const { refreshToken } = await generateSessionTokens(createCtx(), {
      subject: 'user@example.com',
    })

    const result = await refreshSessionTokens(createCtx(), refreshToken)
    assert(result.accessToken)
    assert(result.refreshToken)

    Deno.env.delete('JWT_KEY')
  },
)

Deno.test(
  'refreshSessionTokens: a blocklisted token rejects with HttpError(UNAUTHORIZED), never a bare ' +
    'PermissionDenied',
  async () => {
    Deno.env.set('JWT_KEY', 'my secret')

    const { refreshToken } = await generateSessionTokens(createCtx(), {
      subject: 'user@example.com',
    })

    const cache = { local: { get: () => true } } as any
    const kvDb = { get: () => undefined } as any

    const error = await assertRejects(
      () => refreshSessionTokens(createCtx(), refreshToken, { cache, kvDb }),
      HttpError,
    )
    assertEquals(error.status.value, 401)

    Deno.env.delete('JWT_KEY')
  },
)
