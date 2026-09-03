// deno-lint-ignore-file no-explicit-any
import { assert, assertEquals, assertRejects } from '@std/assert'
import { HttpError, PermissionDenied } from '@zanix/errors'
import { refreshSessionTokens, refreshSessionTokensBase } from 'utils/sessions/refresh.ts'
import { createAppToken, generateSessionTokens } from 'utils/sessions/create.ts'
import { decodeJWT } from 'utils/jwt/decode.ts'
import { CACHE_KEYS, ROTATION_GRACE_WINDOW_ENV } from 'utils/constants.ts'

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

  // Keyed like the real cache: blocklisted, but with no rotation-grace entry (e.g. a revoked
  // token, or one whose grace window already elapsed) — a straight rejection, no tolerance.
  const cache = {
    local: { get: (key: string) => key.includes(CACHE_KEYS.jwtBlockList) ? true : undefined },
  } as any
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
  // Disables the rotation grace window: this test asserts strict, no-tolerance reuse rejection,
  // not the grace path — that gets its own dedicated coverage below.
  Deno.env.set(ROTATION_GRACE_WINDOW_ENV, '0')

  const { refreshToken } = await generateSessionTokens(createCtx(), {
    subject: 'user@example.com',
  })

  const blocklisted = new Map<string, unknown>()
  const cache = {
    local: {
      get: (key: string) => blocklisted.get(key),
      set: (key: string, value: unknown) => blocklisted.set(key, value),
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

  Deno.env.delete(ROTATION_GRACE_WINDOW_ENV)
})

/**
 * Covers the rotation grace window: two requests presenting the SAME, still-valid-at-send-time
 * refresh token in close succession — a browser prefetching a link on hover and then navigating
 * it, a double click, two tabs on one session — is a legitimate pattern, not a replay. The second
 * request lands after the first already rotated and blocklisted the token, but within the grace
 * window it gets the first request's own newly issued pair back instead of a rejection.
 */
Deno.test(
  'refreshSessionTokensBase: a near-simultaneous re-presentation within the grace window ' +
    'returns the already-issued pair instead of rejecting',
  async () => {
    Deno.env.set('JWT_KEY', 'my secret')

    const { refreshToken } = await generateSessionTokens(createCtx(), {
      subject: 'user@example.com',
    })

    const store = new Map<string, unknown>()
    const cache = {
      local: {
        get: (key: string) => store.get(key),
        set: (key: string, value: unknown) => store.set(key, value),
      },
    } as any
    const kvDb = { get: () => undefined, set: () => {} } as any

    const first = await refreshSessionTokensBase(createCtx(), refreshToken, { cache, kvDb })
    assert(first.accessToken)

    // The SAME token, presented again immediately after — within the default grace window, this
    // must succeed with the exact pair `first` already issued, not a rejection.
    const second = await refreshSessionTokensBase(createCtx(), refreshToken, { cache, kvDb })
    assertEquals(second.accessToken, first.accessToken)
    assertEquals(second.refreshToken, first.refreshToken)

    Deno.env.delete('JWT_KEY')
  },
)

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
  // Disables the rotation grace window: this test asserts strict, no-tolerance reuse rejection,
  // not the grace path — that gets its own dedicated coverage below.
  Deno.env.set(ROTATION_GRACE_WINDOW_ENV, '0')

  const { refreshToken } = await generateSessionTokens(createCtx(), {
    subject: 'user@example.com',
  })

  const blocklisted = new Map<string, unknown>()
  const cache = {
    local: {
      get: (key: string) => blocklisted.get(key),
      set: (key: string, value: unknown) => blocklisted.set(key, value),
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
  Deno.env.delete(ROTATION_GRACE_WINDOW_ENV)
})

/**
 * `options.sessionOptions` lets a caller re-resolve fields like `permissions` on refresh, instead
 * of reusing whatever `AuthSessionOptions` was captured in the refresh token at the original
 * login — the only way, before this, to reflect a role/permission change without forcing a full
 * re-login.
 */
Deno.test(
  'refreshSessionTokensBase: sessionOptions overrides permissions embedded at mint time',
  async () => {
    Deno.env.set('JWT_KEY', 'my secret')

    const { refreshToken } = await generateSessionTokens(createCtx(), {
      subject: 'user@example.com',
      permissions: ['read'],
    })

    const result = await refreshSessionTokensBase(createCtx(), refreshToken, {
      sessionOptions: { permissions: ['read', 'write'] },
    })

    const { payload } = decodeJWT(result.accessToken)
    assertEquals(payload.aud, ['read', 'write'])

    Deno.env.delete('JWT_KEY')
  },
)

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

    // Keyed like the real cache: blocklisted, but with no rotation-grace entry.
    const cache = {
      local: { get: (key: string) => key.includes(CACHE_KEYS.jwtBlockList) ? true : undefined },
    } as any
    const kvDb = { get: () => undefined } as any

    const error = await assertRejects(
      () => refreshSessionTokens(createCtx(), refreshToken, { cache, kvDb }),
      HttpError,
    )
    assertEquals(error.status.value, 401)

    Deno.env.delete('JWT_KEY')
  },
)
