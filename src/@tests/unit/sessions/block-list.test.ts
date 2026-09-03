// deno-lint-ignore-file no-explicit-any
import { assert, assertEquals, assertFalse, assertRejects } from '@std/assert'
import { HttpError, PermissionDenied } from '@zanix/errors'
import {
  addTokenToBlockList,
  addTokenToBlockListBase,
  checkTokenBlockList,
  getRotationGraceTokens,
  setRotationGraceTokens,
} from 'utils/sessions/block-list.ts'
import { createJWT } from 'utils/jwt/create.ts'
import { ROTATION_GRACE_WINDOW_ENV } from 'utils/constants.ts'

Deno.test('checkTokenBlockList falls back to KV store and caches the value locally', async () => {
  Deno.env.delete('REDIS_URI')

  const localSets: unknown[] = []
  const cache = {
    local: {
      get: () => undefined,
      set: (key: string, value: unknown) => {
        localSets.push([key, value])
      },
    },
  } as any
  const kvDb = { get: () => true } as any

  const result = await checkTokenBlockList('token-id', cache, kvDb)

  assert(result)
  assertEquals(localSets.length, 1)
})

Deno.test('checkTokenBlockList returns undefined when neither cache nor KV has it', async () => {
  Deno.env.delete('REDIS_URI')

  const cache = { local: { get: () => undefined, set: () => {} } } as any
  const kvDb = { get: () => undefined } as any

  const result = await checkTokenBlockList('token-id', cache, kvDb)

  assertFalse(result)
})

Deno.test('addTokenToBlockListBase: blocklists a valid token, keyed by its own jti', async () => {
  Deno.env.delete('REDIS_URI')

  const token = await createJWT({ exp: 9999999999, sub: 'mock@example.com' }, 'my secret')
  const sets: unknown[][] = []
  const cache = { local: { set: (...args: unknown[]) => sets.push(args) } } as any

  const payload = await addTokenToBlockListBase(token, cache)

  assert(payload.jti)
  assertEquals(sets.length, 1)
})

Deno.test(
  'addTokenToBlockListBase: a malformed token rejects with a bare PermissionDenied',
  async () => {
    await assertRejects(
      () => addTokenToBlockListBase('not-a-real-token', {} as any),
      PermissionDenied,
    )
  },
)

// ── The real, exported entry point: addTokenToBlockList wraps the Base above ──

Deno.test('addTokenToBlockList: a valid token blocklists, same as the Base', async () => {
  Deno.env.delete('REDIS_URI')

  const token = await createJWT({ exp: 9999999999, sub: 'mock@example.com' }, 'my secret')
  const cache = { local: { set: () => {} } } as any

  const payload = await addTokenToBlockList(token, cache)
  assert(payload.jti)
})

Deno.test(
  'addTokenToBlockList: a malformed token rejects with HttpError(BAD_REQUEST), never a bare ' +
    'PermissionDenied',
  async () => {
    const error = await assertRejects(
      () => addTokenToBlockList('not-a-real-token', {} as any),
      HttpError,
    )
    assertEquals(error.status.value, 400)
  },
)

// ── The rotation grace window: setRotationGraceTokens/getRotationGraceTokens ──

Deno.test(
  'setRotationGraceTokens/getRotationGraceTokens: round-trips a pair through local cache, ' +
    'falling back to KV like checkTokenBlockList does',
  async () => {
    Deno.env.delete('REDIS_URI')

    const local = new Map<string, unknown>()
    const kv = new Map<string, unknown>()
    const cache = {
      local: {
        get: (key: string) => local.get(key),
        set: (key: string, value: unknown) => local.set(key, value),
      },
    } as any
    const kvDb = {
      get: (key: string) => kv.get(key),
      set: (key: string, value: unknown) => kv.set(key, value),
    } as any

    const tokens = { accessToken: 'a-token', refreshToken: 'r-token' }
    await setRotationGraceTokens('some-jti', tokens, cache, kvDb)

    // Written to both tiers, same as addTokenToBlockListBase's own local/KV write.
    assertEquals(await getRotationGraceTokens('some-jti', cache, kvDb), tokens)

    // A fresh local cache with nothing in it falls back to KV, exactly like checkTokenBlockList.
    const freshLocal = new Map<string, unknown>()
    const freshCache = {
      local: {
        get: (key: string) => freshLocal.get(key),
        set: (key: string, value: unknown) => freshLocal.set(key, value),
      },
    } as any
    assertEquals(await getRotationGraceTokens('some-jti', freshCache, kvDb), tokens)
  },
)

Deno.test('getRotationGraceTokens returns undefined once nothing was ever set for that jti', async () => {
  Deno.env.delete('REDIS_URI')

  const cache = { local: { get: () => undefined, set: () => {} } } as any
  const kvDb = { get: () => undefined } as any

  assertEquals(await getRotationGraceTokens('never-rotated', cache, kvDb), undefined)
})

Deno.test('setRotationGraceTokens is a no-op once ROTATION_GRACE_WINDOW=0 disables the window', async () => {
  Deno.env.delete('REDIS_URI')
  Deno.env.set(ROTATION_GRACE_WINDOW_ENV, '0')

  const sets: unknown[] = []
  const cache = {
    local: { get: () => undefined, set: (...args: unknown[]) => sets.push(args) },
  } as any

  await setRotationGraceTokens('some-jti', { accessToken: 'a', refreshToken: 'r' }, cache)

  assertEquals(sets.length, 0)

  Deno.env.delete(ROTATION_GRACE_WINDOW_ENV)
})

Deno.test(
  'setRotationGraceTokens/getRotationGraceTokens: use the Redis path when REDIS_URI is set',
  async () => {
    Deno.env.set('REDIS_URI', 'redis://localhost:6379')

    const saved: unknown[] = []
    const tokens = { accessToken: 'a-token', refreshToken: 'r-token' }
    const cache = {
      saveToCaches: (options: unknown) => {
        saved.push(options)
        return Promise.resolve()
      },
      getCachedOrFetch: () => Promise.resolve(tokens),
    } as any

    await setRotationGraceTokens('some-jti', tokens, cache)
    assertEquals(saved.length, 1)
    assertEquals((saved[0] as { value: unknown }).value, tokens)

    assertEquals(await getRotationGraceTokens('some-jti', cache), tokens)

    Deno.env.delete('REDIS_URI')
  },
)
