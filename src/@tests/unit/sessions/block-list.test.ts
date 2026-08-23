// deno-lint-ignore-file no-explicit-any
import { assert, assertEquals, assertFalse, assertRejects } from '@std/assert'
import { HttpError, PermissionDenied } from '@zanix/errors'
import {
  addTokenToBlockList,
  addTokenToBlockListBase,
  checkTokenBlockList,
} from 'utils/sessions/block-list.ts'
import { createJWT } from 'utils/jwt/create.ts'

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
