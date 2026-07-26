// deno-lint-ignore-file no-explicit-any
import { assert, assertEquals } from '@std/assert'
import { checkTokenBlockList } from 'utils/sessions/block-list.ts'

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

  assertEquals(result, undefined)
})
