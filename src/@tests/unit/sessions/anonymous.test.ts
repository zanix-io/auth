import { assert, assertMatch } from '@std/assert'
import { getAnonymousSessionId } from 'utils/sessions/anonymous.ts'

function createHeaders(values: Record<string, string>) {
  return { get: (key: string) => values[key] ?? null } as never
}

Deno.test('getAnonymousSessionId uses the x-forwarded-for IP when well-formed', async () => {
  const id = await getAnonymousSessionId(
    createHeaders({ 'x-forwarded-for': '203.0.113.5' }),
  )
  assertMatch(id, /^anonymous-/)
})

Deno.test('getAnonymousSessionId falls back to invalid-ip on a malformed IP', async () => {
  const id = await getAnonymousSessionId(
    createHeaders({ 'x-forwarded-for': 'not-an-ip-address' }),
  )
  assert(id.startsWith('anonymous-'))
})

Deno.test('getAnonymousSessionId keeps unknown-ip when no IP header is present', async () => {
  const id = await getAnonymousSessionId(createHeaders({}))
  assert(id.startsWith('anonymous-'))
})
