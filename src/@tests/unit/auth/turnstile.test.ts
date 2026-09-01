// deno-lint-ignore-file no-explicit-any
import { assertEquals, assertRejects, assertStrictEquals } from '@std/assert'
import { TurnstileAdapter } from 'modules/connectors/captcha/turnstile.ts'

console.error = () => {}

function mockAdapter(response: unknown) {
  const adapter = new TurnstileAdapter({ secretKey: 'test-secret' })
  const calls: any[] = []
  adapter.http = {
    // @ts-ignore private override, same pattern google.test.ts's MockRestClient uses
    post: (url: string, options: any) => {
      calls.push({ url, body: options?.body })
      return Promise.resolve(response)
    },
  }
  return { adapter, calls }
}

Deno.test('TurnstileAdapter: posts secret/response to siteverify and returns success', async () => {
  const { adapter, calls } = mockAdapter({ success: true })
  const result = await adapter.verify('client-token')

  assertEquals(calls[0].url, 'siteverify')
  assertEquals(calls[0].body.get('secret'), 'test-secret')
  assertEquals(calls[0].body.get('response'), 'client-token')
  assertEquals(result, { success: true, errorCodes: undefined })
})

Deno.test('TurnstileAdapter: never returns a score, even if the response had one', async () => {
  // Turnstile's public API never returns `score` — locking in that this adapter doesn't forward
  // a stray field from a mocked/unexpected response as if it meant something.
  const { adapter } = mockAdapter({ success: true, score: 0.9 } as any)
  const result = await adapter.verify('client-token')
  assertEquals(result.score, undefined)
})

Deno.test('TurnstileAdapter: forwards error-codes on failure', async () => {
  const { adapter } = mockAdapter({ success: false, 'error-codes': ['invalid-input-response'] })
  const result = await adapter.verify('client-token')
  assertEquals(result, { success: false, errorCodes: ['invalid-input-response'] })
})

Deno.test('TurnstileAdapter: a transport failure is logged (metadata) and rethrown', async () => {
  const adapter = new TurnstileAdapter({ secretKey: 'test-secret' })
  const transportError = new Error('network down')
  // @ts-ignore private override, same pattern as mockAdapter() above
  adapter.http = {
    post: <T>() => Promise.reject(transportError) as T,
  }

  const error = await assertRejects(() => adapter.verify('client-token'))
  assertStrictEquals(error, transportError)
})
