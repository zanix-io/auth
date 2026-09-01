// deno-lint-ignore-file no-explicit-any
import { assertEquals, assertRejects, assertStrictEquals } from '@std/assert'
import { HCaptchaAdapter } from 'modules/connectors/captcha/hcaptcha.ts'

console.error = () => {}

function mockAdapter(response: unknown) {
  const adapter = new HCaptchaAdapter({ secretKey: 'test-secret' })
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

Deno.test('HCaptchaAdapter: posts secret/response to siteverify and returns success', async () => {
  const { adapter, calls } = mockAdapter({ success: true })
  const result = await adapter.verify('client-token')

  assertEquals(calls[0].url, 'siteverify')
  assertEquals(calls[0].body.get('secret'), 'test-secret')
  assertEquals(calls[0].body.get('response'), 'client-token')
  assertEquals(result, { success: true, score: undefined, errorCodes: undefined })
})

Deno.test('HCaptchaAdapter: forwards error-codes on failure', async () => {
  const { adapter } = mockAdapter({ success: false, 'error-codes': ['invalid-input-secret'] })
  const result = await adapter.verify('client-token')
  assertEquals(result, { success: false, score: undefined, errorCodes: ['invalid-input-secret'] })
})

Deno.test('HCaptchaAdapter: a transport failure is logged (metadata) and rethrown', async () => {
  const adapter = new HCaptchaAdapter({ secretKey: 'test-secret' })
  const transportError = new Error('network down')
  // @ts-ignore private override, same pattern as mockAdapter() above
  adapter.http = {
    post: <T>() => Promise.reject(transportError) as T,
  }

  const error = await assertRejects(() => adapter.verify('client-token'))
  assertStrictEquals(error, transportError)
})
