// deno-lint-ignore-file no-explicit-any
import { assertEquals, assertRejects, assertStrictEquals } from '@std/assert'
import { RecaptchaAdapter } from 'modules/connectors/captcha/recaptcha.ts'

console.error = () => {}

function mockAdapter(response: unknown) {
  const adapter = new RecaptchaAdapter({ secretKey: 'test-secret' })
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

Deno.test('RecaptchaAdapter: posts secret/response to siteverify and returns success', async () => {
  const { adapter, calls } = mockAdapter({ success: true })
  const result = await adapter.verify('client-token')

  assertEquals(calls[0].url, 'siteverify')
  assertEquals(calls[0].body.get('secret'), 'test-secret')
  assertEquals(calls[0].body.get('response'), 'client-token')
  assertEquals(result, { success: true, score: undefined, errorCodes: undefined })
})

Deno.test('RecaptchaAdapter: forwards a v3 score when the response carries one', async () => {
  const { adapter } = mockAdapter({ success: true, score: 0.9, action: 'signup' })
  const result = await adapter.verify('client-token')
  assertEquals(result.score, 0.9)
})

Deno.test('RecaptchaAdapter: forwards error-codes on failure', async () => {
  const { adapter } = mockAdapter({ success: false, 'error-codes': ['timeout-or-duplicate'] })
  const result = await adapter.verify('client-token')
  assertEquals(result, { success: false, score: undefined, errorCodes: ['timeout-or-duplicate'] })
})

Deno.test('RecaptchaAdapter: a transport failure is logged (metadata) and rethrown', async () => {
  const adapter = new RecaptchaAdapter({ secretKey: 'test-secret' })
  const transportError = new Error('network down')
  // @ts-ignore private override, same pattern as mockAdapter() above
  adapter.http = {
    post: <T>() => Promise.reject(transportError) as T,
  }

  const error = await assertRejects(() => adapter.verify('client-token'))
  assertStrictEquals(error, transportError)
})
