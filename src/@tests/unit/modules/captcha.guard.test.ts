// deno-lint-ignore-file no-explicit-any
import { assertEquals } from '@std/assert'
import type { CaptchaProviderAdapter, CaptchaVerifyResult } from 'typings/captcha.ts'
import { CAPTCHA_TOKEN_HEADER, captchaGuard } from 'modules/middlewares/captcha.guard.ts'

console.error = () => {}

function createCtx(headers: Record<string, string> = {}) {
  return {
    id: 'req-1',
    req: { headers: new Headers(headers) },
  } as any
}

class MockAdapter implements CaptchaProviderAdapter {
  public calls: string[] = []
  constructor(private result: CaptchaVerifyResult) {}
  public verify(token: string): Promise<CaptchaVerifyResult> {
    this.calls.push(token)
    return Promise.resolve(this.result)
  }
}

Deno.test('captchaGuard: pass-through when no provider/adapter is configured', async () => {
  const guard = captchaGuard()
  const result = await guard(createCtx())
  assertEquals(result, {})
})

Deno.test('captchaGuard: rejects with 400 when the token header is missing', async () => {
  const adapter = new MockAdapter({ success: true })
  const guard = captchaGuard({ adapter })
  const result = await guard(createCtx())
  assertEquals(result.response?.status, 400)
  assertEquals(adapter.calls.length, 0)
})

Deno.test('captchaGuard: forwards the header token to the adapter, passes on success', async () => {
  const adapter = new MockAdapter({ success: true })
  const guard = captchaGuard({ adapter })
  const result = await guard(createCtx({ [CAPTCHA_TOKEN_HEADER]: 'token-abc' }))
  assertEquals(result, {})
  assertEquals(adapter.calls, ['token-abc'])
})

Deno.test('captchaGuard: rejects with 403 when the adapter reports failure', async () => {
  const adapter = new MockAdapter({ success: false, errorCodes: ['invalid-input-response'] })
  const guard = captchaGuard({ adapter })
  const result = await guard(createCtx({ [CAPTCHA_TOKEN_HEADER]: 'bad-token' }))
  assertEquals(result.response?.status, 403)
})

Deno.test('captchaGuard: passes when success is true and no score is returned', async () => {
  const adapter = new MockAdapter({ success: true })
  const guard = captchaGuard({ adapter, minScore: 0.9 })
  const result = await guard(createCtx({ [CAPTCHA_TOKEN_HEADER]: 'token-abc' }))
  assertEquals(result, {})
})

Deno.test('captchaGuard: rejects when score is below the default minScore (0.5)', async () => {
  const adapter = new MockAdapter({ success: true, score: 0.3 })
  const guard = captchaGuard({ adapter })
  const result = await guard(createCtx({ [CAPTCHA_TOKEN_HEADER]: 'token-abc' }))
  assertEquals(result.response?.status, 403)
})

Deno.test('captchaGuard: passes when score meets the default minScore (0.5)', async () => {
  const adapter = new MockAdapter({ success: true, score: 0.5 })
  const guard = captchaGuard({ adapter })
  const result = await guard(createCtx({ [CAPTCHA_TOKEN_HEADER]: 'token-abc' }))
  assertEquals(result, {})
})

Deno.test('captchaGuard: honors a custom minScore', async () => {
  const adapter = new MockAdapter({ success: true, score: 0.6 })
  const guard = captchaGuard({ adapter, minScore: 0.8 })
  const result = await guard(createCtx({ [CAPTCHA_TOKEN_HEADER]: 'token-abc' }))
  assertEquals(result.response?.status, 403)
})
