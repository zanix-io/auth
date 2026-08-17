// deno-lint-ignore-file no-explicit-any
import { assertEquals } from '@std/assert'
import { verifyOTP } from 'utils/otp.ts'

Deno.test('verifyOTP returns false immediately when no code is provided', async () => {
  const cache = { local: { get: () => 'never-reached' } } as any

  assertEquals(await verifyOTP(cache, 'target', ''), false)
  assertEquals(
    await verifyOTP(cache, 'target', undefined as unknown as string),
    false,
  )
})
