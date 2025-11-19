import {
  shouldAllowDifferentLens,
  shouldGenerateAndExpire,
  shouldGenerateAndVerify,
} from './asserts.ts'

Deno.test({
  sanitizeOps: false,
  sanitizeResources: false,
  name: 'should generate and expire an OTP',
  fn: async () => {
    Deno.env.delete('REDIS_URI')
    await shouldGenerateAndExpire('local')
  },
})

Deno.test('should generate and verify an OTP', async () => {
  Deno.env.delete('REDIS_URI')
  await shouldGenerateAndVerify('local')
})

Deno.test('should allow diffetent lenghts', async () => {
  Deno.env.delete('REDIS_URI')
  await shouldAllowDifferentLens('local')
})
