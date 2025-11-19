import {
  shouldAllowDifferentLens,
  shouldGenerateAndExpire,
  shouldGenerateAndVerify,
} from './asserts.ts'

Deno.test({
  sanitizeOps: false,
  sanitizeResources: false,
  name: 'should generate an expire an OTP',
  fn: async () => {
    Deno.env.set('REDIS_URI', 'redis://localhost:6379')
    await shouldGenerateAndExpire('redis')
  },
})

Deno.test({
  sanitizeOps: false,
  sanitizeResources: false,
  name: 'should generate and verify an OTP',
  fn: async () => {
    Deno.env.set('REDIS_URI', 'redis://localhost:6379')
    await shouldGenerateAndVerify('redis')
  },
})

Deno.test({
  sanitizeOps: false,
  sanitizeResources: false,
  name: 'should allow different lenghts',
  fn: async () => {
    Deno.env.set('REDIS_URI', 'redis://localhost:6379')
    await shouldAllowDifferentLens('redis')
  },
})
