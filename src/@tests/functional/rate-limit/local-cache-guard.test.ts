import {
  addValidHeaders,
  addValidSessionHeaders,
  shouldFailDueLimit,
  shouldFailDueLimitAnonymous,
  shouldLogError,
  shouldNotAddSessionHeaders,
  shouldResetLimit,
  shouldSupportConcurrency,
} from './asserts.ts'

Deno.test({
  sanitizeOps: false,
  sanitizeResources: false,
  name: 'rateLimitGuard should add valid headers',
  fn: async () => {
    Deno.env.delete('REDIS_URI')
    await addValidHeaders('cache:local')
  },
})

Deno.test('rateLimitGuard should add valid session headers', async () => {
  Deno.env.delete('REDIS_URI')
  await addValidSessionHeaders()
})

Deno.test('rateLimitGuard should not add session headers if already exist', async () => {
  Deno.env.delete('REDIS_URI')
  await shouldNotAddSessionHeaders()
})

Deno.test('rateLimitGuard should support concurrency', async () => {
  Deno.env.delete('REDIS_URI')
  await shouldSupportConcurrency('cache:local')
})

Deno.test('rateLimitGuard should fail due anonymous limit exceed', async () => {
  Deno.env.delete('REDIS_URI')
  await shouldFailDueLimitAnonymous('cache:local')
})

Deno.test('rateLimitGuard should fail due identified user limit exceed', async () => {
  Deno.env.delete('REDIS_URI')
  await shouldFailDueLimit('cache:local')
})

Deno.test('rateLimitGuard should log error due many failed attempts', async () => {
  Deno.env.delete('REDIS_URI')
  await shouldLogError('cache:local')
})

Deno.test('rateLimitGuard should reset limit after window second', async () => {
  Deno.env.delete('REDIS_URI')
  await shouldResetLimit('cache:local')
})
