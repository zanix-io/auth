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

console.info = () => {}
console.warn = () => {}

Deno.test({
  sanitizeOps: false,
  sanitizeResources: false,
  name: 'rateLimitGuard should add valid headers ',
  fn: async () => {
    Deno.env.set('REDIS_URI', 'redis://localhost:6379')
    await addValidHeaders('cache:redis')
  },
})

Deno.test({
  sanitizeOps: false,
  sanitizeResources: false,
  name: 'rateLimitGuard should add valid session headers',
  fn: async () => {
    Deno.env.set('REDIS_URI', 'redis://localhost:6379')
    await addValidSessionHeaders()
  },
})

Deno.test({
  sanitizeOps: false,
  sanitizeResources: false,
  name: 'rateLimitGuard should not add session headers if already exist',
  fn: async () => {
    Deno.env.set('REDIS_URI', 'redis://localhost:6379')
    await shouldNotAddSessionHeaders()
  },
})

Deno.test({
  sanitizeResources: false,
  sanitizeOps: false,
  name: 'rateLimitGuard should support concurrency',
  fn: async () => {
    Deno.env.set('REDIS_URI', 'redis://localhost:6379')
    await shouldSupportConcurrency('cache:redis')
  },
})

Deno.test({
  sanitizeOps: false,
  sanitizeResources: false,
  name: 'rateLimitGuard should fail due anonymous limit exceed',
  fn: async () => {
    Deno.env.set('REDIS_URI', 'redis://localhost:6379')
    await shouldFailDueLimitAnonymous('cache:redis')
  },
})

Deno.test({
  sanitizeOps: false,
  sanitizeResources: false,
  name: 'rateLimitGuard should fail due identified user limit exceed',
  fn: async () => {
    Deno.env.set('REDIS_URI', 'redis://localhost:6379')
    await shouldFailDueLimit('cache:redis')
  },
})

Deno.test({
  sanitizeOps: false,
  sanitizeResources: false,
  name: 'rateLimitGuard should log error due many failed attempts',
  fn: async () => {
    Deno.env.set('REDIS_URI', 'redis://localhost:6379')
    await shouldLogError('cache:redis')
  },
})

Deno.test({
  sanitizeOps: false,
  sanitizeResources: false,
  name: 'rateLimitGuard should reset limit after window second',
  fn: async () => {
    Deno.env.set('REDIS_URI', 'redis://localhost:6379')
    await shouldResetLimit('cache:redis')
  },
})
