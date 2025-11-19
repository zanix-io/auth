import { asserts } from './asserts.ts'

Deno.test({
  sanitizeOps: false,
  sanitizeResources: false,
  name: 'blockList should add valid token using redis',
  fn: async () => {
    Deno.env.set('REDIS_URI', 'redis://localhost:6379')
    await asserts()
  },
})
