import { asserts } from './asserts.ts'

Deno.test({
  sanitizeOps: false,
  sanitizeResources: false,
  name: 'blockList should add valid token using local cache',
  fn: async () => {
    Deno.env.delete('REDIS_URI')
    await asserts()
  },
})
