// deno-lint-ignore-file no-explicit-any
import { assertEquals, assertRejects } from '@std/assert'
import { HttpError } from '@zanix/errors'
import { rateLimitGuard } from 'modules/middlewares/rate-limit.guard.ts'

function createCtx(session: unknown) {
  return {
    id: 'req-1',
    req: { headers: { get: () => null } },
    locals: { session },
  } as any
}

Deno.test('rateLimitGuard reports "Anonymous users not permitted" with no session', async () => {
  const guard = rateLimitGuard({ anonymousLimit: false })

  const error = await assertRejects(
    async () => {
      await guard(createCtx(undefined))
    },
    HttpError,
  )

  assertEquals((error as any).meta.reason, 'Anonymous users are not permitted')
})

Deno.test('rateLimitGuard reports missing rate limit config when session lacks it', async () => {
  const guard = rateLimitGuard({ anonymousLimit: false })

  const error = await assertRejects(
    async () => {
      await guard(createCtx({ id: 'u1', type: 'user' }))
    },
    HttpError,
  )

  assertEquals(
    (error as any).meta.reason,
    'No session found with a valid rate limit configuration.',
  )
})
