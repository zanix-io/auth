// deno-lint-ignore-file no-explicit-any
import { assertEquals, assertRejects, assertThrows } from '@std/assert'
import { HttpError, InternalError } from '@zanix/errors'
import { rateLimitGuard } from 'modules/middlewares/rate-limit.guard.ts'

console.error = () => {}

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

// --- trustProxyHeader: required (no default) whenever anonymous access is enabled --------------
// These throw at CONSTRUCTION time — when `rateLimitGuard({...})` itself is called (e.g. as a
// `@Controller`'s `guards` argument, evaluated when that decorator loads), never on the first
// request. Same contract `ipAllowlistGuard` already established for this exact class of decision.

Deno.test(
  'rateLimitGuard throws at construction when anonymous access is enabled but trustProxyHeader is unset',
  () => {
    const error = assertThrows(
      () => rateLimitGuard({}),
      InternalError,
    )
    assertEquals((error as any).meta.method, 'rateLimitGuard')
  },
)

Deno.test(
  'rateLimitGuard does not throw when anonymousLimit is false (anonymous access disabled)',
  () => {
    rateLimitGuard({ anonymousLimit: false })
  },
)

Deno.test(
  'rateLimitGuard does not throw when anonymousLimit is 0 (same as false)',
  () => {
    rateLimitGuard({ anonymousLimit: 0 })
  },
)

Deno.test(
  'rateLimitGuard does not throw when trustProxyHeader is explicitly true',
  () => {
    rateLimitGuard({ trustProxyHeader: true })
  },
)

Deno.test(
  'rateLimitGuard does not throw when trustProxyHeader is explicitly false',
  () => {
    rateLimitGuard({ trustProxyHeader: false })
  },
)
