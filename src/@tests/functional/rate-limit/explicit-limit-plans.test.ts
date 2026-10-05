import { assert, assertEquals, assertFalse } from '@std/assert'
import { ProgramModule, RATE_LIMIT_HEADERS, type ZanixCacheConnector } from '@zanix/server'

import { rateLimitGuard } from 'modules/middlewares/rate-limit.guard.ts'
import { contextMock } from '../../mocks.ts'

// Own file on purpose: the plan map is parsed once per process, so `RATE_LIMIT_PLANS` has to be set
// before the first limit is resolved and must not leak into the other rate-limit suites.
Deno.env.set('RATE_LIMIT_PLANS', '0:100;1:1000;2:3000')

Deno.test('with RATE_LIMIT_PLANS, session.rateLimit is a plan index but `limit` is a count', async () => {
  Deno.env.delete('REDIS_URI')
  await import('@zanix/datamaster/core') // load cache core
  await ProgramModule.connectors.get<ZanixCacheConnector>('cache:local').clear()
  const options = { anonymousLimit: false, trustProxyHeader: true } as const
  const session = { id: 'jti-1', type: 'user' as const, rateLimit: 1 } // plan 1 = 1000 requests

  const planned = contextMock()
  planned.locals.session = session
  const byPlan = rateLimitGuard({ ...options, app: 'plan' })
  const results = await Promise.all([byPlan(planned), byPlan(planned), byPlan(planned)])
  for (const { response } of results) assertFalse(response)

  const explicit = contextMock()
  explicit.locals.session = session
  const byLimit = rateLimitGuard({ ...options, app: 'explicit', limit: 1 })
  assertFalse((await byLimit(explicit)).response)
  assert((await byLimit(explicit)).response) // `1` is one request, not plan index 1

  Deno.env.delete('RATE_LIMIT_PLANS')
})

Deno.test('rate-limit headers report the limit resolved from the plan, not the plan index', async () => {
  Deno.env.set('RATE_LIMIT_PLANS', '0:100;1:1000;2:3000')
  Deno.env.delete('REDIS_URI')
  await import('@zanix/datamaster/core') // load cache core
  await ProgramModule.connectors.get<ZanixCacheConnector>('cache:local').clear()
  const options = { anonymousLimit: false, trustProxyHeader: true } as const
  const context = contextMock()
  context.locals.session = { id: 'jti-h', type: 'user' as const, rateLimit: 1 }

  const guard = rateLimitGuard({ ...options, app: 'headers' })
  const first = await guard(context)
  assertEquals(first.headers?.[RATE_LIMIT_HEADERS.limitHeader], '1000')
  assertEquals(first.headers?.[RATE_LIMIT_HEADERS.remainingHeader], '999')
  const second = await guard(context)
  assertEquals(second.headers?.[RATE_LIMIT_HEADERS.remainingHeader], '998')

  const explicit = contextMock()
  explicit.locals.session = { id: 'jti-h2', type: 'user' as const, rateLimit: 1 }
  const withLimit = await rateLimitGuard({ ...options, app: 'headers-explicit', limit: 5 })(
    explicit,
  )
  assertEquals(withLimit.headers?.[RATE_LIMIT_HEADERS.limitHeader], '5')
  assertEquals(withLimit.headers?.[RATE_LIMIT_HEADERS.remainingHeader], '4')

  const anonymous = await rateLimitGuard({
    app: 'headers-anon',
    anonymousLimit: 7,
    trustProxyHeader: false,
  })(contextMock())
  assertEquals(anonymous.headers?.[RATE_LIMIT_HEADERS.limitHeader], '7')
  assertEquals(anonymous.headers?.[RATE_LIMIT_HEADERS.remainingHeader], '6')

  Deno.env.delete('RATE_LIMIT_PLANS')
})
