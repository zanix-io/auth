// deno-coverage-ignore-file

import { assert, assertAlmostEquals, assertEquals, assertFalse } from '@std/assert'

import { sessionHeadersInterceptor } from 'modules/middlewares/headers.interceptor.ts'
import { rateLimitGuard } from 'modules/middlewares/rate-limit.guard.ts'
import { contextMock } from '../../mocks.ts'
import { ProgramModule, RATE_LIMIT_HEADERS, type ZanixCacheConnector } from '@zanix/server'
import { stub } from '@std/testing/mock'
import { FakeTime } from '@std/testing/time'
import { CACHE_KEYS } from 'utils/constants.ts'

export const addValidHeaders = async (cache: 'cache:local' | 'cache:redis') => {
  await import('@zanix/datamaster/core') // load cache core
  await (ProgramModule.connectors.get<ZanixCacheConnector>(cache)).clear() // reset data
  const context = contextMock()

  const guard = rateLimitGuard({ app: 'test', trustProxyHeader: true })
  const { response, headers = {} } = await guard(context)
  assertFalse(response)
  assertEquals(headers[RATE_LIMIT_HEADERS.limitHeader], '100')
  assertEquals(headers[RATE_LIMIT_HEADERS.remainingHeader], '99')
  assertAlmostEquals(Number(headers[RATE_LIMIT_HEADERS.resetHeader]), 60, 1)
}

export const addValidSessionHeaders = async () => {
  await import('@zanix/datamaster/core') // load cache core
  const context = contextMock()

  const guard = rateLimitGuard({ app: 'test', trustProxyHeader: true })
  await guard(context)
  // Simulates `@zanix/server`'s `contextSettingPipe`, which always promotes `locals.session` to
  // the frozen `ctx.session` between the guard phase and any interceptor.
  context.session = context.locals.session as never
  const response = new Response()
  await sessionHeadersInterceptor()(context, response)

  assert(response.headers.get('X-Znx-User-Id')?.startsWith('anonymous-'))
  assertEquals(
    response.headers.get('X-Znx-User-Session-Status'),
    'unconfirmed',
  )
}

export const shouldNotAddSessionHeaders = async () => {
  await import('@zanix/datamaster/core') // load cache core
  const context = contextMock()

  const guard = rateLimitGuard({ app: 'test', trustProxyHeader: true })
  context.req.headers.get = (name) => name === 'X-Znx-User-Id' ? 'my-user' : null
  const { headers: baseHeaders = {} } = await guard(context)

  assert(context.locals.session?.id.startsWith('anonymous-'))
  assertEquals(context.locals.session?.type, 'anonymous')
  assertFalse(baseHeaders['X-Znx-User-Id'])
  assertFalse(baseHeaders['X-Znx-User-Session-Status'])
}

export const shouldSupportConcurrency = async (
  cache: 'cache:local' | 'cache:redis',
) => {
  await import('@zanix/datamaster/core') // load cache core
  await (ProgramModule.connectors.get<ZanixCacheConnector>(cache)).clear() // reset data
  const context = contextMock()

  const guard = rateLimitGuard({ app: 'test', trustProxyHeader: true })

  const windowStart = Date.now()
  await guard(context)
  await Promise.all([
    guard(context),
    guard(context),
    guard(context),
    guard(context),
    guard(context),
  ]) // support concurrency
  await new Promise((resolve) => setTimeout(resolve, 1000))
  const { response, headers = {} } = await guard(context)
  assertFalse(response)

  assertEquals(headers[RATE_LIMIT_HEADERS.remainingHeader], '93')

  // `resetHeader` is `windowSeconds - (elapsedSeconds % windowSeconds)`, computed against real
  // wall-clock time (real Redis round-trips add unpredictable latency), so assert it's close to
  // the value derived from what actually elapsed here rather than a hardcoded pair of seconds.
  const elapsedSeconds = Math.floor((Date.now() - windowStart) / 1000)
  const expectedReset = 60 - (elapsedSeconds % 60)
  const reset = Number(headers[RATE_LIMIT_HEADERS.resetHeader])
  assertAlmostEquals(reset, expectedReset, 2)
}

export const shouldFailDueLimitAnonymous = async (
  cache: 'cache:local' | 'cache:redis',
) => {
  await import('@zanix/datamaster/core') // load cache core
  // deno-lint-ignore no-explicit-any
  await ProgramModule.connectors.get<any>(cache).clear() // reset data
  const context = contextMock()

  const guard = rateLimitGuard({ anonymousLimit: 2, app: 'test', trustProxyHeader: true })
  const windowSeconds = 60 // rateLimitGuard's own default, not overridden above

  // Only the Redis path is driven by `FakeTime`: `checkRateLimit`'s local-cache branch schedules
  // its own resolution via a real, zero-delay `setTimeout` (see `rate-limit.ts`), which a globally
  // faked clock would leave permanently pending unless manually ticked — and that branch never had
  // a real-clock race to begin with (no network latency), so it keeps the real wait untouched.
  // `Date.now()` is pinned by `FakeTime` on the Redis side (`rate-limit.guard.ts`/`checkRateLimit`
  // both read it, including the `now` argument sent to the Lua script), advanced only by our own
  // explicit `wait` calls below — no real wall-clock wait, no real-clock/network race, so the
  // `assertEquals` below is exact by construction rather than by tolerance.
  using time = cache === 'cache:redis' ? new FakeTime() : undefined
  const wait = async (ms: number) => {
    if (time) time.tick(ms)
    else await new Promise((resolve) => setTimeout(resolve, ms))
  }

  await Promise.all([guard(context), guard(context)]) // support concurrency
  await wait(1000)
  const { response } = await guard(context)

  const error = await response?.json()
  assertEquals(error.name, 'HttpError')
  assertEquals(error.status.code, 'TOO_MANY_REQUESTS')
  assertEquals(error.meta.sessionType, 'anonymous')
  assertEquals(error.meta.rateLimit, 2)
  assertEquals(error.meta.windowSeconds, 60)
  assert(error.meta.sessionRef.startsWith('anonymous-'))

  await wait(2000)
  const { response: checkRetry } = await guard(context)
  const retryAfter = Number(checkRetry?.headers.get('retry-after'))

  if (time) {
    const elapsedSeconds = 3 // exactly the 1000ms + 2000ms ticked above
    assertEquals(retryAfter, windowSeconds - elapsedSeconds)
  } else {
    // Local-cache path: still a real wall-clock wait, so keep a small tolerance here.
    assertAlmostEquals(retryAfter, windowSeconds - 3, 2)
  }
}

export const shouldFailDueLimit = async (
  cache: 'cache:local' | 'cache:redis',
) => {
  await import('@zanix/datamaster/core') // load cache core
  // deno-lint-ignore no-explicit-any
  await ProgramModule.connectors.get<any>(cache).clear() // reset data
  const context = contextMock()

  context.locals.session = { id: 'my-id', type: 'user', rateLimit: 3 }

  const guard = rateLimitGuard({ app: 'test', trustProxyHeader: true })

  await Promise.all([guard(context), guard(context)]) // support concurrency
  const { response } = await guard(context)
  assertFalse(response)

  const { response: withError } = await guard(context) // limit exceeded with 4 attempts
  const error = await withError?.json()
  assertEquals(error.name, 'HttpError')
  assertEquals(error.status.code, 'TOO_MANY_REQUESTS')
  assertEquals(error.meta.sessionType, 'user')
  assertEquals(error.meta.rateLimit, 3)
  assertEquals(error.meta.windowSeconds, 60)
  assertEquals(error.meta.sessionRef, 'my-id')
}

export const shouldLogError = async (cache: 'cache:local' | 'cache:redis') => {
  await import('@zanix/datamaster/core') // load cache core
  // deno-lint-ignore no-explicit-any
  await ProgramModule.connectors.get<any>(cache).clear() // reset data
  const context = contextMock()

  context.locals.session = { id: 'my-id', type: 'user', rateLimit: 2 }

  const guard = rateLimitGuard({ windowSeconds: 1, app: 'test', trustProxyHeader: true })

  const errorLog = stub(console, 'error')
  // On the Redis path, a window's rollover is decided by the KEY'S OWN TTL on the Redis server
  // (see `utils/lua.ts`) — a real, external clock that neither a real `setTimeout` wait nor a
  // locally-faked `Date.now()` reliably controls from here (the former is what made this test
  // flaky under load; the latter can't reach into Redis' own clock at all). Forcing the rollover
  // by deleting the keys directly makes every window boundary below deterministic instead of
  // racing a real TTL. The local-cache path never had that problem (its own TTL is enforced
  // in-process against the very same `Date.now()` the test's real wait advances), so it keeps the
  // original real wait.
  const rateLimitKey = `${CACHE_KEYS.rateLimit}:test-my-id`
  const wait = async (ms: number) => {
    if (cache !== 'cache:redis') {
      await new Promise((resolve) => setTimeout(resolve, ms))
      return
    }
    // Deletes ONLY the request-count key, simulating its `windowSeconds` TTL having elapsed.
    // `${rateLimitKey}:failed-attempts` is deliberately left alone: it carries a much longer TTL
    // (`windowSeconds * maxFaildedAttempts * 2`) precisely so it survives several window
    // rollovers and keeps accumulating — deleting it here would reset it every burst and the
    // `shouldLog` threshold could never be reached.
    const client = await ProgramModule.connectors.get<ZanixCacheConnector>(cache).getClient()
    // deno-lint-ignore no-explicit-any
    await (client as any).del(rateLimitKey)
  }

  await Promise.all([guard(context), guard(context), guard(context)])
  await wait(1000)
  await Promise.all([guard(context), guard(context), guard(context)])
  await wait(1000)
  await Promise.all([guard(context), guard(context), guard(context)])

  await Promise.all([guard(context), guard(context), guard(context)])
  await wait(1000)
  await Promise.all([guard(context), guard(context), guard(context)])

  assertEquals(errorLog.calls.length, 1)
  assertEquals(errorLog.calls[0].args[1], 'Too Many Requests')

  await wait(1000)
  await Promise.all([guard(context), guard(context), guard(context)])
  await wait(1000)
  await Promise.all([guard(context), guard(context), guard(context)])
  await wait(1000)
  await Promise.all([guard(context), guard(context), guard(context)])
  assertEquals(errorLog.calls.length, 2)
  assertEquals(errorLog.calls[1].args[1], 'Too Many Requests')

  errorLog.restore()
}

export const shouldResetLimit = async (
  cache: 'cache:local' | 'cache:redis',
) => {
  await import('@zanix/datamaster/core') // load cache core
  // deno-lint-ignore no-explicit-any
  await ProgramModule.connectors.get<any>(cache).clear() // reset data
  const context = contextMock()

  context.locals.session = { id: 'my-id', type: 'user', rateLimit: 3 }

  const guard = rateLimitGuard({ windowSeconds: 2, app: 'test', trustProxyHeader: true })

  await Promise.all([
    guard(context),
    guard(context),
    guard(context),
    guard(context),
  ])
  const { response } = await guard(context) //  limit exceeded with 4 attempts
  assert(response)

  await new Promise((resolve) => setTimeout(resolve, 2000))
  const { response: refreshed } = await guard(context) //  limit exceeded with 4 attempts
  assertFalse(refreshed)
}
