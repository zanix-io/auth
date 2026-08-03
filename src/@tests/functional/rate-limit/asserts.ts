// deno-coverage-ignore-file

import { assert, assertAlmostEquals, assertEquals, assertFalse } from '@std/assert'

import { sessionHeadersInterceptor } from 'modules/middlewares/headers.interceptor.ts'
import { rateLimitGuard } from 'modules/middlewares/rate-limit.guard.ts'
import { contextMock } from '../../mocks.ts'
import { ProgramModule, RATE_LIMIT_HEADERS, type ZanixCacheConnector } from '@zanix/server'
import { stub } from '@std/testing/mock'

export const addValidHeaders = async (cache: 'cache:local' | 'cache:redis') => {
  await import('@zanix/datamaster/core') // load cache core
  await (ProgramModule.connectors.get<ZanixCacheConnector>(cache)).clear() // reset data
  const context = contextMock()

  const guard = rateLimitGuard({ app: 'test' })
  const { response, headers = {} } = await guard(context)
  assertFalse(response)
  assertEquals(headers[RATE_LIMIT_HEADERS.limitHeader], '100')
  assertEquals(headers[RATE_LIMIT_HEADERS.remainingHeader], '99')
  assertAlmostEquals(Number(headers[RATE_LIMIT_HEADERS.resetHeader]), 60, 1)
}

export const addValidSessionHeaders = async () => {
  await import('@zanix/datamaster/core') // load cache core
  const context = contextMock()

  const guard = rateLimitGuard({ app: 'test' })
  await guard(context)
  // Simulates `@zanix/server`'s `contextSettingPipe`, which always promotes `locals.session` to
  // the frozen `ctx.session` between the guard phase and any interceptor.
  context.session = context.locals.session as never
  const response = new Response()
  await sessionHeadersInterceptor()(context, response)

  assert(response.headers.get('X-Znx-User-Id')?.startsWith('anonymous-'))
  assertEquals(response.headers.get('X-Znx-User-Session-Status'), 'unconfirmed')
}

export const shouldNotAddSessionHeaders = async () => {
  await import('@zanix/datamaster/core') // load cache core
  const context = contextMock()

  const guard = rateLimitGuard({ app: 'test' })
  context.req.headers.get = (name) => name === 'X-Znx-User-Id' ? 'my-user' : null
  const { headers: baseHeaders = {} } = await guard(context)

  assert(context.locals.session?.id.startsWith('anonymous-'))
  assertEquals(context.locals.session?.type, 'anonymous')
  assertFalse(baseHeaders['X-Znx-User-Id'])
  assertFalse(baseHeaders['X-Znx-User-Session-Status'])
}

export const shouldSupportConcurrency = async (cache: 'cache:local' | 'cache:redis') => {
  await import('@zanix/datamaster/core') // load cache core
  await (ProgramModule.connectors.get<ZanixCacheConnector>(cache)).clear() // reset data
  const context = contextMock()

  const guard = rateLimitGuard({ app: 'test' })

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

export const shouldFailDueLimitAnonymous = async (cache: 'cache:local' | 'cache:redis') => {
  await import('@zanix/datamaster/core') // load cache core
  // deno-lint-ignore no-explicit-any
  await ProgramModule.connectors.get<any>(cache).clear() // reset data
  const context = contextMock()

  const guard = rateLimitGuard({ anonymousLimit: 2, app: 'test' })

  await Promise.all([guard(context), guard(context)]) // support concurrency
  await new Promise((resolve) => setTimeout(resolve, 1000))
  const { response } = await guard(context)

  const error = await response?.json()
  assertEquals(error.name, 'HttpError')
  assertEquals(error.status.code, 'TOO_MANY_REQUESTS')
  assertEquals(error.meta.sessionType, 'anonymous')
  assertEquals(error.meta.rateLimit, 2)
  assertEquals(error.meta.windowSeconds, 60)
  assert(error.meta.sessionId.startsWith('anonymous-'))

  await new Promise((resolve) => setTimeout(resolve, 2000))
  const { response: checkRetry } = await guard(context)
  const retryAfter = Number(checkRetry?.headers.get('retry-after'))
  assert(retryAfter < 59 && retryAfter > 55)
}

export const shouldFailDueLimit = async (cache: 'cache:local' | 'cache:redis') => {
  await import('@zanix/datamaster/core') // load cache core
  // deno-lint-ignore no-explicit-any
  await ProgramModule.connectors.get<any>(cache).clear() // reset data
  const context = contextMock()

  context.locals.session = { id: 'my-id', type: 'user', rateLimit: 3 }

  const guard = rateLimitGuard({ app: 'test' })

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
  assertEquals(error.meta.sessionId, 'my-id')
}

export const shouldLogError = async (cache: 'cache:local' | 'cache:redis') => {
  await import('@zanix/datamaster/core') // load cache core
  // deno-lint-ignore no-explicit-any
  await ProgramModule.connectors.get<any>(cache).clear() // reset data
  const context = contextMock()

  context.locals.session = { id: 'my-id', type: 'user', rateLimit: 2 }

  const guard = rateLimitGuard({ windowSeconds: 1, app: 'test' })

  const errorLog = stub(console, 'error')

  await Promise.all([guard(context), guard(context), guard(context)])
  await new Promise((resolve) => setTimeout(resolve, 1000))
  await Promise.all([guard(context), guard(context), guard(context)])
  await new Promise((resolve) => setTimeout(resolve, 1000))
  await Promise.all([guard(context), guard(context), guard(context)])

  await Promise.all([guard(context), guard(context), guard(context)])
  await new Promise((resolve) => setTimeout(resolve, 1000))
  await Promise.all([guard(context), guard(context), guard(context)])

  assertEquals(errorLog.calls.length, 1)
  assertEquals(errorLog.calls[0].args[1], 'Too Many Requests')

  await new Promise((resolve) => setTimeout(resolve, 1000))
  await Promise.all([guard(context), guard(context), guard(context)])
  await new Promise((resolve) => setTimeout(resolve, 1000))
  await Promise.all([guard(context), guard(context), guard(context)])
  await new Promise((resolve) => setTimeout(resolve, 1000))
  await Promise.all([guard(context), guard(context), guard(context)])
  assertEquals(errorLog.calls.length, 2)
  assertEquals(errorLog.calls[1].args[1], 'Too Many Requests')

  errorLog.restore()
}

export const shouldResetLimit = async (cache: 'cache:local' | 'cache:redis') => {
  await import('@zanix/datamaster/core') // load cache core
  // deno-lint-ignore no-explicit-any
  await ProgramModule.connectors.get<any>(cache).clear() // reset data
  const context = contextMock()

  context.locals.session = { id: 'my-id', type: 'user', rateLimit: 3 }

  const guard = rateLimitGuard({ windowSeconds: 2, app: 'test' })

  await Promise.all([guard(context), guard(context), guard(context), guard(context)])
  const { response } = await guard(context) //  limit exceeded with 4 attempts
  assert(response)

  await new Promise((resolve) => setTimeout(resolve, 2000))
  const { response: refreshed } = await guard(context) //  limit exceeded with 4 attempts
  assertFalse(refreshed)
}
