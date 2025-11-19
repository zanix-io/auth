import { assert, assertEquals, assertFalse } from '@std/assert'

import { sessionHeadersInterceptor } from 'modules/middlewares/headers.interceptor.ts'
import { rateLimitGuard } from 'modules/middlewares/rate-limit.guard.ts'
import { contextMock } from '../../mocks.ts'
import { RATE_LIMIT_HEADERS } from 'utils/constants.ts'
import { ProgramModule } from '@zanix/server'
import { stub } from '@std/testing/mock'

export const addValidHeaders = async (cache: 'cache:local' | 'cache:redis') => {
  await import('@zanix/datamaster') // load cache core
  // deno-lint-ignore no-explicit-any
  await ProgramModule.getConnectors().get<any>(cache).clear() // reset data
  const context = contextMock()

  const guard = rateLimitGuard()
  const { response, headers = {} } = await guard(context)
  assertFalse(response)
  assertEquals(headers[RATE_LIMIT_HEADERS.limitHeader], '100')
  assertEquals(headers[RATE_LIMIT_HEADERS.remainingHeader], '99')
  assertEquals(Number(headers[RATE_LIMIT_HEADERS.resetHeader]), 60)
}

export const addValidSessionHeaders = async () => {
  await import('@zanix/datamaster') // load cache core
  const context = contextMock()

  const guard = rateLimitGuard()
  await guard(context)
  const response = new Response()
  await sessionHeadersInterceptor()(context, response)

  assert(context.locals.session?.id.startsWith('anonymous-'))
  assertEquals(context.locals.session?.type, 'anonymous')
  assert(response.headers.get('X-Znx-User-Id')?.startsWith('anonymous-'))
  assertEquals(response.headers.get('X-Znx-User-Session-Status'), 'unconfirmed')
}

export const shouldNotAddSessionHeaders = async () => {
  await import('@zanix/datamaster') // load cache core
  const context = contextMock()

  const guard = rateLimitGuard()
  context.req.headers.get = (name) => name === 'X-Znx-User-Id' ? 'my-user' : null
  const { headers: baseHeaders = {} } = await guard(context)

  assert(context.locals.session?.id.startsWith('anonymous-'))
  assertEquals(context.locals.session?.type, 'anonymous')
  assertFalse(baseHeaders['X-Znx-User-Id'])
  assertFalse(baseHeaders['X-Znx-User-Session-Status'])
}

export const shouldSupportConcurrency = async (cache: 'cache:local' | 'cache:redis') => {
  await import('@zanix/datamaster') // load cache core
  // deno-lint-ignore no-explicit-any
  await ProgramModule.getConnectors().get<any>(cache).clear() // reset data
  const context = contextMock()

  const guard = rateLimitGuard()

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
  const reset = Number(headers[RATE_LIMIT_HEADERS.resetHeader])
  assert(reset === 58 || reset === 59)
}

export const shouldFailDueLimitAnonymous = async (cache: 'cache:local' | 'cache:redis') => {
  await import('@zanix/datamaster') // load cache core
  // deno-lint-ignore no-explicit-any
  await ProgramModule.getConnectors().get<any>(cache).clear() // reset data
  const context = contextMock()

  const guard = rateLimitGuard({ anonymousLimit: 2 })

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
  assertEquals(checkRetry?.headers.get('retry-after'), '57')
}

export const shouldFailDueLimit = async (cache: 'cache:local' | 'cache:redis') => {
  await import('@zanix/datamaster') // load cache core
  // deno-lint-ignore no-explicit-any
  await ProgramModule.getConnectors().get<any>(cache).clear() // reset data
  const context = contextMock()

  context.locals.session = { id: 'my-id', type: 'user', rateLimit: 3 }

  const guard = rateLimitGuard()

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
  await import('@zanix/datamaster') // load cache core
  // deno-lint-ignore no-explicit-any
  await ProgramModule.getConnectors().get<any>(cache).clear() // reset data
  const context = contextMock()

  context.locals.session = { id: 'my-id', type: 'user', rateLimit: 2 }

  const guard = rateLimitGuard({ windowSeconds: 1 })

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
  await import('@zanix/datamaster') // load cache core
  // deno-lint-ignore no-explicit-any
  await ProgramModule.getConnectors().get<any>(cache).clear() // reset data
  const context = contextMock()

  context.locals.session = { id: 'my-id', type: 'user', rateLimit: 3 }

  const guard = rateLimitGuard({ windowSeconds: 2 })

  await Promise.all([guard(context), guard(context), guard(context), guard(context)])
  const { response } = await guard(context) //  limit exceeded with 4 attempts
  assert(response)

  await new Promise((resolve) => setTimeout(resolve, 2000))
  const { response: refreshed } = await guard(context) //  limit exceeded with 4 attempts
  assertFalse(refreshed)
}
