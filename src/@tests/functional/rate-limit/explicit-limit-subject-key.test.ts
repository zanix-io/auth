import { assert, assertEquals, assertFalse } from '@std/assert'
import { ProgramModule, RATE_LIMIT_HEADERS, type ZanixCacheConnector } from '@zanix/server'

import { rateLimitGuard } from 'modules/middlewares/rate-limit.guard.ts'
import { contextMock } from '../../mocks.ts'

const reset = async () => {
  Deno.env.delete('REDIS_URI')
  await import('@zanix/datamaster/core') // load cache core
  await ProgramModule.connectors.get<ZanixCacheConnector>('cache:local').clear()
}

// deno-lint-ignore no-explicit-any
const contextFor = (session: any) => {
  const context = contextMock()
  context.locals.session = session
  return context
}

const options = { app: 'test', anonymousLimit: false, trustProxyHeader: true } as const

Deno.test('rateLimitGuard `limit` replaces the limit of the session plan', async () => {
  await reset()
  const guard = rateLimitGuard({ ...options, limit: 2 })
  const context = contextFor({ id: 'jti-1', type: 'user', rateLimit: 100 })

  const first = await guard(context)
  assertFalse(first.response)
  assertEquals(first.headers?.[RATE_LIMIT_HEADERS.limitHeader], '2')
  assertEquals(first.headers?.[RATE_LIMIT_HEADERS.remainingHeader], '1')
  assertFalse((await guard(context)).response)

  const exceeded = await guard(context)
  assert(exceeded.response)
  assertEquals(exceeded.response.status, 429)
})

Deno.test('rateLimitGuard `limit` limits a session that carries no rateLimit', async () => {
  await reset()
  const guard = rateLimitGuard({ ...options, limit: 1 })
  const context = contextFor({ id: 'jti-1', type: 'user' })

  assertFalse((await guard(context)).response)
  assert((await guard(context)).response)
})

Deno.test('rateLimitGuard `limit` never applies to anonymous callers', async () => {
  await reset()
  const guard = rateLimitGuard({
    app: 'test',
    trustProxyHeader: false,
    anonymousLimit: 3,
    limit: 1,
  })
  const context = contextMock()

  const results = await Promise.all([guard(context), guard(context), guard(context)])
  for (const { response } of results) assertFalse(response)
  assert((await guard(context)).response)
})

Deno.test('rateLimitGuard key "subject" shares one bucket across the tokens of a subject', async () => {
  await reset()
  const guard = rateLimitGuard({ ...options, limit: 2, key: 'subject' })
  const token = (id: string) => contextFor({ id, type: 'user', rateLimit: 100, subject: 'ana' })

  assertFalse((await guard(token('jti-1'))).response)
  assertFalse((await guard(token('jti-2'))).response)
  // A third, brand new token of the same subject finds the bucket already full.
  assert((await guard(token('jti-3'))).response)
})

Deno.test('rateLimitGuard key "subject" keeps a bucket per subject', async () => {
  await reset()
  const guard = rateLimitGuard({ ...options, limit: 1, key: 'subject' })

  assertFalse((await guard(contextFor({ id: 'a', type: 'user', subject: 'ana' }))).response)
  assert((await guard(contextFor({ id: 'b', type: 'user', subject: 'ana' }))).response)
  assertFalse((await guard(contextFor({ id: 'c', type: 'user', subject: 'bob' }))).response)
})

Deno.test('rateLimitGuard key "subject" falls back to the session id without a subject', async () => {
  await reset()
  const guard = rateLimitGuard({ ...options, limit: 1, key: 'subject' })

  assertFalse((await guard(contextFor({ id: 'a', type: 'user' }))).response)
  assert((await guard(contextFor({ id: 'a', type: 'user' }))).response)
  assertFalse((await guard(contextFor({ id: 'b', type: 'user' }))).response)
})

Deno.test('rateLimitGuard keys by session id by default, even when a subject exists', async () => {
  await reset()
  const guard = rateLimitGuard({ ...options, limit: 1 })

  assertFalse((await guard(contextFor({ id: 'a', type: 'user', subject: 'ana' }))).response)
  assertFalse((await guard(contextFor({ id: 'b', type: 'user', subject: 'ana' }))).response)
  assert((await guard(contextFor({ id: 'a', type: 'user', subject: 'ana' }))).response)
})

Deno.test('rateLimitGuard without `limit` still takes the limit from session.rateLimit', async () => {
  await reset()
  const guard = rateLimitGuard({ ...options, key: 'subject' })
  const token = (id: string) => contextFor({ id, type: 'user', rateLimit: 2, subject: 'ana' })

  assertFalse((await guard(token('a'))).response)
  assertFalse((await guard(token('b'))).response)
  assert((await guard(token('c'))).response)
})

Deno.test('rateLimitGuard subject bucket expires with its window', async () => {
  await reset()
  const guard = rateLimitGuard({ ...options, limit: 1, key: 'subject', windowSeconds: 1 })
  const token = (id: string) => contextFor({ id, type: 'user', subject: 'ana' })

  assertFalse((await guard(token('a'))).response)
  assert((await guard(token('b'))).response)

  await new Promise((resolve) => setTimeout(resolve, 1200))
  assertFalse((await guard(token('c'))).response)
})
