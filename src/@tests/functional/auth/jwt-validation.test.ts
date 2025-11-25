import { ProgramModule, type ZanixCacheProvider, type ZanixKVConnector } from '@zanix/server'

import { jwtValidationGuard } from 'modules/middlewares/jwt-validation.guard.ts'
import { createJWT } from 'utils/jwt/create.ts'
import { contextMock } from '../../mocks.ts'
import { addTokenToBlockList } from 'utils/sessions/block-list.ts'
import { assert, assertEquals, assertFalse } from '@std/assert'
import { isUUID } from '@zanix/validator'
import { generateRSAKeys } from '@zanix/helpers'
import { sessionHeadersInterceptor } from 'modules/middlewares/headers.interceptor.ts'

console.warn = () => {}
console.info = () => {}

const initialize = async () => {
  Deno.env.set('REDIS_URI', 'redis://localhost:6379')
  Deno.env.set('JWT_KEY', 'my-secret')

  await import('@zanix/datamaster') // load cache core

  // deno-lint-ignore no-explicit-any
  await ProgramModule.getConnectors().get<any>('cache:redis').clear() // reset data

  const context = contextMock()

  return context
}

Deno.test({
  sanitizeOps: false,
  sanitizeResources: false,
  name: 'jwtValidation should return an error due block listed token',
  fn: async () => {
    const context = await initialize()

    const token = await createJWT({}, 'my-secret')

    context.req.headers.get = (name) => name === 'Authorization' ? `Bearer ${token}` : null

    const localDb = ProgramModule.getConnectors().get<ZanixKVConnector>('kvLocal')
    const cache = ProgramModule.getProviders().get<ZanixCacheProvider>('cache')
    await addTokenToBlockList(token, cache, localDb)

    const { response } = await jwtValidationGuard()(context)
    const error = await response?.json()

    assertEquals(error.status.code, 'FORBIDDEN')
    assertEquals(error.cause.name, 'PermissionDenied')
    assertEquals(error.cause.message, 'The provided token has been revoked or is blocklisted.')
  },
})

Deno.test({
  sanitizeOps: false,
  sanitizeResources: false,
  name: 'jwtValidation should avoid rate limit and return OK',
  fn: async () => {
    const context = await initialize()

    const token = await createJWT({}, 'my-secret')
    context.req.headers.get = (name) => name === 'Authorization' ? `Bearer ${token}` : null

    const { response } = await jwtValidationGuard({ rateLimit: false })(context)

    assertFalse(response)

    const responseSession = new Response()
    await sessionHeadersInterceptor()(context, responseSession)
    assertEquals(responseSession.headers.get('X-Znx-User-Session-Status'), 'active')
    // deno-lint-ignore no-non-null-assertion
    assert(isUUID(responseSession.headers.get('X-Znx-User-Id')!))
  },
})

Deno.test({
  sanitizeOps: false,
  sanitizeResources: false,
  name: 'jwtValidation should fail due rate limit',
  fn: async () => {
    const context = await initialize()

    const token = await createJWT({}, 'my-secret')
    context.req.headers.get = (name) => name === 'Authorization' ? `Bearer ${token}` : null

    const { response } = await jwtValidationGuard()(context)
    assert(response)

    const error = await response.json()
    assertEquals(error.cause.meta.reason, 'No session found with a valid rate limit configuration.')
  },
})

Deno.test({
  sanitizeOps: false,
  sanitizeResources: false,
  name: 'jwtValidation should fail due rate limit and return correct session headers',
  fn: async () => {
    const context = await initialize()

    const token = await createJWT({ rateLimit: 2, sub: 'my-user-id' }, 'my-secret')
    context.req.headers.get = (name) =>
      name === 'Authorization'
        ? `Bearer ${token}`
        : name === 'X-Znx-User-Id'
        ? 'my-user-id'
        : name === 'X-Znx-User-Session-Status'
        ? 'active'
        : null

    await Promise.all([jwtValidationGuard()(context), jwtValidationGuard()(context)])

    const { response } = await jwtValidationGuard()(context)
    assert(response)

    const error = await response.json()

    assertEquals(error.status.code, 'TOO_MANY_REQUESTS')
    assertEquals(response.headers.get('x-znx-user-id'), 'my-user-id')
    assertEquals(response.headers.get('x-znx-user-session-status'), 'blocked')
    assert(response.headers.has('retry-after'))
  },
})

Deno.test({
  sanitizeOps: false,
  sanitizeResources: false,
  name: 'jwtValidation should return OK for API type',
  fn: async () => {
    const context = await initialize()

    const { publicKey, privateKey } = await generateRSAKeys()

    const token = await createJWT({}, privateKey, { algorithm: 'RS256' })

    context.req.headers.get = (name) => name === 'X-Znx-Authorization' ? `Bearer ${token}` : null

    Deno.env.set('JWK_PUB', btoa(publicKey))
    const { response } = await jwtValidationGuard({ rateLimit: false, type: 'api' })(
      context,
    )
    assertFalse(response)

    const responseSession = new Response()
    await sessionHeadersInterceptor()(context, responseSession)

    assertEquals(responseSession.headers.get('X-Znx-Api-Session-Status'), 'active')
    // deno-lint-ignore no-non-null-assertion
    assert(isUUID(responseSession.headers.get('X-Znx-Api-Id')!))
  },
})

Deno.test({
  sanitizeOps: false,
  sanitizeResources: false,
  name: 'jwtValidation should return OK for custom JWT type',
  fn: async () => {
    const context = await initialize()

    const token = await createJWT({}, 'my-secret', { algorithm: 'HS512' })

    context.req.headers.get = (name) => name === 'Authorization' ? `Bearer ${token}` : null

    const { response } = await jwtValidationGuard({
      rateLimit: false,
      algorithm: 'HS512',
    })(
      context,
    )
    assertFalse(response)

    const responseSession = new Response()
    await sessionHeadersInterceptor()(context, responseSession)

    assertEquals(responseSession.headers.get('X-Znx-User-Session-Status'), 'active')
    // deno-lint-ignore no-non-null-assertion
    assert(isUUID(responseSession.headers.get('X-Znx-User-Id')!))
  },
})
