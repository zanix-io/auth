import {
  GENERAL_HEADERS,
  ProgramModule,
  SESSION_HEADERS,
  type ZanixCacheProvider,
  type ZanixKVConnector,
} from '@zanix/server'

import { jwtValidationGuard } from 'modules/middlewares/jwt-validation.guard.ts'
import { createJWT } from 'utils/jwt/create.ts'
import { contextMock } from '../../mocks.ts'
import { addTokenToBlockList } from 'utils/sessions/block-list.ts'
import { assert, assertArrayIncludes, assertEquals, assertFalse } from '@std/assert'
import { isUUID } from '@zanix/validator'
import { generateRSAKeys } from '@zanix/helpers'
import { sessionHeadersInterceptor } from 'modules/middlewares/headers.interceptor.ts'

console.warn = () => {}
console.info = () => {}

const initialize = async () => {
  Deno.env.set('REDIS_URI', 'redis://localhost:6379')
  Deno.env.set('JWT_KEY', 'my-secret')

  await import('@zanix/datamaster/core') // load cache core

  // deno-lint-ignore no-explicit-any
  await ProgramModule.connectors.get<any>('cache:redis').clear() // reset data

  const context = contextMock()

  return context
}

Deno.test({
  sanitizeOps: false,
  sanitizeResources: false,
  name: 'jwtValidation should return an error due block listed token',
  fn: async () => {
    const context = await initialize()

    const token = await createJWT({ exp: Math.floor(Date.now() / 1000) + 1 }, 'my-secret')

    context.req.headers.get = (name) => name === 'Authorization' ? `Bearer ${token}` : null

    const localDb = ProgramModule.connectors.get<ZanixKVConnector>('kvLocal')
    const cache = ProgramModule.providers.get<ZanixCacheProvider>('cache')
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
    // Simulates `@zanix/server`'s `contextSettingPipe`, which always promotes `locals.session` to
    // the frozen `ctx.session` between the guard phase and any interceptor.
    context.session = context.locals.session as never

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

    context.cookies = {
      [SESSION_HEADERS.user.token]: 'token',
      [GENERAL_HEADERS.cookiesAcceptedHeader]: 'true',
    }
    const { response } = await jwtValidationGuard()(context)
    assert(response)

    assertArrayIncludes(response.headers.getSetCookie(), [
      'X-Znx-User-Session-Status=failed; Max-Age=0; Path=/; HttpOnly; SameSite=Strict',
      'X-Znx-Cookies-Accepted=true; Max-Age=0; Path=/; HttpOnly; SameSite=Strict',
      'X-Znx-App-Token=undefined; Max-Age=0; Path=/; HttpOnly; SameSite=Strict',
    ])

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
    context.session = context.locals.session as never // see the earlier test's own comment

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
    context.session = context.locals.session as never // see the earlier test's own comment

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
  name: 'jwtValidation should not overwrite the refresh-token cookie with the access token',
  fn: async () => {
    const context = await initialize()

    const realRefreshToken = 'this-is-the-real-refresh-token-issued-at-login'
    // Simulates a session already carrying the real refresh token, as generateSessionTokens
    // leaves it right after login.
    context.locals.session = {
      id: 'session-id',
      type: 'user',
      rateLimit: 100,
      token: realRefreshToken,
    }

    // A real access token always has an `exp` claim (set by createAccessToken), which is what
    // makes `maxAge` a real positive number in getSessionHeaders instead of the `0` default.
    const accessToken = await createJWT({}, 'my-secret', { expiration: 3600 })
    context.req.headers.get = (name) =>
      name === 'Authorization'
        ? `Bearer ${accessToken}`
        : name === 'X-Znx-Cookies-Accepted'
        ? 'true'
        : null

    const { response } = await jwtValidationGuard({ rateLimit: false })(context)
    assertFalse(response)
    context.session = context.locals.session as never // see the earlier test's own comment

    const responseSession = new Response()
    await sessionHeadersInterceptor()(context, responseSession)

    const setCookies = responseSession.headers.getSetCookie()
    assert(!setCookies.some((cookie) => cookie.startsWith('X-Znx-App-Token=')))
  },
})
