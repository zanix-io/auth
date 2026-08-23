import { assert, assertArrayIncludes, assertEquals, assertFalse } from '@std/assert'

import { jwtValidationGuard } from 'modules/middlewares/jwt-validation.guard.ts'
import { createJWT } from 'utils/jwt/create.ts'
import { generateRSAKeys } from '@zanix/helpers'
import { contextMock } from '../mocks.ts'

console.error = () => {}

Deno.test('jwtValidation shoud return an error wihout session', async () => {
  const context = contextMock()
  const { response } = await jwtValidationGuard()(context)
  const data = await response?.json()

  delete data.id

  assertEquals(data, {
    message: 'Authorization token is missing or invalid.',
    name: 'HttpError',
    meta: {
      authHeaderKey: 'Authorization',
      source: 'zanix',
      method: 'jwtValidationGuard',
      requestId: '',
    },
    status: { code: 'UNAUTHORIZED', value: 401 },
    cause: 'No JWT provided or Authorization header is not a Bearer token.',
  })

  assertEquals(response?.headers.get('x-znx-user-session-status'), 'failed')
  assert(response?.headers.get('x-znx-user-id')?.startsWith('anonymous-'))
  assertFalse(response?.headers.get('set-cookies'))

  context.req.headers.get = (name) => name === 'X-Znx-Cookies-Accepted' ? 'true' : null
  // check set cookies
  const { response: withCookies } = await jwtValidationGuard()(context)

  // deno-lint-ignore no-non-null-asserted-optional-chain no-non-null-assertion
  assertArrayIncludes(withCookies?.headers.getSetCookie()!, [
    'X-Znx-User-Session-Status=failed; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict',
    'X-Znx-Cookies-Accepted=true; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict',
    'X-Znx-App-Token=undefined; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict',
  ])
})

Deno.test('jwtValidation shoud return an error wihout token', async () => {
  const context = contextMock()

  context.req.headers.get = (name) => name === 'Authorization' ? 'Bearer ' : null
  const { response } = await jwtValidationGuard()(context)
  const data = await response?.json()

  delete data.id

  assertEquals(data, {
    message: 'Authorization token is missing or invalid.',
    name: 'HttpError',
    meta: {
      authHeaderKey: 'Authorization',
      source: 'zanix',
      method: 'jwtValidationGuard',
      requestId: '',
    },
    status: { code: 'UNAUTHORIZED', value: 401 },
    cause: 'No JWT provided or Authorization header is not a Bearer token.',
  })

  context.req.headers.get = (name) => name === 'Authorization' ? 'No Bearer ' : null
  const { response: noBearer } = await jwtValidationGuard()(context)
  const dataNoBearer = await noBearer?.json()

  assertEquals(
    dataNoBearer.message,
    'Authorization token is missing or invalid.',
  )
  assert(noBearer?.headers.has('x-znx-user-session-status'))
})

Deno.test('jwtValidation shoud return an error with invalid token', async () => {
  const context = contextMock()

  context.req.headers.get = (name) => name === 'Authorization' ? 'Bearer token' : null
  const { response } = await jwtValidationGuard()(context)
  const data = await response?.json()

  assertEquals(data.status.code, 'FORBIDDEN')
  assertEquals(data.name, 'HttpError')
  assertEquals(data.meta.source, 'zanix')
  assertEquals(data.meta.method, 'verifyJWT')
  assertEquals(data.cause.code, 'INVALID_TOKEN')
  assertEquals(response?.headers.get('x-znx-user-session-status'), 'failed')
})

Deno.test('jwtValidation shoud return an error without envars', async () => {
  Deno.env.delete('JWT_KEY')
  const context = contextMock()
  const token =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NjMyMjQ4NjksImp0aSI6IjQ2NWQyYjNlLTk0ZmUtNDA0ZS1hNTVjLTE0MDFhYzgxYzRkZSIsImlzcyI6Inphbml4LWF1dGgifQ.Dp8A98hYWXlu_EFHnTtkq25fT2b7ghPnKv23LhizjoI'
  context.req.headers.get = (name) => name === 'Authorization' ? `Bearer ${token}` : null

  const { response } = await jwtValidationGuard()(context)
  const data = await response?.json()

  assertEquals(data.status.code, 'INTERNAL_SERVER_ERROR')
  assertEquals(data.name, 'HttpError')
  assertEquals(data.meta.source, 'zanix')
  assertEquals(data.meta.method, 'getJWTKey')
  assertEquals(data.meta.keyType, 'user')
  assertEquals(data.meta.keyName, 'JWT_KEY')
  assertEquals(
    data.cause,
    'Missing required JWT key in environment variables: JWT_KEY.',
  )
  assertEquals(response?.headers.get('x-znx-user-session-status'), 'failed')
})

Deno.test('jwtValidation shoud return an error with invalid signature', async () => {
  const context = contextMock()
  const token = await createJWT({}, 'my-secret')

  Deno.env.set('JWT_KEY', 'secret')
  context.req.headers.get = (name) => name === 'Authorization' ? `Bearer ${token}` : null

  const { response } = await jwtValidationGuard()(context)
  const data = await response?.json()

  assertEquals(data.status.code, 'FORBIDDEN')
  assertEquals(data.name, 'HttpError')
  assertEquals(data.meta.source, 'zanix')
  assertEquals(data.meta.method, 'verifyJWT')
  assertEquals(data.cause.code, 'INVALID_TOKEN_SIGNATURE')
  assertEquals(response?.headers.get('x-znx-user-session-status'), 'failed')
})

Deno.test('jwtValidation shoud return an error due token expired', async () => {
  const context = contextMock()
  const token = await createJWT({}, 'my-secret', {
    expiration: '1s',
  })
  const realNow = Date.now

  Deno.env.set('JWT_KEY', 'my-secret')
  context.req.headers.get = (name) => name === 'Authorization' ? `Bearer ${token}` : null

  Date.now = () => realNow() + 2_000
  const { response } = await jwtValidationGuard()(context)
  Date.now = realNow

  const data = await response?.json()

  assertEquals(data.status.code, 'FORBIDDEN')
  assertEquals(data.name, 'HttpError')
  assertEquals(data.meta.source, 'zanix')
  assertEquals(data.meta.method, 'verifyJWT')
  assertEquals(data.cause.code, 'EXPIRED_TOKEN')
  assertEquals(response?.headers.get('x-znx-user-session-status'), 'failed')
})

Deno.test('jwtValidation shoud return an error due token issuer', async () => {
  const context = contextMock()
  const token = await createJWT({}, 'my-secret', { expiration: '1h' })
  Deno.env.set('JWT_KEY', 'my-secret')
  context.req.headers.get = (name) => name === 'Authorization' ? `Bearer ${token}` : null

  const { response } = await jwtValidationGuard({ iss: 'any-iss' })(context)
  const data = await response?.json()

  assertEquals(data.status.code, 'FORBIDDEN')
  assertEquals(data.name, 'HttpError')
  assertEquals(data.meta.source, 'zanix')
  assertEquals(data.meta.method, 'verifyJWT')
  assertEquals(data.cause.code, 'INVALID_TOKEN_ISSUER')
  assertEquals(data.cause.meta.expectedIssuer, 'any-iss')
  assertEquals(data.cause.meta.tokenIssuer, 'zanix-auth')
  assertEquals(response?.headers.get('x-znx-user-session-status'), 'failed')
})

Deno.test('jwtValidation shoud return an error due token permissions', async () => {
  const context = contextMock()
  const token = await createJWT({}, 'my-secret', { expiration: '1h' })
  Deno.env.set('JWT_KEY', 'my-secret')
  context.req.headers.get = (name) => name === 'Authorization' ? `Bearer ${token}` : null

  const { response } = await jwtValidationGuard({
    iss: 'zanix-auth',
    permissions: 'admin',
  })(
    context,
  )
  const data = await response?.json()

  assertEquals(data.status.code, 'FORBIDDEN')
  assertEquals(data.name, 'HttpError')
  assertEquals(data.meta.source, 'zanix')
  assertEquals(data.meta.method, 'verifyJWT')
  assertEquals(data.cause.code, 'INVALID_TOKEN_PERMISSIONS')
  assertEquals(
    data.cause.cause,
    'Insufficient permissions. Requires any of [admin].',
  )
  assertEquals(data.cause.meta.expectedAudience, 'admin')
  assertEquals(response?.headers.get('x-znx-user-session-status'), 'failed')
})

Deno.test('jwtValidation shoud return an error due token subject', async () => {
  const context = contextMock()
  const token = await createJWT({ sub: 'my-id', aud: 'admin' }, 'my-secret', { expiration: '1h' })
  Deno.env.set('JWT_KEY', 'my-secret')
  context.req.headers.get = (name) =>
    name === 'Authorization' ? `Bearer ${token}` : name === 'X-Znx-User-Id' ? 'user-id' : null
  context.cookies = { 'X-Znx-User-Id': 'user-cookie' }

  const { response } = await jwtValidationGuard({
    iss: 'zanix-auth',
    permissions: ['admin', 'superadmin'],
  })(
    context,
  )
  const data = await response?.json()

  assertEquals(data.status.code, 'FORBIDDEN')
  assertEquals(data.name, 'HttpError')
  assertEquals(data.meta.source, 'zanix')
  assertEquals(data.meta.method, 'verifyJWT')
  assertEquals(data.cause.code, 'INVALID_TOKEN_SUBJECT')
  assertEquals(data.cause.meta.expectedSubject, 'user-cookie')
  assertEquals(data.cause.meta.tokenSubject, 'my-id')
  assertEquals(response?.headers.get('x-znx-user-session-status'), 'failed')
})

Deno.test('jwtValidation shoud return an error with api session', async () => {
  const context = contextMock()
  const { response } = await jwtValidationGuard({ type: 'api' })(context)
  const data = await response?.json()

  assertEquals(
    data.message,
    'X-Znx-Authorization token is missing or invalid.',
  )
  assertEquals(response?.headers.get('x-znx-api-session-status'), 'failed')
})

// Stubs the blocklist's cache/kv lookups (unrelated to the guard's own type-selection logic) so
// these tests can reach a genuine success without wiring up real DI providers — covers both the
// local and the Redis-backed path (`checkTokenBlockList` branches on `REDIS_URI`, which another
// test file running earlier in the same process may have left set).
const stubBlockListLookup = (context: ReturnType<typeof contextMock>) => {
  const fakeCache = {
    local: new Map(),
    getCachedOrFetch: () => Promise.resolve(false),
  }
  context.providers.get = () => fakeCache as never
  context.connectors.get = () => ({ get: () => undefined } as never)
}

Deno.test('jwtValidation type array: picks user when only Authorization is sent', async () => {
  const context = contextMock()
  stubBlockListLookup(context)
  const token = await createJWT({}, 'my-secret', { expiration: '1h' })
  Deno.env.set('JWT_KEY', 'my-secret')
  context.req.headers.get = (name) => name === 'Authorization' ? `Bearer ${token}` : null

  const { response } = await jwtValidationGuard({
    type: ['api', 'user'],
    rateLimit: false,
  })(
    context,
  )

  assertEquals(response, undefined)
  assertEquals(context.locals.session?.type, 'user')

  Deno.env.delete('JWT_KEY')
})

Deno.test('jwtValidation type array: picks api when only X-Znx-Authorization is sent', async () => {
  const context = contextMock()
  stubBlockListLookup(context)
  const { privateKey, publicKey } = await generateRSAKeys()
  const token = await createJWT({}, privateKey, { algorithm: 'RS256', expiration: '1h' })
  Deno.env.set('JWK_PUB', btoa(publicKey))
  context.req.headers.get = (name) => name === 'X-Znx-Authorization' ? `Bearer ${token}` : null

  const { response } = await jwtValidationGuard({
    type: ['api', 'user'],
    rateLimit: false,
  })(
    context,
  )

  assertEquals(response, undefined)
  assertEquals(context.locals.session?.type, 'api')

  Deno.env.delete('JWK_PUB')
})

Deno.test('jwtValidation type array: reports first type when no header is sent', async () => {
  const context = contextMock()

  const { response: apiFirst } = await jwtValidationGuard({
    type: ['api', 'user'],
  })(context)
  assertEquals(
    (await apiFirst?.json()).message,
    'X-Znx-Authorization token is missing or invalid.',
  )

  const { response: userFirst } = await jwtValidationGuard({
    type: ['user', 'api'],
  })(context)
  assertEquals(
    (await userFirst?.json()).message,
    'Authorization token is missing or invalid.',
  )
})
