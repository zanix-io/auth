// deno-lint-ignore-file no-explicit-any
import { assert, assertEquals, assertRejects } from '@std/assert'
import { HttpError, PermissionDenied } from '@zanix/errors'
import { refreshSessionTokens } from 'utils/sessions/refresh.ts'
import { createAppToken, generateSessionTokens } from 'utils/sessions/create.ts'

console.warn = () => {}

function createCtx() {
  return { locals: {}, cookies: {} } as any
}

Deno.test('refreshSessionTokens throws when there is no refresh token available', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  await assertRejects(
    () => refreshSessionTokens(createCtx(), undefined),
    HttpError,
  )

  Deno.env.delete('JWT_KEY')
})

Deno.test('refreshSessionTokens reads the refresh token from cookies when omitted', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  const { refreshToken } = await generateSessionTokens(createCtx(), {
    subject: 'user@example.com',
  })

  const ctx = { locals: {}, cookies: { 'X-Znx-App-Token': refreshToken } } as any
  const result = await refreshSessionTokens(ctx, undefined)

  assert(result.accessToken)
  assert(result.refreshToken)

  Deno.env.delete('JWT_KEY')
})

Deno.test('refreshSessionTokens throws FORBIDDEN for a non-refresh token', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  const accessOnlyToken = await createAppToken({
    subject: 'user@example.com',
    type: 'user',
    expiration: '1h',
  })

  await assertRejects(
    () => refreshSessionTokens(createCtx(), accessOnlyToken),
    HttpError,
  )

  Deno.env.delete('JWT_KEY')
})

Deno.test('refreshSessionTokens returns new tokens for a valid refresh token', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  const { refreshToken } = await generateSessionTokens(createCtx(), {
    subject: 'user@example.com',
  })

  const result = await refreshSessionTokens(createCtx(), refreshToken)

  assert(result.accessToken)
  assert(result.refreshToken)
  assertEquals(result.oldToken, refreshToken)
  assert(result.payload)

  Deno.env.delete('JWT_KEY')
})

Deno.test('refreshSessionTokens throws PermissionDenied for a blocklisted token', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  const { refreshToken } = await generateSessionTokens(createCtx(), {
    subject: 'user@example.com',
  })

  const cache = { local: { get: () => true } } as any
  const kvDb = { get: () => undefined } as any

  await assertRejects(
    () => refreshSessionTokens(createCtx(), refreshToken, { cache, kvDb }),
    PermissionDenied,
  )

  Deno.env.delete('JWT_KEY')
})

Deno.test('refreshSessionTokens succeeds when the token is not in the block list', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  const { refreshToken } = await generateSessionTokens(createCtx(), {
    subject: 'user@example.com',
  })

  const cache = { local: { get: () => undefined } } as any
  const kvDb = { get: () => undefined } as any

  const result = await refreshSessionTokens(createCtx(), refreshToken, { cache, kvDb })

  assert(result.accessToken)

  Deno.env.delete('JWT_KEY')
})
