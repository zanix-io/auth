// deno-lint-ignore-file no-explicit-any
import { assert, assertEquals, assertStringIncludes } from '@std/assert'
import {
  attachRotatedSessionToError,
  recoverRotatedSessionCookie,
} from 'utils/sessions/rotation-recovery.ts'
import { generateSessionTokens } from 'utils/sessions/create.ts'

function createCtx() {
  return { locals: {}, cookies: {} } as any
}

Deno.test('attachRotatedSessionToError: recoverRotatedSessionCookie() rebuilds the exact refresh-token cookie a real rotation just issued', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  const ctx = createCtx()
  const { refreshToken } = await generateSessionTokens(ctx, { subject: 'operator@example.com' })

  const error = attachRotatedSessionToError(new Error('boom'), ctx)
  const response = await recoverRotatedSessionCookie()(error)

  assert(response instanceof Response, 'expected a real Response, not undefined')
  const setCookies = response.headers.getSetCookie()
  const appToken = setCookies.find((c) => c.startsWith('X-Znx-App-Token='))
  assert(appToken, `expected an X-Znx-App-Token cookie among: ${setCookies.join(' | ')}`)
  assertStringIncludes(appToken, `X-Znx-App-Token=${refreshToken}`)
  assertStringIncludes(appToken, 'HttpOnly')
  assertStringIncludes(appToken, 'Secure')
  assertStringIncludes(appToken, 'SameSite=Strict')

  Deno.env.delete('JWT_KEY')
})

Deno.test('attachRotatedSessionToError: a no-op on an error thrown before any rotation ever happened', async () => {
  const ctx = createCtx() // never rotated — locals.session stays undefined
  const error = attachRotatedSessionToError(new Error('boom'), ctx)

  const response = await recoverRotatedSessionCookie()(error)

  assertEquals(response, undefined)
})

Deno.test(
  'attachRotatedSessionToError: recoverRotatedSessionCookie() declines an unrelated error, ' +
    'composable alongside another OnErrorHandler',
  async () => {
    const response = await recoverRotatedSessionCookie()(new Error('never went through this guard'))

    assertEquals(response, undefined)
  },
)

Deno.test('attachRotatedSessionToError: the raw token never leaks into the response BODY a real client sees', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  const ctx = createCtx()
  const { refreshToken } = await generateSessionTokens(ctx, { subject: 'operator@example.com' })

  const error = attachRotatedSessionToError(new Error('boom'), ctx)
  const response = await recoverRotatedSessionCookie()(error)
  const body = await (response as Response).text()

  assert(
    !body.includes(refreshToken),
    `the response body must never carry the raw refresh token: ${body}`,
  )
  // Sanity check the marker itself really is non-enumerable — proves the guarantee above holds
  // BECAUSE of that, not by accident of what `httpErrorResponse` happens to serialize today.
  assertEquals(Object.keys(error).includes('zanixRotatedSession'), false)
  assert(Object.getOwnPropertyNames(error).includes('zanixRotatedSession'))

  Deno.env.delete('JWT_KEY')
})

Deno.test('attachRotatedSessionToError: returns the SAME error instance, never a wrapper', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  const ctx = createCtx()
  await generateSessionTokens(ctx, { subject: 'operator@example.com' })

  const original = new Error('boom')
  const result = attachRotatedSessionToError(original, ctx)

  assertEquals(result, original)

  Deno.env.delete('JWT_KEY')
})
