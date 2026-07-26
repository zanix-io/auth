// deno-lint-ignore-file no-explicit-any
import { assert, assertEquals, assertMatch } from '@std/assert'
import { sessionHeadersInterceptor } from 'modules/middlewares/headers.interceptor.ts'
import { createJWT } from 'utils/jwt/create.ts'

function createCtx(overrides: any = {}) {
  return {
    locals: {},
    cookies: {},
    req: { headers: { get: () => null } },
    ...overrides,
  } as any
}

Deno.test('sessionHeadersInterceptor returns the response unchanged without a session', () => {
  const interceptor = sessionHeadersInterceptor()
  const response = new Response()

  const result = interceptor(createCtx(), response)

  assertEquals(result, response)
})

Deno.test(
  'sessionHeadersInterceptor appends Set-Cookie headers when cookies are accepted',
  async () => {
    const interceptor = sessionHeadersInterceptor()
    const response = new Response()

    // A real refresh token, expiring in ~1y (as createRefreshToken does), well beyond the
    // access-token-based `payload.exp` below (1h) — the refresh-token cookie's Max-Age must
    // be derived from this token's own `exp`, not from the session's access-token expiration.
    const refreshToken = await createJWT({}, 'my-secret', { expiration: '1y' })

    const ctx = createCtx({
      locals: {
        session: {
          type: 'user',
          status: 'active',
          subject: 'user@example.com',
          payload: { exp: Math.floor(Date.now() / 1000) + 3600 },
          token: refreshToken,
        },
      },
      req: {
        headers: { get: (key: string) => key === 'X-Znx-Cookies-Accepted' ? 'true' : null },
      },
    })

    const result = interceptor(ctx, response) as Response

    const setCookies = result.headers.getSetCookie()
    const appTokenCookie = setCookies.find((cookie) => cookie.startsWith('X-Znx-App-Token='))
    assert(appTokenCookie)
    // ~1 year in seconds (31536000), not the ~3600s tied to the access token's expiration.
    assertMatch(appTokenCookie, /Max-Age=3153[0-9]{4};/)
    assert(!ctx.locals.session)
  },
)

Deno.test('sessionHeadersInterceptor normalizes anonymous type, falls back to session.id', () => {
  const interceptor = sessionHeadersInterceptor()
  const response = new Response()

  const ctx = createCtx({
    locals: {
      session: {
        type: 'anonymous',
        status: 'unconfirmed',
        id: 'anon-session-id',
        payload: {},
      },
    },
  })

  const result = interceptor(ctx, response) as Response

  assertEquals(result.headers.get('X-Znx-User-Id'), 'anon-session-id')
})
