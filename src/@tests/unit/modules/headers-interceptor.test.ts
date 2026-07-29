// deno-lint-ignore-file no-explicit-any
import { assert, assertEquals, assertMatch } from '@std/assert'
import { sessionHeadersInterceptor } from 'modules/middlewares/headers.interceptor.ts'
import { createJWT } from 'utils/jwt/create.ts'

// The interceptor reads `ctx.locals.session` first, falling back to `ctx.session` —
// `@zanix/server`'s `contextSettingPipe` promotes `locals.session` there once, pre-handler, but a
// handler-stage session change (login/refresh/revoke, via `defineLocalSession`) only ever
// re-populates `locals.session`, never `ctx.session`. Most fixtures below set `session` directly
// (simulating the common guard-only case, where `locals.session` is already empty by the time this
// runs); see the dedicated tests further down for the `locals.session` fallback/precedence itself.
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
      session: {
        type: 'user',
        status: 'active',
        subject: 'user@example.com',
        payload: { exp: Math.floor(Date.now() / 1000) + 3600 },
        token: refreshToken,
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
  },
)

Deno.test('sessionHeadersInterceptor normalizes anonymous type, falls back to session.id', () => {
  const interceptor = sessionHeadersInterceptor()
  const response = new Response()

  const ctx = createCtx({
    session: {
      type: 'anonymous',
      status: 'unconfirmed',
      id: 'anon-session-id',
      payload: {},
    },
  })

  const result = interceptor(ctx, response) as Response

  assertEquals(result.headers.get('X-Znx-User-Id'), 'anon-session-id')
})

Deno.test('sessionHeadersInterceptor reads ctx.locals.session when ctx.session is unset', () => {
  const interceptor = sessionHeadersInterceptor()
  const response = new Response()

  // Simulates a login/refresh/revoke handler that just called `defineLocalSession` — no prior
  // guard populated `ctx.session` for this request, so `locals.session` is the only value present.
  const ctx = createCtx({
    locals: {
      session: {
        type: 'anonymous',
        status: 'active',
        id: 'fresh-login-session-id',
        payload: {},
      },
    },
  })

  const result = interceptor(ctx, response) as Response

  assertEquals(result.headers.get('X-Znx-User-Id'), 'fresh-login-session-id')
})

Deno.test('sessionHeadersInterceptor prefers ctx.locals.session over a stale ctx.session', () => {
  const interceptor = sessionHeadersInterceptor()
  const response = new Response()

  // Both are set: `ctx.session` is the stale, pre-handler promoted value; `locals.session` is
  // what a handler-stage `defineLocalSession` call (e.g. revoke/logout) set afterward. The fresher
  // `locals.session` must win.
  const ctx = createCtx({
    session: { type: 'anonymous', status: 'active', id: 'stale-session-id', payload: {} },
    locals: {
      session: { type: 'anonymous', status: 'revoked', id: 'fresh-session-id', payload: {} },
    },
  })

  const result = interceptor(ctx, response) as Response

  assertEquals(result.headers.get('X-Znx-User-Id'), 'fresh-session-id')
  assertEquals(result.headers.get('X-Znx-User-Session-Status'), 'revoked')
})
