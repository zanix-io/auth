// deno-lint-ignore-file no-explicit-any
import { assert, assertEquals, assertFalse, assertRejects } from '@std/assert'
import {
  ProgramModule,
  SESSION_HEADERS,
  type ZanixCacheProvider,
  type ZanixKVConnector,
} from '@zanix/server'
import { PermissionDenied } from '@zanix/errors'

import { generateSessionTokens } from 'utils/sessions/create.ts'
import { refreshSessionTokens } from 'utils/sessions/refresh.ts'
import { revokeSessionToken } from 'utils/sessions/revoke.ts'
import { checkTokenBlockList } from 'utils/sessions/block-list.ts'
import { jwtValidationGuard } from 'modules/middlewares/jwt-validation.guard.ts'
import { sessionHeadersInterceptor } from 'modules/middlewares/headers.interceptor.ts'
import { contextMock } from '../../mocks.ts'

console.warn = () => {}
console.info = () => {}

const APP_TOKEN_COOKIE = SESSION_HEADERS.user.token as string

// Reproduces the real-world flow (as in a consuming app like an IAM service):
// login -> an authenticated request using the issued access token -> refresh -> revoke (logout)
// -> the revoked token can no longer be used. This is what caught the session.token/refresh-cookie
// corruption bug: it only shows up when a SECOND, separate request goes through the guard after
// login, which single-shot unit tests never exercise.
Deno.test({
  sanitizeOps: false,
  sanitizeResources: false,
  name: 'full session lifecycle: login -> authenticated request -> refresh -> revoke',
  fn: async () => {
    Deno.env.set('REDIS_URI', 'redis://localhost:6379')
    Deno.env.set('JWT_KEY', 'my-secret')
    await import('@zanix/datamaster/core') // load cache core
    await ProgramModule.connectors.get<any>('cache:redis').clear() // reset data

    const cache = ProgramModule.providers.get<ZanixCacheProvider>('cache')
    const kvDb = ProgramModule.connectors.get<ZanixKVConnector>('kvLocal')

    // 1. LOGIN — mints the real session tokens. Unlike a guard, `generateSessionTokens` runs at
    // handler stage: `@zanix/server`'s one-time `contextSettingPipe` promotion already happened
    // *before* the login handler executed (there's no prior guard for an anonymous login request,
    // so it promoted nothing). `generateSessionTokens` (via `defineLocalSession`) only ever writes
    // `ctx.locals.session`, never `ctx.session` — so, correctly, `loginCtx.session` is left
    // untouched here (staying unset, exactly as it would after a no-op pre-handler promotion), and
    // `sessionHeadersInterceptor` must read the fresher `locals.session` to produce the cookie at
    // all. This is exactly the scenario that was broken before `sessionHeadersInterceptor` started
    // checking `locals.session` first.
    const loginCtx = contextMock()
    loginCtx.req.headers.get = (name) => name === 'X-Znx-Cookies-Accepted' ? 'true' : null
    const loginTokens = await generateSessionTokens(loginCtx, {
      subject: 'user@example.com',
    })
    assert(loginTokens.accessToken)
    assert(loginTokens.refreshToken)

    const loginResponse = new Response()
    await sessionHeadersInterceptor()(loginCtx, loginResponse)
    const loginCookies = loginResponse.headers.getSetCookie()
    const appTokenCookie = loginCookies.find((cookie) => cookie.startsWith(`${APP_TOKEN_COOKIE}=`))
    assert(appTokenCookie, 'login response should set the app-token cookie')
    assert(
      appTokenCookie.includes(loginTokens.refreshToken),
      'the app-token cookie set at login must carry the real refresh token',
    )

    // 2. AUTHENTICATED REQUEST — the browser sends the access token back, plus the cookie
    // from login. This is the request that, before the fix, corrupted the app-token cookie.
    const authedCtx = contextMock()
    authedCtx.req.headers.get = (name) =>
      name === 'Authorization'
        ? `Bearer ${loginTokens.accessToken}`
        : name === 'X-Znx-Cookies-Accepted'
        ? 'true'
        : null
    authedCtx.cookies = { [APP_TOKEN_COOKIE]: loginTokens.refreshToken }

    const { response: guardResponse } = await jwtValidationGuard({
      rateLimit: false,
    })(authedCtx)
    assertFalse(guardResponse)
    // Unlike the login step above, a guard runs *before* `contextSettingPipe`'s promotion, so
    // simulating the promotion immediately after the guard call (and before the interceptor) is
    // the correct timing here — nothing re-populates `locals.session` afterward in a plain
    // authenticated request.
    authedCtx.session = authedCtx.locals.session as never

    const authedResponse = new Response()
    await sessionHeadersInterceptor()(authedCtx, authedResponse)
    const authedCookies = authedResponse.headers.getSetCookie()
    assertFalse(
      authedCookies.some((cookie) => cookie.startsWith(`${APP_TOKEN_COOKIE}=`)),
      'an authenticated request must not re-set (and corrupt) the app-token cookie',
    )

    // 3. REFRESH — using the cookie value exactly as the browser would resend it. This is
    // where the bug would have surfaced: a corrupted cookie holds an access token, which
    // refreshSessionTokens rejects as "not a refresh token".
    const refreshCtx = contextMock()
    refreshCtx.cookies = { [APP_TOKEN_COOKIE]: loginTokens.refreshToken }
    const refreshed = await refreshSessionTokens(refreshCtx, undefined, {
      cache,
      kvDb,
    })
    assert(refreshed.accessToken)
    assert(refreshed.refreshToken)
    assertEquals(refreshed.oldToken, loginTokens.refreshToken)

    // 4. REVOKE (logout) — using the rotated refresh token from the refresh step.
    const revokeCtx = contextMock()
    const revokedPayload = await revokeSessionToken(revokeCtx, {
      token: refreshed.refreshToken,
      cache,
      kvDb,
    })
    assert(revokedPayload.jti)

    const isBlocked = await checkTokenBlockList(
      revokedPayload.jti,
      cache,
      kvDb,
    )
    assert(isBlocked, 'the revoked refresh token should be blocklisted')

    // A subsequent refresh attempt with the revoked token must be rejected.
    const postRevokeCtx = contextMock()
    await assertRejects(
      () =>
        refreshSessionTokens(postRevokeCtx, refreshed.refreshToken, {
          cache,
          kvDb,
        }),
      PermissionDenied,
    )

    Deno.env.delete('JWT_KEY')
    Deno.env.delete('REDIS_URI')
  },
})
