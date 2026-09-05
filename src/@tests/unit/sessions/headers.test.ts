import { assert, assertEquals, assertFalse, assertMatch, assertRejects } from '@std/assert'
import {
  checkAcceptedCookies,
  getDefaultSessionHeaders,
  getSessionHeaders,
} from 'utils/sessions/headers.ts'
import { createJWT } from 'utils/jwt/create.ts'
import { InternalError } from '@zanix/errors'

console.error = () => {}

Deno.test('getSessionHeaders returns default headers without cookies', () => {
  const { 'Set-Cookie': cookies, ...headers } = getSessionHeaders({
    cookiesAccepted: false,
    type: 'user',
    subject: 'anonymous',
  })

  assertEquals(headers['X-Znx-User-Id'], 'anonymous')
  assertEquals(headers['X-Znx-User-Session-Status'], 'unconfirmed')
  assert(!cookies.length)
})

Deno.test('getSessionHeaders includes cookies when requested', () => {
  const now = Math.floor(Date.now() / 1000)
  const expiration = now + 3600

  const { 'Set-Cookie': cookies, ...headers } = getSessionHeaders({
    cookiesAccepted: true,
    type: 'user',
    sessionStatus: 'active',
    subject: 'alice',
    expiration,
  })

  assertEquals(headers['X-Znx-User-Id'], 'alice')
  assertEquals(headers['X-Znx-User-Session-Status'], 'active')
  assert(cookies.length)

  assertMatch(cookies[0], /Max-Age=3600/)
  assertMatch(
    cookies[0],
    /X-Znx-User-Session-Status=active; Max-Age=\d+; Path=\/; HttpOnly; Secure; SameSite=Strict/,
  )
  assertMatch(
    cookies[1],
    /X-Znx-User-Id=alice; Max-Age=\d+; Path=\/; HttpOnly; Secure; SameSite=Strict/,
  )
})

/**
 * Regression coverage for a confirmed vulnerability: every session/subject/cookie-consent/
 * refresh-token cookie used to be built without `Secure`, so a browser would still attach it over
 * a plain-HTTP connection.
 */
Deno.test('getSessionHeaders: every cookie it sets includes Secure', async () => {
  const refreshToken = await createJWT({}, 'my-secret', { expiration: '1y' })
  const { 'Set-Cookie': cookies } = getSessionHeaders({
    cookiesAccepted: true,
    type: 'user',
    subject: 'alice',
    expiration: Math.floor(Date.now() / 1000) + 3600,
    refreshToken,
  })

  assert(cookies.length >= 4) // status + subject + cookies-accepted + refresh token
  for (const cookie of cookies) {
    assertMatch(cookie, /; Secure(;|$)/)
  }
})

Deno.test('getSessionHeaders derives the refresh cookie Max-Age from its own exp', async () => {
  // Access token expiring in 1h -> this bounds `maxAge` for the other cookies.
  const expiration = Math.floor(Date.now() / 1000) + 3600
  // Refresh token expiring in ~1y, as createRefreshToken does -> must NOT be capped at 1h.
  const refreshToken = await createJWT({}, 'my-secret', { expiration: '1y' })

  const { 'Set-Cookie': cookies } = getSessionHeaders({
    cookiesAccepted: true,
    type: 'user',
    subject: 'alice',
    expiration,
    refreshToken,
  })

  const appTokenCookie = cookies.find((cookie) => cookie.startsWith('X-Znx-App-Token='))
  assert(appTokenCookie)
  assertMatch(appTokenCookie, /Max-Age=3153[0-9]{4};/) // ~1 year, not ~3600 (1h)
})

/**
 * Regression coverage for a confirmed vulnerability: the session-status/subject/cookie-consent
 * cookies used to be capped at the access token's own `expiration` (≤1h) even when a `refreshToken`
 * (~1y) was also given — expiring `X-Znx-Cookies-Accepted` long before the session cookie it's meant
 * to gate. Once a browser dropped that expired consent cookie, `checkAcceptedCookies` fell back to
 * `false` for every later request, and this function's own `if (cookiesAccepted)` gate then
 * suppressed EVERY session `Set-Cookie` for that browser — not just a stray one, but a normal
 * refresh-token rotation and even a logout/revoke's own clearing cookie — while the underlying
 * refresh token stayed genuinely valid server-side.
 */
Deno.test(
  "getSessionHeaders: the status/subject/cookie-consent cookies track the refresh token's own " +
    'exp, not the shorter access token expiration, when a refreshToken is given',
  async () => {
    const now = Math.floor(Date.now() / 1000)
    // Access token expiring in 1h, as generateSessionTokens always issues it.
    const expiration = now + 3600
    // Refresh token expiring in ~1y, as createRefreshToken does.
    const refreshToken = await createJWT({}, 'my-secret', { expiration: '1y' })

    const { 'Set-Cookie': cookies } = getSessionHeaders({
      cookiesAccepted: true,
      type: 'user',
      sessionStatus: 'active',
      subject: 'alice',
      expiration,
      refreshToken,
    })

    const statusCookie = cookies.find((cookie) => cookie.startsWith('X-Znx-User-Session-Status='))
    const subjectCookie = cookies.find((cookie) => cookie.startsWith('X-Znx-User-Id='))
    const consentCookie = cookies.find((cookie) => cookie.startsWith('X-Znx-Cookies-Accepted='))

    for (const cookie of [statusCookie, subjectCookie, consentCookie]) {
      assert(cookie)
      assertMatch(cookie, /Max-Age=3153[0-9]{4};/) // ~1 year, not ~3600 (1h)
    }
  },
)

/**
 * Without a `refreshToken` at all (an `'api'` session, or a `'user'` one that never got one), these
 * cookies have no longer-lived signal to track — they stay bound to `expiration`, exactly as before.
 */
Deno.test(
  'getSessionHeaders: the status/subject/cookie-consent cookies still use expiration when there ' +
    'is no refreshToken',
  () => {
    const now = Math.floor(Date.now() / 1000)
    const expiration = now + 3600

    const { 'Set-Cookie': cookies } = getSessionHeaders({
      cookiesAccepted: true,
      type: 'user',
      sessionStatus: 'active',
      subject: 'alice',
      expiration,
    })

    assertMatch(cookies[0], /Max-Age=3600;/)
    assertMatch(cookies[1], /Max-Age=3600;/)
    assertMatch(cookies[2], /Max-Age=3600;/)
  },
)

Deno.test('getSessionHeaders zeroes the refresh cookie Max-Age when it has no exp', async () => {
  const refreshToken = await createJWT({}, 'my-secret') // no `expiration` -> no `exp` claim

  const { 'Set-Cookie': cookies } = getSessionHeaders({
    cookiesAccepted: true,
    type: 'user',
    subject: 'alice',
    expiration: Math.floor(Date.now() / 1000) + 3600,
    refreshToken,
  })

  const appTokenCookie = cookies.find((cookie) => cookie.startsWith('X-Znx-App-Token='))
  assert(appTokenCookie)
  assertMatch(appTokenCookie, /Max-Age=0;/)
})

Deno.test('getSessionHeaders zeroes the refresh cookie when invalidated', async () => {
  // A still-valid refresh token (~1y left), but the caller signals invalidation via
  // `expiration: 0` (maxAge === 0, e.g. a failed/blocked session) — the refresh cookie
  // must be cleared too, not kept alive with its own long-lived exp.
  const refreshToken = await createJWT({}, 'my-secret', { expiration: '1y' })

  const { 'Set-Cookie': cookies } = getSessionHeaders({
    cookiesAccepted: true,
    type: 'user',
    subject: 'alice',
    expiration: 0,
    refreshToken,
  })

  const appTokenCookie = cookies.find((cookie) => cookie.startsWith('X-Znx-App-Token='))
  assert(appTokenCookie)
  assertMatch(appTokenCookie, /Max-Age=0;/)

  // Invalidation (`expiration: 0`) wins over the refresh token's own long exp for every cookie,
  // not just the app-token one — a logout/revoke must still clear the whole batch.
  const statusCookie = cookies.find((cookie) => cookie.startsWith('X-Znx-User-Session-Status='))
  const consentCookie = cookies.find((cookie) => cookie.startsWith('X-Znx-Cookies-Accepted='))
  assert(statusCookie)
  assert(consentCookie)
  assertMatch(statusCookie, /Max-Age=0;/)
  assertMatch(consentCookie, /Max-Age=0;/)
})

Deno.test(
  'getSessionHeaders clears cookies for a revoked session even without cookiesAccepted',
  async () => {
    // A plain, no-JS `<form method="post">` logout has no way to attach the
    // `X-Znx-Cookies-Accepted` header, and its consent cookie may already be gone by the time it
    // navigates — a revoked session clears every cookie regardless.
    const refreshToken = await createJWT({}, 'my-secret', { expiration: '1y' })

    const { 'Set-Cookie': cookies } = getSessionHeaders({
      cookiesAccepted: false,
      sessionStatus: 'revoked',
      type: 'user',
      subject: 'alice',
      expiration: 0,
      refreshToken,
    })

    const appTokenCookie = cookies.find((cookie) => cookie.startsWith('X-Znx-App-Token='))
    const statusCookie = cookies.find((cookie) => cookie.startsWith('X-Znx-User-Session-Status='))
    const consentCookie = cookies.find((cookie) => cookie.startsWith('X-Znx-Cookies-Accepted='))

    for (const cookie of [appTokenCookie, statusCookie, consentCookie]) {
      assert(cookie)
      assertMatch(cookie, /Max-Age=0;/)
    }
  },
)

Deno.test(
  'getSessionHeaders withholds cookies for a non-revoked session without cookiesAccepted',
  () => {
    const { 'Set-Cookie': cookies } = getSessionHeaders({
      cookiesAccepted: false,
      sessionStatus: 'active',
      type: 'user',
      subject: 'alice',
      expiration: Math.floor(Date.now() / 1000) + 3600,
    })

    assert(!cookies.length)
  },
)

Deno.test('getSessionHeaders clears the refresh cookie when there is no refresh token', () => {
  const { 'Set-Cookie': cookies } = getSessionHeaders({
    cookiesAccepted: true,
    type: 'user',
    subject: 'alice',
    expiration: 0,
  })

  const appTokenCookie = cookies.find((cookie) => cookie.startsWith('X-Znx-App-Token='))
  assert(appTokenCookie)
  assertMatch(appTokenCookie, /Max-Age=0;/)
})

Deno.test('getSessionHeaders handles API type correctly', () => {
  const { 'Set-Cookie': _, ...headers } = getSessionHeaders({
    cookiesAccepted: false,
    type: 'api',
    subject: 'anonymous',
  })

  assertEquals(headers['X-Znx-Api-Id'], 'anonymous')
  assertEquals(headers['X-Znx-Api-Session-Status'], 'unconfirmed')
})

Deno.test('getSessionHeaders never sets a token cookie for api type, even at Max-Age=0', () => {
  // `SESSION_HEADERS.api.token` is `undefined` — `api` sessions have no refresh-token concept (see
  // `docs/service-credential.md`). `maxAge === 0` (the default here, and what every auth-failure
  // response uses via `getDefaultSessionHeaders`) must not bypass that and push a stray
  // `undefined=undefined` cookie.
  const { 'Set-Cookie': cookies } = getSessionHeaders({
    cookiesAccepted: true,
    type: 'api',
    subject: 'anonymous',
    sessionStatus: 'failed',
  })

  assertFalse(cookies.some((cookie) => cookie.startsWith('undefined=')))
  assertEquals(cookies.length, 3) // status + subject + cookies-accepted only, no token cookie
})

Deno.test('getSessionHeaders caps Max-Age at 0 if expiration is in the past', () => {
  const past = Math.floor(Date.now() / 1000) - 100
  const { 'Set-Cookie': cookies } = getSessionHeaders({
    cookiesAccepted: true,
    type: 'user',
    expiration: past,
    subject: 'anonymous',
  })

  assertMatch(cookies[0], /Max-Age=0;/)
})

Deno.test('getSessionHeaders caps Max-Age at 10 if expiration is in the future', () => {
  const future = Math.floor(Date.now() / 1000) + 10
  const { 'Set-Cookie': cookies } = getSessionHeaders({
    cookiesAccepted: true,
    type: 'user',
    expiration: future,
    subject: 'anonymous',
  })

  assertMatch(cookies[0], /Max-Age=10;/)
})

Deno.test(
  'getDefaultSessionHeaders returns default headers without cookies and headers',
  async () => {
    const { 'Set-Cookie': _, ...apiHeaders } = await getDefaultSessionHeaders(
      {
        headers: {
          get: (name: string) => name === 'X-Znx-User-Id' ? 'my-user' : null,
        } as never,
        cookies: {},
        type: 'api',
        cookiesAccepted: false,
        trustProxyHeader: false,
      },
    )

    assertEquals(apiHeaders['X-Znx-Api-Session-Status'], 'unconfirmed')
    assert(apiHeaders['X-Znx-Api-Id'].startsWith('anonymous-'))

    const { 'Set-Cookie': __, ...userHeaders } = await getDefaultSessionHeaders(
      {
        headers: {
          get: (name: string) => name === 'X-Znx-Api-Id' ? 'my-user' : null,
        } as never,
        cookies: {},
        type: 'user',
        cookiesAccepted: false,
        trustProxyHeader: false,
      },
    )

    assertEquals(userHeaders['X-Znx-User-Session-Status'], 'unconfirmed')
    assert(userHeaders['X-Znx-User-Id'].startsWith('anonymous-'))
  },
)

/**
 * Regression coverage for the gap this whole `trustProxyHeader` contract exists to close: before
 * `getAnonymousSessionId` enforced it directly (rather than only `rateLimitGuard` doing so at
 * construction time), `getDefaultSessionHeaders`'s own anonymous fallback silently defaulted to
 * `false` — closing the spoofing bypass by accident, never by an explicit decision, and only for
 * this one caller. Any caller reaching the fallback with no decision made must now throw.
 */
Deno.test(
  'getDefaultSessionHeaders throws when it falls back to an anonymous session id without an explicit trustProxyHeader',
  async () => {
    await assertRejects(
      () =>
        getDefaultSessionHeaders({
          headers: { get: () => null } as never,
          cookies: {},
          type: 'user',
          cookiesAccepted: false,
        }),
      InternalError,
    )
  },
)

Deno.test(
  'getDefaultSessionHeaders does not throw when a real client subject is resolved, even without trustProxyHeader',
  async () => {
    const { 'Set-Cookie': _, ...headers } = await getDefaultSessionHeaders({
      headers: { get: () => null } as never,
      cookies: { 'X-Znx-User-Id': 'my-user' },
      type: 'user',
      cookiesAccepted: false,
    })
    assert(headers['X-Znx-User-Id'].startsWith('my-user'))
  },
)

Deno.test('getDefaultSessionHeaders returns default headers with cookies', async () => {
  const { 'Set-Cookie': cookies, ...apiHeaders } = await getDefaultSessionHeaders(
    {
      headers: {
        get: (name: string) => name === 'X-Znx-Api-Id' ? 'my-api' : null,
      } as never,
      cookies: {},
      type: 'api',
      cookiesAccepted: true,
    },
  )

  assert(apiHeaders['X-Znx-Api-Id'].startsWith('my-api'))
  assertMatch(cookies[0], /^X-Znx-Api-Session-Status=unconfirmed; Max-Age=0;/)
  assertMatch(cookies[1], /^X-Znx-Api-Id=my-api;/)

  const { 'Set-Cookie': userCookies, ...userHeaders } = await getDefaultSessionHeaders(
    {
      headers: { get: () => null } as never,
      cookies: { 'X-Znx-User-Id': 'my-user' },
      type: 'user',
      cookiesAccepted: true,
    },
  )

  assert(userHeaders['X-Znx-User-Id'].startsWith('my-user'))
  assertMatch(
    userCookies[0],
    /^X-Znx-User-Session-Status=unconfirmed; Max-Age=0;/,
  )
  assertMatch(userCookies[1], /^X-Znx-User-Id=my-user; Max-Age=0;/)
})

Deno.test('checkAcceptedCookies reads the header value when present', () => {
  assert(
    checkAcceptedCookies(
      { get: () => 'true' } as never,
      {},
    ),
  )
  assertFalse(
    checkAcceptedCookies(
      { get: () => 'false' } as never,
      {},
    ),
  )
})

Deno.test('checkAcceptedCookies falls back to the cookie value when the header is absent', () => {
  assert(
    checkAcceptedCookies(
      { get: () => null } as never,
      { 'X-Znx-Cookies-Accepted': 'true' },
    ),
  )
  assertFalse(
    checkAcceptedCookies(
      { get: () => null } as never,
      {},
    ),
  )
})
