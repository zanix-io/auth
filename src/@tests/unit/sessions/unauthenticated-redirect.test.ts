import { assert, assertEquals, assertFalse } from '@std/assert'
import { HttpError } from '@zanix/errors'
import { attachRequestToError } from '@zanix/server'
import { redirectUnauthenticatedPageVisit } from 'utils/sessions/unauthenticated-redirect.ts'

Deno.test(
  'redirectUnauthenticatedPageVisit: a 401 with a request attached redirects to the computed login URL',
  async () => {
    const error = attachRequestToError(
      new HttpError('UNAUTHORIZED'),
      new Request('https://example.test/es/profile'),
    )
    const handler = redirectUnauthenticatedPageVisit({
      loginUrl: (request) => `/${new URL(request.url).pathname.split('/')[1]}/login`,
    })

    const response = await handler(error)

    assert(response instanceof Response, 'expected a real Response, not undefined')
    assertEquals(response.status, 302)
    assertEquals(response.headers.get('location'), '/es/login')
  },
)

Deno.test(
  'redirectUnauthenticatedPageVisit: omitting clearSessionCookie keeps the original redirect-only ' +
    'behavior — no Set-Cookie header at all',
  async () => {
    const error = attachRequestToError(
      new HttpError('UNAUTHORIZED'),
      new Request('https://example.test/es/profile'),
    )
    const handler = redirectUnauthenticatedPageVisit({ loginUrl: () => '/es/login' })

    const response = await handler(error)

    assert(response instanceof Response, 'expected a real Response, not undefined')
    assertEquals(response.headers.getSetCookie(), [])
  },
)

Deno.test(
  'redirectUnauthenticatedPageVisit: clearSessionCookie: true clears the "user" session cookie ' +
    'alongside the redirect',
  async () => {
    const error = attachRequestToError(
      new HttpError('UNAUTHORIZED'),
      new Request('https://example.test/es/profile'),
    )
    const handler = redirectUnauthenticatedPageVisit({
      loginUrl: () => '/es/login',
      clearSessionCookie: true,
    })

    const response = await handler(error)

    assert(response instanceof Response, 'expected a real Response, not undefined')
    assertEquals(response.status, 302)
    assertEquals(response.headers.get('location'), '/es/login')
    const setCookies = response.headers.getSetCookie()
    const appToken = setCookies.find((c) => c.startsWith('X-Znx-App-Token='))
    assert(appToken, `expected a cleared X-Znx-App-Token cookie among: ${setCookies.join(' | ')}`)
    assert(appToken.includes('Max-Age=0'), `expected Max-Age=0, got: ${appToken}`)
  },
)

Deno.test(
  'redirectUnauthenticatedPageVisit: clearSessionCookie: "api" clears the "api" session status ' +
    'header instead of the "user" one — "api" has no cookie token to clear at all',
  async () => {
    const error = attachRequestToError(
      new HttpError('UNAUTHORIZED'),
      new Request('https://example.test/es/profile'),
    )
    const handler = redirectUnauthenticatedPageVisit({
      loginUrl: () => '/es/login',
      clearSessionCookie: 'api',
    })

    const response = await handler(error)

    assert(response instanceof Response, 'expected a real Response, not undefined')
    assertEquals(response.headers.get('X-Znx-Api-Session-Status'), 'revoked')
    assertFalse(
      response.headers.getSetCookie().some((c) => c.startsWith('X-Znx-App-Token=')),
      'the "api" type has no cookie token — nothing to clear as a Set-Cookie',
    )
  },
)

Deno.test(
  'redirectUnauthenticatedPageVisit: declines a 403 (a valid session lacking the required role) — ' +
    'only a genuinely UNAUTHENTICATED visit redirects, never an authenticated one lacking permission',
  async () => {
    const error = attachRequestToError(
      new HttpError('FORBIDDEN'),
      new Request('https://example.test/es/profile'),
    )
    const handler = redirectUnauthenticatedPageVisit({ loginUrl: () => '/es/login' })

    assertEquals(await handler(error), undefined)
  },
)

Deno.test(
  'redirectUnauthenticatedPageVisit: declines a 401 with no request attached (attachRequestToErrors ' +
    'left unset) — composes safely alongside another OnErrorHandler instead of throwing itself',
  async () => {
    const handler = redirectUnauthenticatedPageVisit({ loginUrl: () => '/es/login' })

    assertEquals(await handler(new HttpError('UNAUTHORIZED')), undefined)
  },
)

Deno.test(
  'redirectUnauthenticatedPageVisit: declines an unrelated, non-HttpError throw',
  async () => {
    const handler = redirectUnauthenticatedPageVisit({ loginUrl: () => '/es/login' })

    assertEquals(await handler(new Error('boom')), undefined)
  },
)

Deno.test(
  'redirectUnauthenticatedPageVisit: redirects a 401 from a DIFFERENT HttpError class — the real, ' +
    "confirmed cross-package identity split (e.g. zanix/iam's own iamSessionGuard, a real guard " +
    'this package never built, throwing its OWN @zanix/errors import) — never an `instanceof` check ' +
    "against this package's own import",
  async () => {
    // A plain class, structurally identical to a real HttpError (`name`/`status.value`) but NOT
    // `instanceof` this package's own `HttpError` — exactly what a second, independently-resolved
    // copy of `@zanix/errors` produces under `zanix space dev`'s dev-mode SSR bundler.
    class OtherPackageHttpError extends Error {
      public override name = 'HttpError'
      public status = { code: 'UNAUTHORIZED', value: 401 }
    }
    const error = attachRequestToError(
      new OtherPackageHttpError('No session cookie present.'),
      new Request('https://example.test/es/profile'),
    )
    const handler = redirectUnauthenticatedPageVisit({
      loginUrl: (request) => `/${new URL(request.url).pathname.split('/')[1]}/login`,
    })

    const response = await handler(error)

    assert(response instanceof Response, 'expected a real Response, not undefined')
    assertEquals(response.status, 302)
    assertEquals(response.headers.get('location'), '/es/login')
  },
)

Deno.test(
  'redirectUnauthenticatedPageVisit: declines a plain object shaped like a 403, even with no real ' +
    'HttpError class at all — the structural check still respects status.value, not just name',
  () => {
    const handler = redirectUnauthenticatedPageVisit({ loginUrl: () => '/es/login' })

    assertEquals(
      handler({ name: 'HttpError', status: { code: 'FORBIDDEN', value: 403 } }),
      undefined,
    )
  },
)

Deno.test(
  'redirectUnauthenticatedPageVisit: declines primitives and null without throwing',
  () => {
    const handler = redirectUnauthenticatedPageVisit({ loginUrl: () => '/es/login' })

    assertEquals(handler(null), undefined)
    assertEquals(handler(undefined), undefined)
    assertEquals(handler('boom'), undefined)
    assertEquals(handler(401), undefined)
  },
)
