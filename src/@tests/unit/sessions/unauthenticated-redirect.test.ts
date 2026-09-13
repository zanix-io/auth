import { assert, assertEquals } from '@std/assert'
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
