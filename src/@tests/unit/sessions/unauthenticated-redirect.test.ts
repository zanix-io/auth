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
