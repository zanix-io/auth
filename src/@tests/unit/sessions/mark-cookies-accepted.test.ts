import { assertEquals, assertFalse } from '@std/assert'
import { GENERAL_HEADERS } from '@zanix/server'
import type { GuardContext } from '@zanix/server'
import { markCookiesAccepted } from 'utils/sessions/mark-cookies-accepted.ts'

/**
 * `markCookiesAccepted`'s own logic in isolation — the real-server constraints it exists to
 * survive (an immutable `Headers` `Request`, an already-consumed `POST` body) are covered by
 * `integration/mark-cookies-accepted.test.ts` instead.
 */

const HEADER = GENERAL_HEADERS.cookiesAcceptedHeader

/** A minimal `GuardContext` — `ctx.cookies` is `Object.freeze`'d, matching what `@zanix/server`'s
 * own built-in `cookiesGuard` (run before every app guard) actually hands downstream, so a
 * regression back to writing `ctx.cookies` directly throws here too. `ctx.req` stays a bare `new
 * Request(...)` — its `Headers` guard is mutable (`"request"`), which is fine here: the immutable-
 * `Headers` case a real incoming request carries is covered by the integration test instead. */
function buildGuardContext(): GuardContext {
  return {
    req: new Request('http://localhost/es/login'),
    cookies: Object.freeze({}),
  } as unknown as GuardContext
}

Deno.test(
  'markCookiesAccepted: injects the accepted header onto a fresh ctx.req, never ctx.cookies',
  () => {
    const ctx = buildGuardContext()
    const originalReq = ctx.req
    markCookiesAccepted(ctx)
    assertEquals(ctx.req.headers.get(HEADER), 'true')
    // The frozen ctx.cookies object is never touched — the fix reassigns ctx.req instead.
    assertEquals(ctx.cookies[HEADER], undefined)
    // ctx.req is a genuinely NEW Request (the original's Headers guard stays untouched), not a
    // mutation of the one the pipeline started with.
    assertFalse(ctx.req === originalReq)
  },
)

Deno.test(
  'markCookiesAccepted: never touches Set-Cookie or any other response header — purely a ' +
    "request-side signal for THIS request's own checkAcceptedCookies read",
  () => {
    const ctx = buildGuardContext()
    markCookiesAccepted(ctx)
    // Nothing beyond the one header changed — same method, same url, no new headers added.
    assertEquals(ctx.req.method, 'GET')
    assertEquals(ctx.req.url, 'http://localhost/es/login')
    assertEquals([...ctx.req.headers.keys()], [HEADER.toLowerCase()])
  },
)
