import { assertEquals } from '@std/assert'
import { GENERAL_HEADERS } from '@zanix/server'
import type { GuardContext } from '@zanix/server'
import { markCookiesAccepted } from 'utils/sessions/mark-cookies-accepted.ts'

/**
 * Regression coverage for two real, previously-live bugs in the two consumers this function
 * replaces (`zanix/iam`'s own `cookieConsentBypassGuard`, `@presenza/web`'s own
 * `cookiesAcceptedGuard` — both independently hit and fixed the identical shape before this
 * function existed to share the fix once): the first fix attempt wrote
 * `GENERAL_HEADERS.cookiesAcceptedHeader` onto `ctx.req.headers` directly, which passes a unit test
 * built against a bare `new Request(...)` (mutable `"request"` `Headers` guard) but throws
 * `TypeError: Cannot change headers: headers are immutable` against a REAL server request (the
 * `"immutable"` guard). This test reproduces that real constraint via an actual `Deno.serve` round
 * trip — a genuine server dependency, `zanix-test-tier-conventions`' own Pattern B, never reachable
 * from `unit/`.
 */
Deno.test(
  "markCookiesAccepted: tolerates a real request's immutable Headers and a frozen ctx.cookies",
  async () => {
    let caught: unknown
    let headerValue: string | null = null
    const server = Deno.serve({ port: 0, onListen: () => {} }, (req) => {
      // Mirrors real production ordering: `cookiesGuard` runs BEFORE any app guard and hands over
      // an already-frozen `cookies` object.
      const ctx = { req, cookies: Object.freeze({}) } as unknown as GuardContext
      try {
        markCookiesAccepted(ctx)
        headerValue = ctx.req.headers.get(GENERAL_HEADERS.cookiesAcceptedHeader)
      } catch (error) {
        caught = error
      }
      return new Response(null, { status: 204 })
    })

    try {
      await fetch(`http://localhost:${server.addr.port}/`)
    } finally {
      await server.shutdown()
    }

    assertEquals(caught, undefined)
    assertEquals(headerValue, 'true')
  },
)

/**
 * Regression coverage for a SECOND real, previously-live bug in the same fix: `new Request(ctx.req,
 * { headers })` itself throws `TypeError: Input request's body is unusable` once `ctx.req`'s body
 * has already been read — which `@zanix/server`'s own request handler does globally, for every
 * `POST`/`PUT`/`PATCH` request carrying a JSON or `application/x-www-form-urlencoded` body, BEFORE
 * any guard (this one included) ever runs. That's the real, common case for BOTH consumers this
 * function replaces: every login/OTP/TOTP/password-recovery action is exactly such a `POST`. This
 * test drains the request body first — the same way that framework-level parsing step does —
 * before invoking the function, to prove it survives an ALREADY-CONSUMED body rather than only
 * ever being exercised against a bodyless `GET`.
 */
Deno.test(
  'markCookiesAccepted: tolerates a POST request whose body was already consumed before it ran',
  async () => {
    let caught: unknown
    let headerValue: string | null = null
    let methodPreserved: string | undefined
    const server = Deno.serve({ port: 0, onListen: () => {} }, async (req) => {
      // Mirrors `bodyPayloadProperty` (`@zanix/server`) draining the body before any guard runs.
      await req.text()

      const ctx = { req, cookies: Object.freeze({}) } as unknown as GuardContext
      try {
        markCookiesAccepted(ctx)
        headerValue = ctx.req.headers.get(GENERAL_HEADERS.cookiesAcceptedHeader)
        methodPreserved = ctx.req.method
      } catch (error) {
        caught = error
      }
      return new Response(null, { status: 204 })
    })

    try {
      await fetch(`http://localhost:${server.addr.port}/es/login`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: 'a@b.com', password: 'x' }),
      })
    } finally {
      await server.shutdown()
    }

    assertEquals(caught, undefined)
    assertEquals(headerValue, 'true')
    assertEquals(methodPreserved, 'POST')
  },
)
