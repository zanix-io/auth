import type { GuardContext } from '@zanix/server'
import { GENERAL_HEADERS } from '@zanix/server'

/**
 * Marks the CURRENT request as having accepted cookies — injects `X-Znx-Cookies-Accepted: true` as
 * a REQUEST header, so {@linkcode checkAcceptedCookies} (read by `sessionHeadersInterceptor`) sees
 * it for THIS SAME request, not just the next one. `checkAcceptedCookies` checks the incoming
 * request's own HEADER before falling back to its COOKIE — a cookie a response is only now setting
 * can never be visible to the request that sets it (`ctx.cookies` is populated once from the
 * incoming request and frozen by `cookiesGuard`, `@zanix/server`'s own built-in guard, before any
 * app guard runs), so a response-only `Set-Cookie` always pays off one request late. This closes
 * that gap for any guard that needs the caller's very first request already counted as
 * consent-given — a deployment with no real consent banner of its own (every cookie it sets is
 * functional, nothing to meaningfully decline), or a login/action response that must deliver
 * session cookies on the SAME response that establishes the session.
 *
 * ## Why this exists, not a more obvious two-liner
 *
 * Two more direct ways to attach this signal both throw on a REAL request — confirmed live, never
 * caught by a unit test built against a synthetic, unguarded `Request`/`ctx.cookies`:
 * - `ctx.req.headers.set(...)` — throws `TypeError: Cannot change headers: headers are immutable`.
 *   `ctx.req` is the raw `Request` Deno's own server handler receives, whose `Headers` carry an
 *   `"immutable"` guard.
 * - `ctx.cookies[...] = 'true'` — throws `TypeError: Cannot add property ..., object is not
 *   extensible`. `cookiesGuard` (`@zanix/server`'s own built-in guard, run before every app guard)
 *   `Object.freeze`s `ctx.cookies` right after populating it.
 *
 * Reassigning `ctx.req` itself to a clone (a plain, mutable `GuardContext` property, never a
 * readonly one) is the one thing that DOES work: every later guard/pipe/interceptor in the same
 * pipeline reads `ctx.req` fresh off the shared context, not a pre-guard snapshot, so the injected
 * header is both writable now and correctly read back later by `checkAcceptedCookies`.
 * `ctx.req.bodyUsed` distinguishes the one real constraint on that clone: `new Request(ctx.req,
 * ...)` throws `TypeError: Input request's body is unusable` once the body has already been read —
 * true for every `POST`/`PUT`/`PATCH` request carrying a JSON or `application/x-www-form-urlencoded`
 * body, by the time ANY guard runs (`@zanix/server`'s own request handler eagerly parses it into
 * `ctx.payload.body` before route matching/guards ever start) — so that case rebuilds from
 * `url`/`method` alone instead, losing nothing real since nothing downstream can re-read that body a
 * second time either way.
 *
 * **Requires `@zanix/server@^4.2.7`** when called from a GLOBAL guard (`@zanix/space`'s
 * `defineMiddleware`/this package's own `registerGlobalGuard`, as opposed to a page-level
 * `@Guard(...)`) — a real bug in `registerGlobalGuard` before that version handed a global guard a
 * `{...ctx}` SPREAD COPY of the context rather than the shared one, silently discarding this exact
 * `ctx.req` reassignment the instant the guard returned. Fixed upstream in `@zanix/server`; this
 * function itself needed no change and works correctly from a page-level `@Guard(...)` regardless
 * of `@zanix/server` version, since that call path never went through the buggy wrapper.
 *
 * @param ctx - The current guard's own context — mutated in place (`ctx.req` is reassigned).
 *
 * @example
 * ```ts
 * import type { MiddlewareGuard } from '@zanix/server'
 * import { markCookiesAccepted } from '@zanix/auth'
 *
 * // A deployment with no cookie-consent banner of its own — every cookie is functional, so every
 * // request counts as accepted, unconditionally.
 * export function cookiesAcceptedGuard(): MiddlewareGuard {
 *   return (ctx) => {
 *     markCookiesAccepted(ctx)
 *     return {}
 *   }
 * }
 * ```
 */
export function markCookiesAccepted(ctx: GuardContext): void {
  const headers = new Headers(ctx.req.headers)
  headers.set(GENERAL_HEADERS.cookiesAcceptedHeader, 'true')
  ctx.req = ctx.req.bodyUsed
    ? new Request(ctx.req.url, { method: ctx.req.method, headers })
    : new Request(ctx.req, { headers })
}
