import { getRequestFromError } from '@zanix/server'
import { HttpError } from '@zanix/errors'

/**
 * An `OnErrorHandler`-shaped recovery function — pass it (typically alongside `@zanix/space`'s own
 * `createNotFoundHandler()`, composed via that package's `globalErrorHandler`) as `server.ssr.onError`
 * to turn an unauthenticated visit to a `pageSessionGuard`-protected page into a real redirect
 * instead of a raw JSON `401`.
 *
 * ## The gap this closes
 *
 * `pageSessionGuard` (and any guard built on `deriveSessionToken`/`refreshSessionTokens`, e.g. this
 * package's own README-documented composition pattern) throws `HttpError('UNAUTHORIZED')` directly
 * for a missing/invalid/expired session — it never redirects itself (see that guard's own doc). A
 * guard throw happens BEFORE `@zanix/space`'s own per-route `error.tsx`/`DefaultErrorView` machinery
 * ever runs — that only wraps a `loader`/render-phase throw (`renderLoaderErrorPage`), never a
 * guard/pipe throw, which instead reaches `server.ssr.onError` uncaught. With no handler recognizing
 * it there, it falls through to `@zanix/server`'s own generic `httpErrorResponse` — the same raw
 * JSON body a REST API route would return, on what a browser navigation is expecting to be a full
 * HTML page. `server.ssr.onError` is a distinct target from `server.rest.onError` (`@zanix/server`'s
 * own per-server-type `ServerOptions`), so this handler only ever runs for a page (SSR) request,
 * never for a real REST API caller expecting JSON — no need to special-case route shape here.
 *
 * ## Requirements
 *
 * - `server.ssr.attachRequestToErrors: true` — without it, `getRequestFromError` finds nothing and
 *   this handler declines every error, same as if it weren't composed at all.
 * - `options.loginUrl` decides where to send the visitor — this package has no opinion on an app's
 *   own login route shape (lang-prefixed, `?next=` return param, or neither); compute it from the
 *   `Request` this handler hands back.
 *
 * Declines (returns `undefined`, the same "not handled, fall through" convention `@zanix/space`'s
 * own `createNotFoundHandler`/this package's own `recoverRotatedSessionCookie` already establish)
 * for anything that isn't a `401`, or that arrives with no request attached — composes safely with
 * other `OnErrorHandler`s regardless of order.
 *
 * @param options - Configuration for this handler.
 * @param options.loginUrl - Computes the login page to redirect to, given the original `Request`
 * this guard rejected. Return anything `Response`'s `Location` header accepts — an absolute URL, or
 * a path resolved against `request.url`.
 *
 * @example
 * ```ts
 * import { globalErrorHandler, createNotFoundHandler } from '@zanix/space'
 * import { recoverRotatedSessionCookie, redirectUnauthenticatedPageVisit } from '@zanix/auth'
 *
 * await bootstrapRemoteApp(spaceApp, {
 *   server: {
 *     ssr: {
 *       attachRequestToErrors: true,
 *       onError: globalErrorHandler(
 *         recoverRotatedSessionCookie(),
 *         redirectUnauthenticatedPageVisit({
 *           loginUrl: (request) => {
 *             const lang = new URL(request.url).pathname.split('/')[1]
 *             return `/${lang}/login`
 *           },
 *         }),
 *         createNotFoundHandler(),
 *       ),
 *     },
 *   },
 * })
 * ```
 */
export function redirectUnauthenticatedPageVisit(
  options: { loginUrl: (request: Request) => string | URL },
): (error: unknown) => Response | undefined {
  return (error: unknown) => {
    if (!(error instanceof HttpError) || error.status.value !== 401) return undefined
    const request = getRequestFromError(error)
    if (!request) return undefined
    const location = options.loginUrl(request)
    return new Response(null, { status: 302, headers: { location: String(location) } })
  }
}
