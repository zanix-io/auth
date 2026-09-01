import type { ScopedContext, Session } from '@zanix/server'
import type { SessionStatus, SessionTypes } from 'typings/sessions.ts'

import { httpErrorResponse } from '@zanix/server'
import { addHeadersToResponse, getSessionHeaders } from './headers.ts'

/**
 * Non-enumerable property {@link attachRotatedSessionToError}/{@link recoverRotatedSessionCookie}
 * share — invisible to `serializeError`/`console.error`/`JSON.stringify`, same discretion
 * `@zanix/server`'s own `attachRequestToError` applies to the `Request` it attaches to an error.
 */
const ROTATED_SESSION_PROPERTY = 'zanixRotatedSession'

/** What {@link attachRotatedSessionToError} carries on an error, and {@link
 * recoverRotatedSessionCookie} reads back — the exact subset of `ctx.locals.session`
 * {@link getSessionHeaders} needs to rebuild the refresh-token cookie. */
type RotatedSessionMarker = {
  token: string
  type: SessionTypes
  subject: string
  status?: SessionStatus
}

/**
 * Marks `error` with the session `refreshSessionTokens` already rotated on `ctx` before something
 * downstream threw — a guard's own permission check, a rate limit, any later guard/pipe in the
 * same chain. `@zanix/server`'s guard pipeline skips its registered response interceptors whenever
 * a guard throws (unlike a handler-body throw, which its own recovery path still runs interceptors
 * over), so `sessionHeadersInterceptor` never gets a chance to deliver that rotated cookie on the
 * resulting error response — the client is left holding a cookie the rotation itself already
 * blocklisted, with no replacement, until it happens to hit a request that succeeds outright.
 *
 * Call this from inside a guard's own `catch`, right before re-throwing, once `refreshSessionTokens`
 * has already run against `ctx`:
 *
 * ```ts
 * import { attachRotatedSessionToError, refreshSessionTokens } from '@zanix/auth'
 *
 * export function requireSession(roles: string[]): MiddlewareGuard {
 *   return async (ctx) => {
 *     await refreshSessionTokens(ctx, undefined, { cache })
 *     try {
 *       await requirePermissions(ctx)
 *     } catch (error) {
 *       throw attachRotatedSessionToError(error, ctx)
 *     }
 *     return {}
 *   }
 * }
 * ```
 *
 * A no-op (returns `error` unchanged) when `ctx.locals.session` carries no `token` — nothing to
 * recover, e.g. `refreshSessionTokens` itself never ran or never rotated anything on this request.
 *
 * **The marker carries a live, valid refresh token — treat it with the same discretion
 * `@zanix/server`'s own `attachRequestToError` already applies to the `Request` it attaches.**
 * Non-enumerable hides it from `serializeError`/`console.error`/`JSON.stringify`/object-spread —
 * confirmed directly: `httpErrorResponse` (`getPublicErrorResponse`'s explicit field allowlist,
 * layered on top of `serializeError`'s own enumerable-only spread) never surfaces it, and neither
 * does `logAppError`'s internal, unrestricted logging path. This is obscurity, not a hard access
 * boundary: `Object.getOwnPropertyNames`/`Reflect.ownKeys` still list it as a real own key, and
 * `error[ROTATED_SESSION_PROPERTY]` reads it back directly, no need to go through {@link
 * getRotatedSessionFromError} — a generic error-reporting/observability integration that walks
 * every own property regardless of enumerability would still see it once attached.
 *
 * @param error - The error a downstream guard/pipe threw — returned unchanged, never wrapped or
 * replaced, so a caller's own `throw attachRotatedSessionToError(...)` keeps the original error
 * identity/type/stack intact.
 * @param ctx - The same context `refreshSessionTokens` already ran against — reads `ctx.locals.session`
 * as it stands right now, whatever this guard chain has already written to it.
 * @returns `error`, mutated in place (a real own property, not a clone).
 */
export function attachRotatedSessionToError<E>(error: E, ctx: ScopedContext): E {
  // `ScopedContext['locals']` types as a plain `Record<string, unknown>` — same reason
  // `refreshSessionTokens`'s own `generateSessionTokens` casts it (`as object`) before writing
  // `token` onto it; this reads that same untyped-by-contract field back.
  const session = ctx.locals.session as Session | undefined
  if (typeof error === 'object' && error !== null && session?.token) {
    // `'anonymous'` (a real runtime `Session.type` value — see `sessionHeadersInterceptor`'s own
    // doc) has no `getSessionHeaders` cookie shape of its own; normalized to `'user'`, the same
    // rule that interceptor already applies for every OTHER session-header path.
    const type = session.type === 'anonymous' ? 'user' : session.type
    const marker: RotatedSessionMarker = {
      token: session.token,
      type: type as SessionTypes,
      subject: session.subject ?? session.id,
      status: session.status,
    }
    Object.defineProperty(error, ROTATED_SESSION_PROPERTY, {
      value: marker,
      enumerable: false,
      configurable: true,
    })
  }
  return error
}

/**
 * Reads back the {@link RotatedSessionMarker} {@link attachRotatedSessionToError} attached to
 * `error`, if any — `undefined` for any error that never went through it. A typed, safe
 * convenience over the same non-enumerable own-property access `@zanix/server`'s own
 * `getRequestFromError` already establishes the pattern for.
 */
function getRotatedSessionFromError(error: unknown): RotatedSessionMarker | undefined {
  if (typeof error !== 'object' || error === null) return undefined
  return (error as Record<string, unknown>)[ROTATED_SESSION_PROPERTY] as
    | RotatedSessionMarker
    | undefined
}

/**
 * An `OnErrorHandler`-shaped recovery function — pass it (typically alongside `@zanix/space`'s own
 * `createNotFoundHandler()`, composed via that package's `globalErrorHandler`) as
 * `server.ssr.onError` to deliver the refresh-token cookie {@link attachRotatedSessionToError}
 * marked, on whatever error response a guard's own throw produced.
 *
 * Declines (returns `undefined`, this package's own "not handled, fall through" convention — see
 * `@zanix/space`'s `createNotFoundHandler`) for any error `attachRotatedSessionToError` never
 * touched, so it composes safely with other `OnErrorHandler`s regardless of order.
 *
 * Rebuilds the response via the SAME `getSessionHeaders`/`addHeadersToResponse` this package's own
 * `sessionHeadersInterceptor` uses for a successful response — never a hand-rolled cookie string —
 * so the refresh-token cookie's attributes (`HttpOnly`/`Secure`/`SameSite`/its own `Max-Age`,
 * derived from the token's real `exp` claim) stay identical to every other path that sets it.
 * Consent is never re-checked here: a rotated session marker existing at all already proves this
 * request's own refresh-token cookie was present and accepted (`refreshSessionTokens` would never
 * have found one to rotate otherwise), so `cookiesAccepted` is unconditionally `true`.
 *
 * The session-status/subject/cookie-consent cookies this call ALSO sets (alongside the refresh
 * token) carry `Max-Age=0` here — this recovery path has no fresh access-token expiration to derive
 * their real lifetime from, unlike a normal successful response. Harmless: the very next
 * successful, guard-passing request re-sets all three correctly through the normal
 * `sessionHeadersInterceptor` path; only the refresh-token cookie's own `Max-Age` (derived
 * independently from the token's own `exp`) matters for the client's session to keep working, and
 * that one is always correct here.
 *
 * @example
 * ```ts
 * import { globalErrorHandler, createNotFoundHandler } from '@zanix/space'
 * import { recoverRotatedSessionCookie } from '@zanix/auth'
 *
 * await bootstrapRemoteApp(spaceApp, {
 *   server: {
 *     ssr: {
 *       onError: globalErrorHandler(recoverRotatedSessionCookie(), createNotFoundHandler()),
 *     },
 *   },
 * })
 * ```
 */
export function recoverRotatedSessionCookie(): (
  error: unknown,
) => Response | Promise<Response> | undefined {
  return (error: unknown) => {
    const rotated = getRotatedSessionFromError(error)
    if (!rotated) return undefined

    const response = httpErrorResponse(error)
    const headers = getSessionHeaders({
      cookiesAccepted: true,
      refreshToken: rotated.token,
      type: rotated.type,
      subject: rotated.subject,
      sessionStatus: rotated.status,
    })
    addHeadersToResponse(response, headers)
    return response
  }
}
