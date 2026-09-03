import type { MiddlewareGlobalGuard, ScopedContext } from '@zanix/server'

import { attachRotatedSessionToError } from 'utils/sessions/rotation-recovery.ts'
import { refreshSessionTokens } from 'utils/sessions/refresh.ts'
import { permissionsPipe } from './permissions.pipe.ts'

/**
 * Creates and returns a middleware guard that gates a `@zanix/space` page behind an active human
 * session AND at least one of `roles` — pure composition of this package's own exported
 * session/permission primitives ({@link refreshSessionTokens}/{@link permissionsPipe}/{@link
 * attachRotatedSessionToError}), never a parallel "roles" system of its own. Apply as a
 * class-level `@Guard(pageSessionGuard([...]))` on any `SpacePageController` subclass
 * (`@zanix/server`'s `Guard`, `@zanix/space`'s `page-decorator.ts` doc confirms a class-level
 * `@Guard` wires to BOTH `GET`/`POST` for that page) — pass whichever role/permission constants the
 * backend hub exports, in the OR-matched shape `scopeValidation` already applies: at least one of
 * `roles` must be present in the session's `scope` — never ALL of them.
 *
 * @example
 * ```ts
 * import { pageSessionGuard } from 'jsr:@zanix/auth'
 *
 * @Page()
 * @Guard(pageSessionGuard(['admin', 'admin:triggers']))
 * export default class TriggersPage extends SpacePageController { ... }
 * ```
 *
 * ## Why this doesn't reuse `AuthTokenValidation`/`jwtValidationGuard` directly
 *
 * A `@zanix/space` page is server-rendered, browser-navigated HTML — a real `<a>`/full-page `GET`
 * cannot attach a bearer `Authorization` header the way `AuthTokenValidation`/`jwtValidationGuard`
 * expect (that's the SPA-fetch shape, not the no-JS-navigation shape `@zanix/space` targets). A
 * host app's own login flow sets only the `HttpOnly` refresh-token cookie this package already
 * issues (`X-Znx-App-Token`) — there is no access-token cookie anywhere in `@zanix/auth`. So this
 * guard re-derives the session from THAT cookie, per protected page load, via
 * {@link refreshSessionTokens} — the exact mechanism this package's own session-lifecycle test
 * exercises, just invoked here instead of from an explicit `/refresh` endpoint. The rotated
 * refresh-token cookie this leaves on `ctx.locals.session.token` must be written onto the eventual
 * response by a `sessionHeadersInterceptor` the host app registers globally
 * (`import 'jsr:@zanix/auth/core'`) — nothing here writes a cookie by hand.
 *
 * **The host app must have a `'cache'` core-provider slot registered** (`ctx.providers.get('cache')`
 * below) before this guard runs — any provider works; this guard is agnostic to which one. Without
 * one, `refreshSessionTokens` still works but with no durable, single-use rotation (see this
 * package's own `block-list.ts` doc for the in-process fallback and its trade-off).
 *
 * ## `ctx` cast — a genuine, confirmed type-boundary gap, not a shortcut
 *
 * `refreshSessionTokens` only accepts this package's own `ScopedContext` (`payload` as callable
 * accessors), never `GuardContext`/`HandlerContext` (`payload` as plain data) — a real structural
 * mismatch, not just a missing overload: `@zanix/server` only ever converts one into the other at
 * PIPE stage (`contextSettingPipe`, `processScopedPayload`), which runs AFTER guards, so no real
 * `ScopedContext` exists yet at guard time to pass instead. `refreshSessionTokens` never reads
 * `.payload` itself — only `.cookies`/`.locals`, both declared identically on `GuardContext` and
 * `ScopedContext` — so the cast below is safe in practice. This package's own `jwtValidationGuard`
 * sidesteps this the same way, by never going through `ScopedContext` at all inside a guard.
 *
 * - **401** — no session cookie, or an invalid/expired/blocklisted one: `refreshSessionTokens`
 *   itself throws `HttpError('UNAUTHORIZED')` for every one of these.
 * - **403** — a real, valid session that carries none of `roles`: `permissionsPipe` (reused as-is)
 *   throws `HttpError('FORBIDDEN')`.
 *
 * **A 403 (or any OTHER guard downstream throwing) would otherwise drop the rotated cookie it
 * already blocklisted the old one for.** `refreshSessionTokens` above ALWAYS rotates+blocklists
 * before `requirePermissions` runs — that ordering is unavoidable, since `permissionsPipe` reads
 * the roles/permissions the rotation itself just resolved onto the session. When
 * `requirePermissions` then throws `FORBIDDEN`, `@zanix/server`'s own guard pipeline short-circuits
 * straight to an error response WITHOUT ever running its global response interceptors —
 * `sessionHeadersInterceptor` never gets a chance to attach the replacement `Set-Cookie` on that
 * response, even though `ctx.locals.session.token` genuinely holds the new one by then. A
 * successful (200) response has no such gap — its rotated cookie always reaches the client; this
 * is specific to a THROW at guard stage.
 *
 * {@link attachRotatedSessionToError} closes this: the `catch` below marks the caught error with
 * whatever `ctx.locals.session` already holds, then re-throws it unchanged. The host app's own
 * `onError` (`globalErrorHandler(recoverRotatedSessionCookie(), ...)`) reads that marker back and
 * delivers the cookie on the error response itself — the client's next request, even to a page it
 * DOES have access to, gets its real session back instead of a spurious 401. See
 * `docs/configuration.md`'s "Guard-Stage Rotation Recovery" section for the general pattern this
 * guard is the ready-made version of.
 *
 * @param roles - Required roles/permissions, OR-matched (`scopeValidation`) — the session needs AT
 * LEAST ONE of these, never all of them.
 */
export function pageSessionGuard(roles: string[]): MiddlewareGlobalGuard {
  const requirePermissions = permissionsPipe(roles)

  return async (ctx) => {
    // `ctx.providers` is read off the ORIGINAL, correctly-typed `GuardContext` — never the
    // `ScopedContext` cast below, which has no reason to redeclare a getter `refreshSessionTokens`
    // itself never reads (see this function's own doc: only `.cookies`/`.locals` are shared).
    const cache = ctx.providers.get('cache')
    const scopedCtx = ctx as unknown as ScopedContext
    await refreshSessionTokens(scopedCtx, undefined, { cache })
    try {
      await requirePermissions(ctx)
    } catch (error) {
      // See this function's own doc — without this, a 403 here silently strands the client on a
      // now-blocklisted cookie with no replacement ever delivered.
      throw attachRotatedSessionToError(error, scopedCtx)
    }
    return {}
  }
}
