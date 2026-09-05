import type { MiddlewareGlobalGuard, ScopedContext } from '@zanix/server'

import { attachRotatedSessionToError } from 'utils/sessions/rotation-recovery.ts'
import { deriveSessionToken } from 'utils/sessions/derive.ts'
import { permissionsPipe } from './permissions.pipe.ts'

/**
 * Creates and returns a middleware guard that gates a `@zanix/space` page behind an active human
 * session AND at least one of `roles` — pure composition of this package's own exported
 * session/permission primitives ({@link deriveSessionToken}/{@link permissionsPipe}/{@link
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
 *
 * // A high-traffic, low-sensitivity page that would rather never pay a rotation's mint +
 * // blocklist-write cost on this specific path — the session still rotates normally on any
 * // OTHER protected page the same user visits:
 * @Guard(pageSessionGuard(['viewer'], { rotateRefresh: false }))
 * export default class ReadOnlyDashboardPage extends SpacePageController { ... }
 *
 * // A page whose OWN loader forwards the session against a downstream credential exchange that
 * // enforces its own single-use rotation, with no separate "action moment" to hook a one-off call
 * // into — the load itself IS the sensitive operation, every time:
 * @Guard(pageSessionGuard(['admin'], { rotateRefresh: true }))
 * export default class ExternalCredentialRelayPage extends SpacePageController { ... }
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
 * {@link deriveSessionToken} — the cheaper counterpart to this package's own session-lifecycle
 * mechanism, built specifically for this call site: it never signs a real access token (this guard
 * never needed one — only the claims it carries), and it rotates the refresh token itself only
 * once it's old enough to warrant it, not on every single page load. The rotated (or, on most
 * calls, unchanged) refresh-token cookie this leaves on `ctx.locals.session.token` must be written
 * onto the eventual response by a `sessionHeadersInterceptor` the host app registers globally
 * (`import 'jsr:@zanix/auth/core'`) — nothing here writes a cookie by hand.
 *
 * ## Rotation cadence: automatic by default, forceable either way
 *
 * By default (`options.rotateRefresh` omitted), a presented refresh token younger than its own
 * `accessExpiration` (the access-token lifetime chosen when the session was created, defaulting to
 * `'1h'`) is reused as-is — no new token minted, no blocklist write, no new cookie. Only a token at
 * least that old gets a real rotation. In practice, a session actively browsed rotates its refresh
 * token roughly once per `accessExpiration` window, not once per page — see
 * {@link deriveSessionToken}'s own doc for the full mechanism. This default is the right choice for
 * almost every page — reach for one of the two overrides below only for a page that genuinely needs
 * a different cadence, never as a default habit:
 *
 * - **`rotateRefresh: false`** forwards straight to that same override on
 *   {@link deriveSessionToken}, forcing reuse even once the token is stale — this guard call never
 *   renews it, though the session still rotates normally the next time any OTHER protected page
 *   (without the override) is loaded; the token only lapses at its own absolute `exp` if NO page
 *   the user ever visits rotates it. Fits a high-traffic, low-sensitivity page that would rather
 *   never pay a rotation's mint + blocklist-write cost on its own path.
 * - **`rotateRefresh: true`** forces a real rotation on EVERY load of this page, even for a token
 *   that's still fresh. For "force a fresh token before a sensitive action" in the common case —
 *   where the sensitive action is a distinct moment separate from any page load, e.g. a REST
 *   handler a page's own form submits to — a DIRECT, one-off {@link deriveSessionToken}/
 *   {@link mintAccessToken} call made at that exact moment stays the better fit; tagging a whole
 *   recurring page guard as "always rotate" for that case only reintroduces the identical
 *   every-load mint + blocklist-write cost the automatic freshness check exists to avoid, for any
 *   user who happens to reload or revisit the page, with no real security benefit over letting the
 *   freshness check decide. This override earns its place on a page whose OWN loader IS the
 *   sensitive operation on every single load, with no separate action moment to hook a one-off call
 *   into instead — a loader that forwards the session against a downstream credential exchange
 *   enforcing its own single-use rotation is the concrete case: every visit needs the freshest
 *   token this guard can hand it, not just the one from the last rotation window.
 *
 * **The host app must have a `'cache'` core-provider slot registered** (`ctx.providers.get('cache')`
 * below) before this guard runs — any provider works; this guard is agnostic to which one. Without
 * one, `deriveSessionToken` still works but with no durable, single-use rotation (see this
 * package's own `block-list.ts` doc for the in-process fallback and its trade-off).
 *
 * ## `ctx` cast — a genuine, confirmed type-boundary gap, not a shortcut
 *
 * `deriveSessionToken` only accepts this package's own `ScopedContext` (`payload` as callable
 * accessors), never `GuardContext`/`HandlerContext` (`payload` as plain data) — a real structural
 * mismatch, not just a missing overload: `@zanix/server` only ever converts one into the other at
 * PIPE stage (`contextSettingPipe`, `processScopedPayload`), which runs AFTER guards, so no real
 * `ScopedContext` exists yet at guard time to pass instead. `deriveSessionToken` never reads
 * `.payload` itself — only `.cookies`/`.locals`, both declared identically on `GuardContext` and
 * `ScopedContext` — so the cast below is safe in practice. This package's own `jwtValidationGuard`
 * sidesteps this the same way, by never going through `ScopedContext` at all inside a guard.
 *
 * - **401** — no session cookie, or an invalid/expired/blocklisted one: `deriveSessionToken`
 *   itself throws `HttpError('UNAUTHORIZED')` for every one of these.
 * - **403** — a real, valid session that carries none of `roles`: `permissionsPipe` (reused as-is)
 *   throws `HttpError('FORBIDDEN')`.
 *
 * **A 403 (or any OTHER guard downstream throwing), on a request that DID rotate, would otherwise
 * drop the rotated cookie it already blocklisted the old one for.** `deriveSessionToken` above
 * always runs to completion (rotating or not) before `requirePermissions` runs — that ordering is
 * unavoidable, since `permissionsPipe` reads the roles/permissions it just resolved onto the
 * session. When `requirePermissions` then throws `FORBIDDEN`, `@zanix/server`'s own guard pipeline
 * short-circuits straight to an error response WITHOUT ever running its global response
 * interceptors — `sessionHeadersInterceptor` never gets a chance to attach the replacement
 * `Set-Cookie` on that response, even though `ctx.locals.session.token` genuinely holds the new one
 * by then. A successful (200) response has no such gap — its rotated cookie always reaches the
 * client; this is specific to a THROW at guard stage. On a request that DIDN'T rotate, the cookie
 * `ctx.locals.session.token` carries is the same one the client already has, so there's nothing to
 * lose — the recovery below still runs, harmlessly, in that case.
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
 * @param options - Options for the guard.
 * @param {boolean} [options.rotateRefresh] - Forces the rotation decision for this specific page
 * instead of the automatic freshness check — see the "Rotation cadence" section above for when
 * each direction actually earns its place: `false` for a page that should never pay a rotation's
 * cost, `true` only for a page whose own load is the sensitive operation with no separate action
 * moment to rotate at instead. Omitted (the default), the automatic freshness check decides.
 */
export function pageSessionGuard(
  roles: string[],
  options: { rotateRefresh?: boolean } = {},
): MiddlewareGlobalGuard {
  const requirePermissions = permissionsPipe(roles)

  return async (ctx) => {
    // `ctx.providers` is read off the ORIGINAL, correctly-typed `GuardContext` — never the
    // `ScopedContext` cast below, which has no reason to redeclare a getter `deriveSessionToken`
    // itself never reads (see this function's own doc: only `.cookies`/`.locals` are shared).
    const cache = ctx.providers.get('cache')
    const scopedCtx = ctx as unknown as ScopedContext
    await deriveSessionToken(scopedCtx, undefined, { cache, rotateRefresh: options.rotateRefresh })
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
