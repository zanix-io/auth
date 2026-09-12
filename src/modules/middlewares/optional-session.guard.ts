import type { MiddlewareGlobalGuard, ScopedContext } from '@zanix/server'

import { deriveSessionToken } from 'utils/sessions/derive.ts'

/**
 * Creates a guard that resolves a REAL session onto `ctx.locals.session` when one exists, but
 * never gates the request on it — the opposite failure mode from `pageSessionGuard`, which is the
 * wrong tool for a page that must stay reachable by an anonymous visitor while still rendering
 * differently for one who happens to be logged in (a public landing page with its own "your
 * dashboard" section, say). Apply as a class-level `@Guard(optionalSessionGuard())` on any
 * `SpacePageController` subclass, exactly like `pageSessionGuard`.
 *
 * Pure composition, same as `pageSessionGuard`: reuses {@link deriveSessionToken} as-is — same
 * verification, same automatic rotation cadence, same single-use blocklist guarantee — the only
 * difference is what happens when it fails. `pageSessionGuard` lets that failure become
 * `HttpError('UNAUTHORIZED')`; this one catches it and resolves to "anonymous visitor" instead,
 * leaving `ctx.locals.session` exactly as `@zanix/server`'s own request setup already left it.
 *
 * **This never attaches a rotated session to a later error** the way `pageSessionGuard` does via
 * `attachRotatedSessionToError` — there is no downstream permission check here for a rotation to
 * outlive. A host composing this with some OTHER guard/pipe that runs afterward and CAN throw
 * (reading `ctx.locals.session` itself, say) needs that same recovery — see
 * `attachRotatedSessionToError`'s own doc (`utils/sessions/rotation-recovery.ts`) for the pattern.
 *
 * @param options - Options for the guard.
 * @param {boolean} [options.rotateRefresh] - Same override `pageSessionGuard` exposes — forces the
 * rotation decision instead of the automatic freshness check. Irrelevant when no session was
 * presented at all — there is nothing to rotate.
 *
 * @example
 * ```ts
 * import { optionalSessionGuard } from 'jsr:@zanix/auth'
 *
 * // Public landing page — renders the anonymous view for a visitor with no session, and a
 * // logged-in view for one who has one, never redirecting either way.
 * @Page()
 * @Guard(optionalSessionGuard())
 * export default class HomePage extends SpacePageController {
 *   loader = (ctx) => ({ session: ctx.session })
 *   component = HomeView
 * }
 * ```
 */
export function optionalSessionGuard(
  options: { rotateRefresh?: boolean } = {},
): MiddlewareGlobalGuard {
  return async (ctx) => {
    const cache = ctx.providers.get('cache')
    const scopedCtx = ctx as unknown as ScopedContext
    try {
      await deriveSessionToken(scopedCtx, undefined, {
        cache,
        rotateRefresh: options.rotateRefresh,
      })
    } catch {
      // No session cookie, or an invalid/expired/blocklisted one — resolves to "anonymous
      // visitor" instead of rejecting the request. See this function's own doc for why.
    }
    return {}
  }
}
