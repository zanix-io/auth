import type { MiddlewarePipe } from '@zanix/server'

import { scopeValidation } from 'utils/scope.ts'
import { HttpError } from '@zanix/errors'

/**
 * Creates a middleware pipe that enforces permission validation on a request.
 *
 * The pipe ensures that `ctx.session` exists and verifies whether the session
 * contains the required permissions (roles, scopes, or capability strings).
 * Access is granted if **at least one** required permission is present in
 * `ctx.session.scope`.
 *
 * The session object is expected to follow the `Session` type:
 *
 * ```ts
 * export type Session = {
 *   id: string
 *   type: SessionTypes
 *   scope?: string[]
 * }
 * ```
 *
 * @param permissions - A list of permissions, roles, or scopes required for the
 *                      request to proceed.
 *
 * @returns A `MiddlewarePipe` that validates permissions and throws an authorization
 *          error if the session does not meet the required access level.
 */
export const permissionsPipe = (
  permissions: string[],
): MiddlewarePipe => {
  const uniquePermissions = new Set(permissions)

  return (ctx) => {
    // `ctx.locals.session` first, `ctx.session` as fallback: `@zanix/server`'s
    // `contextSettingPipe` promotes `locals.session` to the frozen `ctx.session` once, before the
    // pipe stage runs — under `@zanix/auth`'s own guards/handlers today, nothing re-populates
    // `locals.session` before this pipe runs (`defineLocalSession` is only ever called from a
    // guard, which runs pre-promotion, or from handler/interactor code, which runs after this
    // entire pipe stage). Still checked defensively: a consuming app's own custom pipe composed
    // alongside `@RequirePermissions` could call `defineLocalSession` itself, and pipes run
    // concurrently (`Promise.all`) with no ordering guarantee between them — reading
    // `locals.session` first costs nothing and stays correct either way.
    const session = ctx.locals.session ?? ctx.session
    if (!session) {
      throw new HttpError('UNAUTHORIZED', {
        message: 'Access to this resource is not allowed.',
        meta: {
          source: 'zanix',
          method: 'permissionsPipe',
          reason: 'No active user session',
          requestId: ctx.id,
        },
      })
    }

    const validation = scopeValidation(uniquePermissions, new Set(session.scope))

    if (validation !== 'OK') {
      throw new HttpError('FORBIDDEN', {
        message: 'You do not have the required permission to access this resource.',
        cause: validation,
        meta: {
          source: 'zanix',
          method: 'permissionsPipe',
          sessionId: session.id,
          sessionType: session.type,
          requestId: ctx.id,
        },
      })
    }
  }
}
