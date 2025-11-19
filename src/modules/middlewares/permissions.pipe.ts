import type { MiddlewarePipe } from '@zanix/server'

import { scopeValidation } from 'utils/scope.ts'
import { HttpError } from '@zanix/errors'

/**
 * Creates a middleware pipe that enforces permission validation on a request.
 *
 * The pipe ensures that `ctx.session` exists and verifies whether the session
 * contains the required permissions (roles, scopes, or capability strings).
 * Access is granted only if **all** required permissions are present in
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
    const { locals: { session } } = ctx
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
