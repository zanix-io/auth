import { defineMiddlewareDecorator, type ZanixGenericDecorator } from '@zanix/server'
import { permissionsPipe } from '../permissions.pipe.ts'

/**
 * A method-level decorator that enforces permission checks on a handler or method.
 *
 * Use this decorator to restrict access to a method based on the required permissions,
 * roles, or scopes. Only sessions with the necessary permissions will be allowed to
 * access the decorated method.
 *
 * This decorator ensures that the `ctx.session` object exists and validates its `scope`
 * property to determine if the current session has the appropriate permissions. If the
 * session does not exist or lacks the required permissions, access is denied.
 *
 * The session object must conform to the following `Session` type:
 *
 * ```ts
 * export type Session = {
 *   id: string
 *   type: SessionTypes
 *   scope?: string[] // Array of permissions, roles, or scopes
 * }
 * ```
 *
 * @see {@link permissionsPipe} for additional context on how permissions are validated.
 *
 * @param permissions - An array of required permissions, roles, or scopes that the session
 *                      must have in order to access the decorated method.
 *
 * @returns A method decorator (`ZanixGenericDecorator`) that applies permission validation
 *          logic to the target method.
 *
 * @example
 * ```ts
 * @RequirePermissions(['admin', 'delete:user'])
 * async function handleRequest(ctx: HandlerContext) {
 *   // Access is granted only if ctx.session.scope includes the specified permissions.
 * }
 * ```
 */
export function RequirePermissions(permissions: string[]): ZanixGenericDecorator {
  return defineMiddlewareDecorator('pipe', permissionsPipe(permissions))
}
