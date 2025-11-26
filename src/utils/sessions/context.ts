import type { HandlerContext, ScopedContext } from '@zanix/server'
import type { SessionStatus, SessionTypes } from 'typings/sessions.ts'
import type { JWTPayload } from 'typings/jwt.ts'

/**
 * Assigns a session object to the `locals` of the given context.
 *
 * Extracts relevant fields from the provided JWT payload and stores
 * them as a structured session in `context.locals.session`.
 *
 * This allows `authentication` and `header` middlewares to access
 * the session during the lifetime of the request.
 *
 * @param context - The current request context, either a `HandlerContext` or a `ScopedContext`.
 * @param {SessionTypes} options.type - The type of session being created (from `SessionTypes`).
 * @param {JWTPayload} options.payload - The JWT payload containing session information.
 * @param {SessionStatus} [options.status] - The optional session status.
 */
export const defineLocalSession = (
  context: HandlerContext | ScopedContext,
  options: { type: SessionTypes; payload: JWTPayload; status?: SessionStatus },
) => {
  const { type, payload, status } = options
  const { jti, rateLimit: trl, sub: subject, aud, ...rest } = payload

  // Assign a session to the context
  context.locals.session = {
    type,
    id: jti,
    rateLimit: trl,
    scope: typeof aud === 'string' ? [aud] : aud,
    payload: rest,
    subject,
    status,
  }
}
