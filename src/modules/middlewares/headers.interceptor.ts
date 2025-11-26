import type { MiddlewareInterceptor } from '@zanix/server'

import { getClientSubject, getSessionHeaders } from 'utils/sessions/headers.ts'
import { GENERAL_HEADERS } from 'utils/constants.ts'

/**
 * Creates a middleware interceptor that attaches session-related headers
 * to the outgoing `Response` object based on the current session state.
 *
 * This interceptor:
 * - Extracts the session metadata (`type`, `status`, `payload`, `subject`)
 * - Determines whether cookies were accepted from the incoming request headers
 * - Normalizes the session type (e.g., `"anonymous"` is treated as `"user"`)
 * - Generates standardized session headers via `getSessionHeaders`
 * - Appends those headers to the outgoing response
 *
 * If no valid session is present, the response is returned unchanged.
 *
 * ### Session Response Headers
 * When a valid session is present:
 *
 * - `x-znx-<type>-session-status:<SessionStatus}>` is added to indicate the session status.
 * - `x-znx-<type>-id` Subject Id header is added when a user token identifier (`sub`) is included.
 * - If `X-Znx-Cookies-Accepted: true` is present, session cookies are sent in the `Set-Cookie` header:
 *   - `x-znx-app-token=<sessionToken>; x-znx-<type>-session-status=<SessionStatus>; x-znx-<type>-id=<sub>; Max-Age=<seconds>; Path=/; HttpOnly; SameSite=Strict`
 * - `Max-Age` is calculated from the session expiration timestamp minus the current Unix time.
 *
 * @returns {MiddlewareInterceptor}
 *   A middleware interceptor function that enriches the response with
 *   session-derived headers.
 */
export const sessionHeadersInterceptor = (): MiddlewareInterceptor => {
  const { cookiesAcceptedHeader } = GENERAL_HEADERS

  return (ctx, response) => {
    const { locals: { session }, req: { headers }, cookies } = ctx
    if (!session?.type) return response

    const cookiesAccepted = headers.get(cookiesAcceptedHeader) === 'true'
    const { payload, type, subject, status, token } = session
    const authSessionType = type === 'anonymous' ? 'user' : type

    const { 'Set-Cookie': sessionCookies, ...sessionHeaders } = getSessionHeaders({
      subject: subject || getClientSubject(headers, cookies, authSessionType) || session.id,
      expiration: payload?.exp,
      sessionStatus: status,
      type: authSessionType,
      refreshToken: token,
      cookiesAccepted,
    })

    for (const cookie of sessionCookies) {
      response.headers.set('Set-Cookie', cookie)
    }
    for (const header of Object.entries(sessionHeaders)) {
      response.headers.append(...header)
    }

    delete ctx.locals.session

    return response
  }
}
