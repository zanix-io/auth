import type { MiddlewareInterceptor } from '@zanix/server'

import {
  checkAcceptedCookies,
  getClientSubject,
  getSessionHeaders,
} from 'utils/sessions/headers.ts'

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
 * - If `X-Znx-Cookies-Accepted: true` is present (in headers or cookies), session cookies are sent via
 *   `Set-Cookie`:
 *
 *           - X-Znx-App-Token=<sessionToken>; Max-Age=<seconds>; Path=/; HttpOnly; SameSite=Strict
 *           - X-Znx-<type>-Session-Status=<SessionStatus>; Max-Age=<seconds>; Path=/; HttpOnly; SameSite=Strict
 *           - X-Znx-<type>-Id=<sub>; Max-Age=<seconds>; Path=/; HttpOnly; SameSite=Strict
 *           - X-Znx-Cookies-Accepted=true; Max-Age=<seconds>; Path=/; HttpOnly; SameSite=Strict
 *
 * - `Max-Age` is calculated from the session expiration timestamp minus the current Unix time.
 *
 * @returns {MiddlewareInterceptor}
 *   A middleware interceptor function that enriches the response with
 *   session-derived headers.
 */
export const sessionHeadersInterceptor = (): MiddlewareInterceptor => {
  return (ctx, response) => {
    // `ctx.locals.session` first, `ctx.session` as fallback: `@zanix/server`'s
    // `contextSettingPipe` promotes `locals.session` to the frozen `ctx.session` exactly once,
    // during the pipe phase, before this interceptor runs — but that's only the *initial* value.
    // Handler-stage session changes (login/OTP/TOTP/OAuth2 `generateTokens`, `refreshTokens`,
    // `revokeToken`) all go through `defineLocalSession`, which only ever writes
    // `ctx.locals.session` (never `ctx.session`, which stays frozen from the pre-handler
    // promotion). Since this interceptor is global and runs on every response — including the
    // login/refresh/revoke endpoints that mint or invalidate a session mid-request — reading only
    // `ctx.session` would miss that fresher value entirely: a login response would carry no
    // session headers/cookies at all, a refresh response would omit the rotated refresh token, and
    // a revoke/logout response would report the pre-revocation status. `locals.session` is only
    // ever populated again if something set it after the promotion, so checking it first is always
    // safe and always the more current value when present.
    const { req: { headers }, cookies } = ctx
    const session = ctx.locals.session ?? ctx.session
    if (!session?.type) return response

    const cookiesAccepted = checkAcceptedCookies(headers, cookies)

    const { payload, type, subject, status, token } = session
    const authSessionType = type === 'anonymous' ? 'user' : type

    const { 'Set-Cookie': sessionCookies, ...sessionHeaders } = getSessionHeaders({
      subject: subject ||
        getClientSubject(headers, cookies, authSessionType) || session.id,
      expiration: payload?.exp,
      sessionStatus: status,
      type: authSessionType,
      refreshToken: token,
      cookiesAccepted,
    })

    for (const cookie of sessionCookies) {
      response.headers.append('Set-Cookie', cookie)
    }
    for (const header of Object.entries(sessionHeaders)) {
      response.headers.append(...header)
    }

    return response
  }
}
