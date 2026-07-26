import type { HandlerContext } from '@zanix/server'
import type { SessionStatus, SessionTypes } from 'typings/sessions.ts'

import { getAnonymousSessionId } from './anonymous.ts'
import { GENERAL_HEADERS, SESSION_HEADERS } from 'utils/constants.ts'
import { decodeJWT } from 'utils/jwt/decode.ts'

/** The header dictionary returned by {@link getSessionHeaders} and {@link getDefaultSessionHeaders}. */
export type Headers = { 'Set-Cookie': string[] } & { [key: string]: string }

const { cookiesAcceptedHeader } = GENERAL_HEADERS

/**
 * Generates HTTP headers describing the current session state, with optional
 * cookies when the user has granted cookie consent.
 *
 * Behavior:
 * - Always sets a session status header and a subject header, both determined
 *   by the `type` option (`"user"` or `"api"`).
 * - If `cookiesAccepted` is `true`, also sets `Set-Cookie` entries for the
 *   session status, the subject, and cookie consent itself, each with
 *   `Max-Age=<maxAge>` (cookie lifetime in seconds), `Path=/`, `HttpOnly`,
 *   `SameSite=Strict`. If a `refreshToken` is provided (or `maxAge` is `0`,
 *   to clear it), a refresh-token cookie is set as well — its `Max-Age` is
 *   derived from the refresh token's own `exp` claim, not from `maxAge`.
 * - If `cookiesAccepted` is `false`, no cookies are added.
 *
 * Defaults:
 * - `sessionStatus` defaults to `"unconfirmed"` if not provided.
 * - `maxAge` defaults to `0` (immediately expires the cookie) when `expiration` is omitted.
 *
 * @param {Object} options - Configuration for generating session-related headers.
 * @param {boolean} options.cookiesAccepted - Whether the user has accepted cookies.
 * @param {SessionStatus} [options.sessionStatus='unconfirmed'] - Indicates whether the session is active.
 * @param {string} options.subject - The subject/user identifier included in headers and cookies.
 * @param {'user' | 'api'} options.type - Determines which session and subject headers/cookies to use.
 * @param {number} [options.expiration=0] - The access token's expiration (Unix timestamp), used to compute
 *                                          the `maxAge` (in seconds) for the session status/subject/cookie-consent
 *                                          cookies. When set to `0`, those cookies are issued with `Max-Age=0`,
 *                                          effectively removing them.
 * @param {string} [options.refreshToken] - The refresh token to store in the `user` session's app-token cookie
 *                                          (only applies when `type` is `'user'`). Its own `exp` claim, not
 *                                          `expiration` above, determines that cookie's `Max-Age`.
 *
 * @returns {Headers} A dictionary of HTTP headers containing
 * session metadata and optionally a `Set-Cookie` header.
 */
export function getSessionHeaders(options: {
  sessionStatus?: SessionStatus
  expiration?: number
  refreshToken?: string
  cookiesAccepted: boolean
  subject: string
  type: SessionTypes
}): Headers {
  const {
    cookiesAccepted,
    sessionStatus = 'unconfirmed',
    refreshToken,
    type,
    subject,
    expiration = 0,
  } = options
  const { sub: subjectHeader, session: statusHeader, token: tokenHeader } = SESSION_HEADERS[type]

  const headers = {
    'Set-Cookie': [],
    [statusHeader]: sessionStatus,
    [subjectHeader]: subject,
  } as Headers

  if (cookiesAccepted) {
    const nowInSeconds = Math.floor(Date.now() / 1000) // current Unix timestamp
    const maxAge = Math.max(0, Math.floor(expiration - nowInSeconds))

    const baseCookie = 'Path=/; HttpOnly; SameSite=Strict'
    const baseCookieWithExp = `Max-Age=${maxAge}; ${baseCookie}`

    headers['Set-Cookie'].push(`${statusHeader}=${sessionStatus}; ${baseCookieWithExp}`)
    headers['Set-Cookie'].push(`${subjectHeader}=${subject}; ${baseCookieWithExp}`)
    headers['Set-Cookie'].push(`${cookiesAcceptedHeader}=true; ${baseCookieWithExp}`)

    if (tokenHeader && refreshToken || maxAge === 0) {
      // The refresh-token cookie's lifetime must match the refresh token's OWN expiration
      // (set independently, e.g. '1y' in createRefreshToken), not `maxAge` above — that one
      // tracks the much shorter-lived access token's `exp` and would otherwise expire this
      // cookie long before the refresh token itself stops being valid.
      // `maxAge === 0` signals session invalidation (same as the other cookies above), so it
      // always wins and zeroes this cookie too, regardless of the refresh token's own exp.
      // `!refreshToken` is redundant at runtime (the `if` above guarantees it's set whenever
      // maxAge !== 0), but TypeScript can't infer that across statements — kept for narrowing.
      const refreshTokenMaxAge = maxAge === 0 || !refreshToken ? 0 : Math.max(
        0,
        Math.floor((decodeJWT(refreshToken).payload.exp ?? nowInSeconds) - nowInSeconds),
      )
      headers['Set-Cookie'].push(
        `${tokenHeader}=${refreshToken}; Max-Age=${refreshTokenMaxAge}; ${baseCookie}`,
      )
    }
  }

  return headers
}

/**
 * Generates the default session headers for a given request and session type.
 *
 * This function determines the session "subject" by first attempting to retrieve it
 * from the client (via cookies or headers). If no client subject is found, it falls back
 * to generating an anonymous session ID. The resulting subject, along with other options,
 * is used to generate the full session headers.
 *
 * @param {Object} options - The options for generating the session headers.
 * @param {SessionStatus} [options.sessionStatus] - Optional session status to include in the headers.
 * @param {HandlerContext['req']['headers']} options.headers - The HTTP request headers from which to extract client information.
 * @param {HandlerContext['cookies']} options.cookies - The request cookies.
 * @param {SessionTypes} options.type - The type of session, used to determine the appropriate header/cookie keys.
 * @param {boolean} options.cookiesAccepted - Whether cookies are accepted by the client, affecting header generation.
 * @returns {Promise<Record<string, string>>} A promise that resolves to an object containing the default session headers.
 *
 * @example
 * const headers = await getDefaultSessionHeaders({
 *   headers: request.headers,
 *   type: 'user',
 *   cookiesAccepted: true
 * });
 */
export const getDefaultSessionHeaders = async (options: {
  sessionStatus?: SessionStatus
  headers: HandlerContext['req']['headers']
  cookies: HandlerContext['cookies']
  type: SessionTypes
  cookiesAccepted: boolean
}): Promise<Headers> => {
  const { headers, type, cookiesAccepted, sessionStatus, cookies } = options
  const clientSubject = getClientSubject(headers, cookies, type)
  const baseSubject = clientSubject || await getAnonymousSessionId(headers)
  return getSessionHeaders({ cookiesAccepted, type, sessionStatus, subject: baseSubject })
}

/**
 * Retrieves the "subject" value from the storage client based on the session type.
 *
 * This function checks for the subject in cookies first, and falls back to HTTP headers
 * if the cookie is not present. It is used to identify the client associated with a session.
 *
 * @param {HandlerContext['req']['headers']} headers - The request headers from which to extract the subject.
 * @param {HandlerContext['cookies']} cookies - The request cookies.
 * @param {SessionTypes} type - The type of session, which determines the specific header/cookie key to use.
 * @returns {string | undefined} The subject value from the cookie or header, or `undefined` if not found.
 *
 * @example
 * const subject = getClientSubject(request.headers, 'user')
 */
export const getClientSubject = (
  headers: HandlerContext['req']['headers'],
  cookies: HandlerContext['cookies'],
  type: SessionTypes,
): string | null => {
  const { sub: subjectHeaderKey } = SESSION_HEADERS[type]
  const userCookie = cookies[subjectHeaderKey]
  return userCookie || headers.get(subjectHeaderKey)
}

/**
 * Check If cookies where accepted
 * @param headers
 * @param cookies
 * @returns
 */
export const checkAcceptedCookies = (
  headers: HandlerContext['req']['headers'],
  cookies: HandlerContext['cookies'],
) => {
  const header = headers.get(cookiesAcceptedHeader)

  return header === 'true'
    ? true
    : header === 'false'
    ? false
    : cookies[cookiesAcceptedHeader] === 'true'
}

/**
 * Add headers to response
 * @param response
 * @param headers
 */
export const addHeadersToResponse = (response: Response, headers: Headers) => {
  const { 'Set-Cookie': cookies, ...baseHeaders } = headers

  addCookiesToResponse(response, cookies)
  for (const header of Object.entries(baseHeaders)) {
    response.headers.append(...header)
  }
}

/**
 * Add cookies to response
 * @param response
 * @param cookies
 */
export const addCookiesToResponse = (response: Response, cookies: string[]) => {
  for (const cookie of cookies) {
    response.headers.append('Set-Cookie', cookie)
  }
}
