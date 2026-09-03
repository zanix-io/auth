import type { SessionStatus, SessionTypes } from 'typings/sessions.ts'
import type { AnonymousSessionOptions } from './anonymous.ts'

import { GENERAL_HEADERS, type HandlerContext, SESSION_HEADERS } from '@zanix/server'
import { getAnonymousSessionId } from './anonymous.ts'
import { decodeJWT } from 'utils/jwt/decode.ts'
import { SESSION_COOKIE_ATTRIBUTES } from '@zanix/helpers'

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
 *   `Secure`, `SameSite=Strict`. If a `refreshToken` is provided (or `expiration` is `0`,
 *   to clear it), a refresh-token cookie is set as well, with its own `Max-Age` derived from the
 *   refresh token's own `exp` claim. Whenever a `refreshToken` is given, that same, much longer
 *   `Max-Age` is what the session status/subject/cookie-consent cookies get too — never
 *   `expiration`'s own, much shorter one — so the consent signal that gates this whole function
 *   never expires out from under a session the refresh-token cookie still keeps alive.
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
 * @param {number} [options.expiration=0] - The access token's expiration (Unix timestamp). Used to
 *                                          compute the session status/subject/cookie-consent cookies'
 *                                          `Max-Age` only when no `refreshToken` is given (an `'api'`
 *                                          session, or a `'user'` one issued with no refresh token at
 *                                          all) — see `refreshToken` below otherwise. When set to `0`,
 *                                          every cookie is issued with `Max-Age=0`, clearing all of them
 *                                          regardless of `refreshToken`.
 * @param {string} [options.refreshToken] - The refresh token to store in the `user` session's app-token
 *                                          cookie (only applies when `type` is `'user'`). Its own `exp`
 *                                          claim — not `expiration` above — determines that cookie's
 *                                          `Max-Age`, and the session status/subject/cookie-consent
 *                                          cookies' `Max-Age` as well, so all of them stay alive exactly
 *                                          as long as the session this refresh token represents does.
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
    const accessMaxAge = Math.max(0, Math.floor(expiration - nowInSeconds))

    // `maxAge === 0` signals session invalidation (logout/revoke passes `expiration: 0`), so it
    // always wins and zeroes every cookie below, regardless of the refresh token's own exp.
    // `!refreshToken` is redundant at runtime (the `if` below guarantees it's set whenever
    // `accessMaxAge !== 0`), but TypeScript can't infer that across statements — kept for narrowing.
    const refreshTokenMaxAge = accessMaxAge === 0 || !refreshToken ? 0 : Math.max(
      0,
      Math.floor(
        (decodeJWT(refreshToken).payload.exp ?? nowInSeconds) - nowInSeconds,
      ),
    )

    // The session-status/subject/cookie-consent cookies below must track the REFRESH token's own,
    // much longer lifetime (e.g. '1y', set independently in `createRefreshToken`) whenever one is
    // present — never the much shorter-lived access token's `expiration` above. Tying them to the
    // access token instead would let them expire out from under a still-alive session: once the
    // browser drops the consent cookie, `checkAcceptedCookies` falls back to `false`, and no
    // session `Set-Cookie` — not even a clearing one on a later logout/revoke, nor a rotated
    // refresh token on a later normal refresh — can be emitted again for it, even though the
    // refresh-token cookie itself (`X-Znx-App-Token`) is still very much valid.
    const maxAge = refreshToken ? refreshTokenMaxAge : accessMaxAge

    const baseCookie = SESSION_COOKIE_ATTRIBUTES
    const baseCookieWithExp = `Max-Age=${maxAge}; ${baseCookie}`

    headers['Set-Cookie'].push(
      `${statusHeader}=${sessionStatus}; ${baseCookieWithExp}`,
    )
    headers['Set-Cookie'].push(
      `${subjectHeader}=${subject}; ${baseCookieWithExp}`,
    )
    headers['Set-Cookie'].push(
      `${cookiesAcceptedHeader}=true; ${baseCookieWithExp}`,
    )

    if (tokenHeader && (refreshToken || accessMaxAge === 0)) {
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
 * @param {boolean} [options.trustProxyHeader] - Forwarded to {@link getAnonymousSessionId} for the
 *   fallback-to-anonymous path (when no client subject is found in `cookies`/`headers`) — see that
 *   function's own doc. Only required (no default) when that fallback actually runs; a request that
 *   resolves a real client subject never needs it.
 * @param {string[]} [options.trustedHeaders] - Forwarded to {@link getAnonymousSessionId}, same
 *   fallback path.
 * @returns {Promise<Record<string, string>>} A promise that resolves to an object containing the default session headers.
 *
 * @example
 * const headers = await getDefaultSessionHeaders({
 *   headers: request.headers,
 *   type: 'user',
 *   cookiesAccepted: true,
 *   trustProxyHeader: false,
 * });
 * @throws {InternalError} If no client subject is found (falls back to
 * {@link getAnonymousSessionId}) and `trustProxyHeader` isn't explicitly `true` or `false`.
 */
export const getDefaultSessionHeaders = async (
  options: {
    sessionStatus?: SessionStatus
    headers: HandlerContext['req']['headers']
    cookies: HandlerContext['cookies']
    type: SessionTypes
    cookiesAccepted: boolean
  } & AnonymousSessionOptions,
): Promise<Headers> => {
  const {
    headers,
    type,
    cookiesAccepted,
    sessionStatus,
    cookies,
    trustProxyHeader,
    trustedHeaders,
  } = options
  const clientSubject = getClientSubject(headers, cookies, type)
  const baseSubject = clientSubject ||
    await getAnonymousSessionId(headers, { trustProxyHeader, trustedHeaders })
  return getSessionHeaders({
    cookiesAccepted,
    type,
    sessionStatus,
    subject: baseSubject,
  })
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
