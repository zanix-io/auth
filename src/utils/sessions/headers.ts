import type { HandlerContext } from '@zanix/server'
import type { SessionStatus, SessionTypes } from 'typings/sessions.ts'

import { getAnonymousSessionId } from './anonymous.ts'
import { SESSION_HEADERS } from '../constants.ts'
import { getCookies } from '@std/http'

/**
 * Generates HTTP headers describing the current session state, with optional
 * cookies when the user has granted cookie consent.
 *
 * Behavior:
 * - Always sets a session validity header and a subject header, both determined
 *   by the `type` option (`"user"` or `"api"`).
 * - If `cookiesAccepted` is `true`, sets a `Set-Cookie` header containing:
 *     - `<type>SessionValid=<sessionValid>`
 *     - A subject cookie name based on the session type
 *     - `Max-Age=<maxAge>` (cookie lifetime in seconds)
 *     - `Path=/`, `HttpOnly`, `SameSite=Strict`
 * - If `cookiesAccepted` is `false`, no cookies are added.
 *
 * Defaults:
 * - `sessionValid` defaults to `"false"` if not provided.
 * - `subject` defaults to `"anonymous"`.
 * - `maxAge` defaults to `0` (immediately expires the cookie).
 *
 * @param {Object} options - Configuration for generating session-related headers.
 * @param {boolean} options.cookiesAccepted - Whether the user has accepted cookies.
 * @param {SessionStatus} [options.sessionStatus='temporal'] - Indicates whether the session is active.
 * @param {string} [options.subject='anonymous'] - The subject/user identifier included in headers and cookies.
 * @param {'user' | 'api'} options.type - Determines which session and subject headers/cookies to use.
 * @param {number} [options.expiration=0] - Token expiration (Unix timestamp) used to compute the cookie’s lifetime in seconds.
 *                                          When set to `0`, the cookie is issued with `Max-Age=0`, effectively removing it.
 *
 * @returns {Record<string, string>} A dictionary of HTTP headers containing
 * session metadata and optionally a `Set-Cookie` header.
 */
export function getSessionHeaders(options: {
  sessionStatus?: SessionStatus
  expiration?: number
  cookiesAccepted: boolean
  subject: string
  type: SessionTypes
}): Record<string, string> {
  const {
    cookiesAccepted,
    sessionStatus = 'unconfirmed',
    type,
    subject,
    expiration = 0,
  } = options
  const { sub: subjectHeader, session: statusHeader } = SESSION_HEADERS[type]

  const headers: Record<string, string> = {
    [statusHeader]: sessionStatus,
    [subjectHeader]: subject,
  }

  if (cookiesAccepted) {
    const nowInSeconds = Math.floor(Date.now() / 1000) // current Unix timestamp
    const maxAge = Math.max(0, Math.floor(expiration - nowInSeconds))
    headers['Set-Cookie'] =
      `${statusHeader}=${sessionStatus}; ${subjectHeader}=${subject}; Max-Age=${maxAge}; Path=/; HttpOnly; SameSite=Strict`
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
  type: SessionTypes
  cookiesAccepted: boolean
}): Promise<Record<string, string>> => {
  const { headers, type, cookiesAccepted, sessionStatus } = options
  const clientSubject = getClientSubject(headers, type)
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
 * @param {SessionTypes} type - The type of session, which determines the specific header/cookie key to use.
 * @returns {string | undefined} The subject value from the cookie or header, or `undefined` if not found.
 *
 * @example
 * const subject = getClientSubject(request.headers, 'user')
 */
export const getClientSubject = (
  headers: HandlerContext['req']['headers'],
  type: SessionTypes,
): string | null => {
  const { sub: subjectHeaderKey } = SESSION_HEADERS[type]
  const userCookie = getCookies(headers)[subjectHeaderKey]
  return userCookie || headers.get(subjectHeaderKey)
}
