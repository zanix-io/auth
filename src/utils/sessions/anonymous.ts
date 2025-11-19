import type { HandlerContext, Session } from '@zanix/server'

import { base64ToUint8Array, generateHash, uint8ArrayToHEX } from '@zanix/helpers'
import { IP_REGEX } from 'utils/constants.ts'

/**
 * Generates a session ID for an anonymous user.
 *
 * This function creates a unique session ID based on the client's IP address and User-Agent
 *
 * @param req
 * @returns
 */
export const getAnonymousSessionId = async (
  headers: HandlerContext['req']['headers'],
) => {
  // Extract IP from common headers
  let ip = headers.get('x-forwarded-for')?.split(',')[0].trim() ||
    headers.get('cf-connecting-ip') ||
    headers.get('x-real-ip') ||
    'unknown-ip'

  // Optionally validate IP format (simple regex)
  if (!IP_REGEX.test(ip) && ip !== 'unknown-ip') {
    ip = 'invalid-ip'
  }

  // Extract User-Agent, truncated for consistency
  const ua = (headers.get('user-agent') ?? 'unknown-agent').slice(0, 256)

  // Generate a hashed ID for privacy and uniqueness
  const base64Id = await generateHash(`${ip}-${ua}`, 'low', false)

  return `anonymous-${uint8ArrayToHEX(base64ToUint8Array(base64Id))}`
}

/**
 * Generates a session object for an anonymous user.
 *
 * @param rateLimit - The maximum number of allowed requests for this session.
 * @param req - The request object containing headers, typically from the handler context.
 *              Used to extract the client's IP and User-Agent.
 * @returns {Promise<Session>} - A Promise that resolves a `Session` object representing
 *            an anonymous user session with:
 *          - `id`: a unique identifier based on IP and User-Agent
 *          - `rateLimit`: the provided request limit
 *          - `type`: always `'anonymous'`
 *
 * @example
 * const session = generateAnonymousSession(100, req);
 * console.log(session.id); // "123.45.67.89-Mozilla/5.0 ..."
 */
export async function generateAnonymousSession(
  rateLimit: number,
  headers: HandlerContext['req']['headers'],
): Promise<Session> {
  const id = await getAnonymousSessionId(headers)

  return {
    id,
    rateLimit,
    type: 'anonymous',
  }
}
