import type { HandlerContext, Session } from '@zanix/server'
import type { ProxyTrustOptions } from '@zanix/helpers'

import { base64ToUint8Array, generateHash, getClientIp, uint8ArrayToHEX } from '@zanix/helpers'
import { IP_REGEX } from 'utils/constants.ts'
import { InternalError } from '@zanix/errors'

/**
 * Options controlling how {@linkcode getAnonymousSessionId}/{@linkcode generateAnonymousSession}
 * resolve the client identity — exactly `@zanix/helpers`'s shared {@linkcode ProxyTrustOptions}
 * contract, the same one `ipAllowlistGuard`/`RateLimitsOptions` build on for this identical class
 * of decision (declared once in `@zanix/helpers` so the shape can't drift between consumers — see
 * that type's own doc).
 */
export type AnonymousSessionOptions = ProxyTrustOptions

/** The single shared session id every anonymous request resolves to when the caller hasn't
 * explicitly trusted a proxy header (see {@linkcode AnonymousSessionOptions.trustProxyHeader}). */
const UNTRUSTED_ANONYMOUS_SESSION_ID = 'anonymous-shared'

/**
 * Throws unless `trustProxyHeader` was explicitly decided (`true` or `false`) — the single shared
 * enforcement point for the "no silent default" rule this whole `trustProxyHeader` contract
 * depends on. Two distinct call shapes rely on this:
 * - {@linkcode getAnonymousSessionId} calls it itself, on every invocation — the backstop that
 *   covers every caller uniformly (`rateLimitGuard`, `getDefaultSessionHeaders`, and any future
 *   one), so this one check can't be forgotten by a new call site the way it was here.
 * - `rateLimitGuard` ALSO calls it directly, eagerly, before returning its guard closure — so
 *   misconfiguration fails when the guard is built (e.g. as a `@Controller`'s `guards` argument,
 *   at decorator-load time), not silently deferred to the first request that happens to need an
 *   anonymous session. Same check, two call sites, by design — not duplicated logic.
 *
 * @param trustProxyHeader - The value to validate.
 * @param source - The calling function's own name, folded into the thrown error for context.
 * @throws {InternalError} If `trustProxyHeader` is `undefined`.
 */
export function assertTrustProxyHeaderDecided(
  trustProxyHeader: boolean | undefined,
  source: string,
): void {
  if (trustProxyHeader !== undefined) return

  throw new InternalError(
    `Cannot resolve an anonymous session identity in ${source} without an explicit ` +
      'trustProxyHeader decision.',
    {
      code: 'ANONYMOUS_SESSION_TRUST_PROXY_UNDECIDED',
      cause: 'trustProxyHeader was left unset where an anonymous session id needs to be resolved.',
      meta: {
        source: 'zanix',
        method: source,
        reason:
          'trustProxyHeader must be explicitly true (key the id off the resolved client IP — ' +
          'only safe behind a trusted proxy) or false (every anonymous request shares ONE id ' +
          'instead — a deliberate trade-off, not a silent default).',
      },
    },
  )
}

/**
 * Generates a session ID for an anonymous user.
 *
 * With `trustProxyHeader: true`, this creates a unique session ID based on the client's IP
 * address and User-Agent. With `trustProxyHeader: false`, every anonymous request resolves to the
 * SAME id — see {@linkcode AnonymousSessionOptions.trustProxyHeader}. `trustProxyHeader` has no
 * default; omitting it throws (see {@linkcode assertTrustProxyHeaderDecided}).
 *
 * @param headers - The request headers.
 * @param options - See {@linkcode AnonymousSessionOptions}.
 * @throws {InternalError} If `options.trustProxyHeader` isn't explicitly `true` or `false`.
 */
export const getAnonymousSessionId = async (
  headers: HandlerContext['req']['headers'],
  options: AnonymousSessionOptions = {},
) => {
  const { trustProxyHeader, trustedHeaders } = options
  assertTrustProxyHeaderDecided(trustProxyHeader, 'getAnonymousSessionId')

  if (!trustProxyHeader) return UNTRUSTED_ANONYMOUS_SESSION_ID

  // Extract IP from common headers
  let ip = getClientIp(headers, trustedHeaders)

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
 * @param headers - The request headers, typically from the handler context.
 *              Used to extract the client's IP and User-Agent.
 * @param options - See {@linkcode AnonymousSessionOptions}.
 * @returns {Promise<Session>} - A Promise that resolves a `Session` object representing
 *            an anonymous user session with:
 *          - `id`: a hashed identifier derived from IP and User-Agent, prefixed with `anonymous-`
 *            — or the single shared id, when `options.trustProxyHeader` isn't `true`.
 *          - `rateLimit`: the provided request limit
 *          - `type`: always `'anonymous'`
 *
 * @example
 * const session = await generateAnonymousSession(100, req.headers, { trustProxyHeader: true });
 * console.log(session.id); // "anonymous-3f9a1b..."
 * @throws {InternalError} If `options.trustProxyHeader` isn't explicitly `true` or `false` — see
 * {@linkcode getAnonymousSessionId}.
 */
export async function generateAnonymousSession(
  rateLimit: number,
  headers: HandlerContext['req']['headers'],
  options: AnonymousSessionOptions = {},
): Promise<Session> {
  const id = await getAnonymousSessionId(headers, options)

  return {
    id,
    rateLimit,
    type: 'anonymous',
  }
}
