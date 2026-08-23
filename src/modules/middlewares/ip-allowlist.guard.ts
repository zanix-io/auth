import type { ProxyTrustOptions } from '@zanix/helpers'

import { getClientIp, isIpInCidr } from '@zanix/helpers'
import { httpErrorResponse, type MiddlewareGlobalGuard } from '@zanix/server'
import { HttpError, InternalError } from '@zanix/errors'

/**
 * Env var providing the default IP allowlist for `ipAllowlistGuard` (a comma-separated list of
 * exact IPs and/or IPv4 CIDR ranges) when `options.allow` is omitted.
 */
export const ADMIN_IP_ALLOWLIST_ENV = 'ADMIN_IP_ALLOWLIST'

/**
 * The IP allowlist configuration options. `trustProxyHeader`/`trustedHeaders` are `@zanix/helpers`'s
 * shared {@linkcode ProxyTrustOptions} contract — see that type's own doc for the general shape;
 * this guard's own doc on `trustProxyHeader` below covers what "not trusted" resolves to HERE
 * specifically (a construction-time throw, not a silent pass-through).
 */
export interface IpAllowlistOptions extends ProxyTrustOptions {
  /**
   * Exact IPs or IPv4 CIDR ranges allowed to access the resource (e.g. `['10.0.0.1', '10.0.0.0/8']`).
   * If omitted, falls back to the `ADMIN_IP_ALLOWLIST` environment variable (comma-separated).
   * If neither is set, the guard is a pass-through — it does not restrict anything.
   */
  allow?: string[]
  // Redeclares `ProxyTrustOptions.trustProxyHeader` (same `boolean | undefined` type — this does
  // NOT change what's accepted) purely so hovering it on `IpAllowlistOptions` specifically shows
  // THIS doc instead of `ProxyTrustOptions`'s generic one. `trustedHeaders` is deliberately NOT
  // redeclared below: "headers considered trustworthy" means the same thing in every consumer, so
  // the shared doc is already the right one.
  /**
   * Must be explicitly set to `true` to trust the `x-forwarded-for`/`cf-connecting-ip`/`x-real-ip`
   * headers used to resolve the client IP. Since these headers can be spoofed by the client unless
   * your own infrastructure guarantees they're overwritten by a trusted proxy, this guard refuses
   * to silently trust them: if an allowlist is configured (via `allow` or `ADMIN_IP_ALLOWLIST`) and
   * `trustProxyHeader` is not `true`, it throws at construction time instead of at request time.
   */
  trustProxyHeader?: boolean
}

/**
 * Creates and returns a middleware guard that restricts access to a set of allowed IPs/CIDR
 * ranges.
 *
 * This guard can be used in a request-handling pipeline (e.g., an API framework) to reject
 * requests whose resolved client IP does not match any entry in the configured allowlist.
 *
 * ## Allowlist Configuration
 * The allowlist can be provided directly via `options.allow`, or configured with the
 * `ADMIN_IP_ALLOWLIST` environment variable (a comma-separated list of exact IPs and/or IPv4 CIDR
 * ranges). When neither is set, this guard does not restrict access at all (pass-through).
 *
 * ## Client IP Resolution
 * The client IP is resolved from the incoming request headers, checking (in order):
 * `x-forwarded-for` (first entry), `cf-connecting-ip`, `x-real-ip`. Since these are all
 * client-controllable unless your infrastructure guarantees a trusted proxy overwrites them,
 * `options.trustProxyHeader` must be explicitly `true` whenever an allowlist is configured —
 * otherwise this guard throws an {@link InternalError} at construction time.
 *
 * @param options - The IP allowlist configuration options.
 * @param options.allow - Exact IPs or CIDR ranges allowed to access the resource. Falls back to
 *                        `ADMIN_IP_ALLOWLIST` when omitted.
 * @param options.trustProxyHeader - Must be `true` when an allowlist is configured, acknowledging
 *                        that the client IP is resolved from spoofable headers.
 * @function ipAllowlistGuard
 * @returns {MiddlewareGlobalGuard} A middleware guard instance that restricts requests to the
 *          configured allowlist.
 *
 * @throws {InternalError} If an allowlist is configured but `trustProxyHeader` is not `true`.
 */
export const ipAllowlistGuard = (
  options: IpAllowlistOptions = {},
): MiddlewareGlobalGuard => {
  const { trustProxyHeader = false, trustedHeaders } = options

  const allow = options.allow ?? Deno.env.get(ADMIN_IP_ALLOWLIST_ENV)?.split(',')
    .map((entry) => entry.trim()).filter(Boolean)

  if (allow?.length && !trustProxyHeader) {
    throw new InternalError(
      'Cannot configure ipAllowlistGuard without trusting a proxy header.',
      {
        cause: 'An IP allowlist was configured but `trustProxyHeader` was not set to `true`.',
        meta: {
          source: 'zanix',
          method: 'ipAllowlistGuard',
          reason:
            'The client IP is resolved from spoofable headers (x-forwarded-for, cf-connecting-ip, ' +
            'x-real-ip). Set `trustProxyHeader: true` to explicitly acknowledge this.',
        },
      },
    )
  }

  return (ctx) => {
    if (!allow?.length) return {}

    const { req: { headers } } = ctx
    const ip = getClientIp(headers, trustedHeaders)

    const isAllowed = allow.some((entry) => isIpInCidr(ip, entry))

    if (!isAllowed) {
      const response = httpErrorResponse(
        new HttpError('FORBIDDEN', {
          message: 'Forbidden',
          meta: {
            source: 'zanix',
            method: 'ipAllowlistGuard',
            requestId: ctx.id,
            reason: 'Client IP is not in the configured allowlist.',
          },
        }),
        { contextId: ctx.id },
      )
      return { response }
    }

    return {}
  }
}
