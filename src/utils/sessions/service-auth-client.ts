import { AUTH_HEADERS, RestClient } from '@zanix/server'
import { createServiceAssertion } from './service-exchange.ts'
import type { ServiceCredential } from './service-exchange.ts'

/**
 * Identifies THIS caller's own identity — the same options {@link createServiceAssertion} itself
 * takes, reused as-is rather than a parallel shape that could drift from it.
 */
export interface ServiceAuthClientOptions {
  /** This caller's own registered identity (`iss`/`sub` of every assertion it signs). */
  serviceId: string
  /**
   * This caller's own private key, **base64-encoded**, **PKCS#8 only** (the same convention
   * `JWK_PRI`/`JWK_PUB_<serviceId>` already use — see {@link createServiceAssertion}) — never
   * `@zanix/auth`'s own `JWK_PRI`. **Optional** — omit it to resolve
   * `JWK_PRI_<serviceId>`/`JWK_PRI_<serviceId>_<keyId>` automatically (see
   * {@link createServiceAssertion}'s own doc on this).
   */
  privateKey?: string
  /**
   * Which of this caller's own registered keys to sign with. **Optional** — omit it to resolve
   * `JWK_ID_<serviceId>` automatically (see {@link createServiceAssertion}'s
   * {@link resolveServiceAssertionKeyId}), falling back to `serviceId` itself when that's unset too.
   */
  keyId?: string
  /** How long each signed assertion stays valid. Defaults to `createServiceAssertion`'s own. */
  assertionExpiration?: number | string
  /**
   * Presents this client certificate on the exchange call itself — passed straight through to
   * `RestClient`'s own constructor (`RequestOptions` already extends `RequestInit`, which Deno
   * defines `client` on), so a caller reaching a target behind a genuinely mTLS-enforcing listener
   * (one that requires a client certificate on EVERY connection, including the exchange endpoint,
   * not only the data call after it) can present the SAME certificate for both. Omit entirely for
   * plain HTTP/TLS with no client certificate (the default).
   */
  httpClient?: Deno.HttpClient
}

/** The header(s) to attach to an authenticated outbound request. */
export type ServiceAuthHeaders = Record<string, string>

/** Slack subtracted from a cached token's real expiry before it's treated as stale — avoids a
 * request racing a token that expires mid-flight. */
const EXPIRY_SAFETY_MARGIN_MS = 5_000

/**
 * Builds a reusable, per-target-cached "get me an authenticated header" function for
 * service-to-service calls — the sign → exchange → cache plumbing behind
 * {@link createServiceAssertion}/`exchangeServiceCredential`, factored out so no consuming package
 * has to hand-roll its own token cache.
 *
 * Deliberately generic: the returned function takes a bare `targetServiceId`/`exchangeUrl` pair
 * per call rather than any particular "registered service" shape (a `ServiceRegistry` entry, or
 * anything else a specific consumer might define) — this file has no knowledge of `@zanix/admin`
 * or any other consumer's own types. A package with its own richer "known target" concept (e.g.
 * `@zanix/admin`'s `ServiceRegistryEntry`) should build a thin adapter on top of this rather than
 * this function growing consumer-specific parameters.
 *
 * @param options - This caller's own identity — see {@link ServiceAuthClientOptions}.
 * @returns A function that, given a target's `serviceId` and its own `POST .../admin/service-token`
 * exchange URL, returns `{ 'X-Znx-Authorization': 'Bearer <token>' }` — signing and exchanging a
 * fresh assertion only on a cache miss (nothing cached yet for that target, or the cached token is
 * within {@link EXPIRY_SAFETY_MARGIN_MS} of expiring).
 *
 * @example
 * ```ts
 * // `privateKey` omitted — resolves JWK_PRI_zanix-admin-hub automatically.
 * const auth = createServiceAuthClient({ serviceId: 'zanix-admin-hub' })
 * const headers = await auth('billing', 'http://billing.internal:8000/admin/service-token')
 * // { 'X-Znx-Authorization': 'Bearer ...' }
 * ```
 */
export function createServiceAuthClient(
  options: ServiceAuthClientOptions,
): (
  targetServiceId: string,
  exchangeUrl: string,
) => Promise<ServiceAuthHeaders> {
  const { serviceId, privateKey, keyId, assertionExpiration, httpClient } = options
  const cache = new Map<
    string,
    { headers: ServiceAuthHeaders; expiresAt: number }
  >()
  const client = new RestClient(httpClient ? { client: httpClient } : {})

  return async (targetServiceId, exchangeUrl) => {
    const cached = cache.get(targetServiceId)
    if (cached && cached.expiresAt > Date.now()) return cached.headers

    const assertion = await createServiceAssertion({
      serviceId,
      privateKey,
      keyId,
      expiration: assertionExpiration,
    })

    const { accessToken, expiresIn } = await client.http.post<
      ServiceCredential
    >(exchangeUrl, {
      body: JSON.stringify({ assertion }),
    })

    const headers: ServiceAuthHeaders = {
      [AUTH_HEADERS.api]: `Bearer ${accessToken}`,
    }
    cache.set(targetServiceId, {
      headers,
      expiresAt: Date.now() + expiresIn * 1000 - EXPIRY_SAFETY_MARGIN_MS,
    })

    return headers
  }
}
