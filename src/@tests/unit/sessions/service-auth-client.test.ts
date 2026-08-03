import { assert, assertEquals } from '@std/assert'
import { assertSpyCalls, spy } from '@std/testing/mock'
import { generateRSAKeys } from '@zanix/helpers'
import { createServiceAuthClient } from 'utils/sessions/service-auth-client.ts'
import { decodeJWT } from 'utils/jwt/decode.ts'

console.error = () => {}

const jsonResponse = (body: unknown) =>
  Promise.resolve(
    new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }),
  )

Deno.test({
  name:
    'createServiceAuthClient: signs an assertion for its OWN serviceId and exchanges it, returning X-Znx-Authorization',
  fn: async () => {
    const { privateKey } = await generateRSAKeys()
    let sentBody: unknown

    const mockFetch = spy((_url: string, opts: { body: string }) => {
      sentBody = JSON.parse(opts.body)
      return jsonResponse({ accessToken: 'token-1', expiresIn: 1800, serviceId: 'billing' })
    })
    globalThis.fetch = mockFetch as unknown as typeof fetch

    const auth = createServiceAuthClient({
      serviceId: 'zanix-admin-hub',
      privateKey: btoa(privateKey),
    })
    const headers = await auth('billing', 'http://billing.internal/admin/service-token')

    assertEquals(headers, { 'X-Znx-Authorization': 'Bearer token-1' })
    assertSpyCalls(mockFetch, 1)
    assertEquals(mockFetch.calls[0].args[0], 'http://billing.internal/admin/service-token')

    // The assertion sent identifies THIS caller (the hub), never the target.
    const { payload } = decodeJWT((sentBody as { assertion: string }).assertion)
    assertEquals(payload.iss, 'zanix-admin-hub')
    assertEquals(payload.sub, 'zanix-admin-hub')
  },
})

Deno.test({
  name:
    'createServiceAuthClient: caches per target — a second call for the SAME target does not re-exchange',
  fn: async () => {
    const { privateKey } = await generateRSAKeys()
    const mockFetch = spy(() =>
      jsonResponse({ accessToken: 'cached-token', expiresIn: 1800, serviceId: 'billing' })
    )
    globalThis.fetch = mockFetch as unknown as typeof fetch

    const auth = createServiceAuthClient({
      serviceId: 'zanix-admin-hub',
      privateKey: btoa(privateKey),
    })
    const first = await auth('billing', 'http://billing.internal/admin/service-token')
    const second = await auth('billing', 'http://billing.internal/admin/service-token')

    assertEquals(first, second)
    assertSpyCalls(mockFetch, 1)
  },
})

Deno.test({
  name:
    'createServiceAuthClient: DIFFERENT targets get independent cache entries (and independent exchange calls)',
  fn: async () => {
    const { privateKey } = await generateRSAKeys()
    let call = 0
    const mockFetch = spy(() => {
      call++
      return jsonResponse({ accessToken: `token-${call}`, expiresIn: 1800, serviceId: 'x' })
    })
    globalThis.fetch = mockFetch as unknown as typeof fetch

    const auth = createServiceAuthClient({
      serviceId: 'zanix-admin-hub',
      privateKey: btoa(privateKey),
    })
    const billing = await auth('billing', 'http://billing.internal/admin/service-token')
    const inventory = await auth('inventory', 'http://inventory.internal/admin/service-token')

    assertEquals(billing, { 'X-Znx-Authorization': 'Bearer token-1' })
    assertEquals(inventory, { 'X-Znx-Authorization': 'Bearer token-2' })
    assertSpyCalls(mockFetch, 2)
  },
})

Deno.test({
  name:
    'createServiceAuthClient: re-exchanges once the cached token is within the expiry safety margin',
  fn: async () => {
    const { privateKey } = await generateRSAKeys()
    let call = 0
    const mockFetch = spy(() => {
      call++
      // Expires almost immediately — the 5s safety margin should treat it as already stale.
      return jsonResponse({ accessToken: `token-${call}`, expiresIn: 1, serviceId: 'billing' })
    })
    globalThis.fetch = mockFetch as unknown as typeof fetch

    const auth = createServiceAuthClient({
      serviceId: 'zanix-admin-hub',
      privateKey: btoa(privateKey),
    })
    const first = await auth('billing', 'http://billing.internal/admin/service-token')
    const second = await auth('billing', 'http://billing.internal/admin/service-token')

    assert(
      first !== second || mockFetch.calls.length === 2,
      'a near-expiry token must trigger a fresh exchange',
    )
    assertSpyCalls(mockFetch, 2)
  },
})

Deno.test({
  name: 'createServiceAuthClient: forwards an explicit keyId into the signed assertion',
  fn: async () => {
    const { privateKey } = await generateRSAKeys()
    let sentBody: unknown
    globalThis.fetch = ((_url: string, opts: { body: string }) => {
      sentBody = JSON.parse(opts.body)
      return jsonResponse({ accessToken: 't', expiresIn: 1800, serviceId: 'billing' })
    }) as unknown as typeof fetch

    const auth = createServiceAuthClient({
      serviceId: 'zanix-admin-hub',
      privateKey: btoa(privateKey),
      keyId: 'key2',
    })
    await auth('billing', 'http://billing.internal/admin/service-token')

    const { header } = decodeJWT((sentBody as { assertion: string }).assertion)
    assertEquals(header.kid, 'key2')
  },
})
