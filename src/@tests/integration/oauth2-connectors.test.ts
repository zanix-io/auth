import { assert, assertEquals } from '@std/assert'
import { assertSpyCalls, type Spy, spy } from '@std/testing/mock'
import { GoogleOAuth2Connector } from 'modules/connectors/google/mod.ts'
import { GitHubOAuth2Connector } from 'modules/connectors/github/mod.ts'

// This file exercises `GoogleOAuth2Connector`/`GitHubOAuth2Connector` through their REAL
// `RestClient` internals — only `globalThis.fetch` is patched (same technique
// `service-auth-client.test.ts` already uses for `createServiceAuthClient`), never `this.http`
// itself. Unlike `google.test.ts`/`github.test.ts` (which replace `this.http` wholesale and so
// never exercise `RestClient`'s own URL-joining/header-merging/body-encoding/response-parsing
// logic), this proves the ACTUAL outbound request each connector builds matches that provider's
// real, documented contract — the exact gap that made `GitHubOAuth2Connector.revokeToken()`'s
// override necessary in the first place (see `auth-oauth2`'s own "Golden rule" note on this).

console.error = () => {}
console.warn = () => {}

Deno.env.set('JWT_KEY', 'secret')

const jsonResponse = (body: unknown, status = 200) =>
  Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    }),
  )

/** Installs a fake `globalThis.fetch`, restoring the original once `fn` settles — mirrors
 * `withFakeFetch` (`notifications/src/@tests/integration/remote-template-backend.test.ts`),
 * adapted to this repo's own `spy()`-based convention (`service-auth-client.test.ts`). */
async function withFakeFetch<T>(
  respond: (url: string, init?: RequestInit) => Response | Promise<Response>,
  fn: (
    mockFetch: Spy<unknown, [url: string, init?: RequestInit], Promise<Response>>,
  ) => Promise<T> | T,
): Promise<T> {
  const original = globalThis.fetch
  const mockFetch = spy((url: string, init?: RequestInit) => Promise.resolve(respond(url, init)))
  globalThis.fetch = mockFetch as unknown as typeof fetch
  try {
    return await fn(mockFetch)
  } finally {
    globalThis.fetch = original
  }
}

Deno.test('Google authenticateWithCode(): real token exchange + user-info round trip', async () => {
  const connector = new GoogleOAuth2Connector({
    clientId: 'g-client',
    clientSecret: 'g-secret',
    redirectUri: 'https://example.com/callback',
    responseType: 'code',
  })

  await withFakeFetch(
    (url) => {
      if (url === 'https://oauth2.googleapis.com/token') {
        return jsonResponse({ access_token: 'real-access-token' })
      }
      if (url === 'https://www.googleapis.com/oauth2/v1/userinfo?alt=json') {
        return jsonResponse({ id: '999', email: 'user@example.com' })
      }
      throw new Error(`Unexpected fetch: ${url}`)
    },
    async (mockFetch) => {
      const { user, session } = await connector.authenticateWithCode(
        // deno-lint-ignore no-explicit-any
        { locals: {} } as any,
        'auth-code-1',
      )

      assertEquals(user.email, 'user@example.com')
      assert(session.accessToken)

      assertSpyCalls(mockFetch, 2)
      const [tokenCall, userInfoCall] = mockFetch.calls

      // The real token-exchange request: form-encoded body, the connector's own credentials.
      assertEquals(tokenCall.args[0], 'https://oauth2.googleapis.com/token')
      const tokenInit = tokenCall.args[1] as RequestInit
      assertEquals(tokenInit.method, 'POST')
      const sentBody = new URLSearchParams(tokenInit.body as string)
      assertEquals(sentBody.get('grant_type'), 'authorization_code')
      assertEquals(sentBody.get('code'), 'auth-code-1')
      assertEquals(sentBody.get('client_id'), 'g-client')
      assertEquals(sentBody.get('client_secret'), 'g-secret')
      assertEquals(sentBody.get('redirect_uri'), 'https://example.com/callback')

      // The real user-info request: the exchanged token as a Bearer header.
      const userInfoInit = userInfoCall.args[1] as RequestInit
      assertEquals(
        (userInfoInit.headers as Record<string, string>)['Authorization'],
        'Bearer real-access-token',
      )
    },
  )
})

Deno.test("Google revokeToken(): real POST, form-encoded 'token', no auth header", async () => {
  const connector = new GoogleOAuth2Connector({
    clientId: 'g-client',
    clientSecret: 'g-secret',
    redirectUri: 'https://example.com/callback',
  })

  await withFakeFetch(
    () => jsonResponse({}),
    async (mockFetch) => {
      const result = await connector.revokeToken('token-to-revoke')

      assert(result)
      assertSpyCalls(mockFetch, 1)
      const [url, init] = mockFetch.calls[0].args as [string, RequestInit]

      assertEquals(url, 'https://oauth2.googleapis.com/revoke')
      assertEquals(init.method, 'POST')
      assertEquals(
        (init.headers as Record<string, string>)['Content-Type'],
        'application/x-www-form-urlencoded',
      )
      assertEquals((init.headers as Record<string, string>)['Authorization'], undefined)
      assertEquals(new URLSearchParams(init.body as string).get('token'), 'token-to-revoke')
    },
  )
})

Deno.test('GitHub authenticateWithCode(): real token exchange + user-info round trip', async () => {
  const connector = new GitHubOAuth2Connector({
    clientId: 'gh-client',
    clientSecret: 'gh-secret',
    redirectUri: 'https://example.com/callback',
  })

  await withFakeFetch(
    (url) => {
      if (url === 'https://github.com/login/oauth/access_token') {
        return jsonResponse({ access_token: 'real-access-token' })
      }
      if (url === 'https://api.github.com/user') {
        return jsonResponse({ id: 42, login: 'octocat', email: 'octocat@example.com' })
      }
      throw new Error(`Unexpected fetch: ${url}`)
    },
    async (mockFetch) => {
      const { user, session } = await connector.authenticateWithCode(
        // deno-lint-ignore no-explicit-any
        { locals: {} } as any,
        'auth-code-1',
      )

      // Confirmed real: GitHub's numeric `id`, not `email` (which can be `null` for a real
      // account) — see `GitHubOAuth2Connector.getSubject()`'s own doc.
      assertEquals(user.id, 42)
      assert(session.accessToken)

      assertSpyCalls(mockFetch, 2)
      const [tokenCall, userInfoCall] = mockFetch.calls

      assertEquals(tokenCall.args[0], 'https://github.com/login/oauth/access_token')
      const tokenInit = tokenCall.args[1] as RequestInit
      assertEquals(tokenInit.method, 'POST')
      // GitHub defaults a form-encoded token response unless `Accept: application/json` is sent —
      // confirm the real request asks for it (see `exchangeCode`'s own doc).
      assertEquals((tokenInit.headers as Record<string, string>)['Accept'], 'application/json')
      const sentBody = new URLSearchParams(tokenInit.body as string)
      assertEquals(sentBody.get('client_id'), 'gh-client')
      assertEquals(sentBody.get('client_secret'), 'gh-secret')

      const userInfoInit = userInfoCall.args[1] as RequestInit
      assertEquals(
        (userInfoInit.headers as Record<string, string>)['Authorization'],
        'Bearer real-access-token',
      )
    },
  )
})

Deno.test("GitHub revokeToken(): real DELETE, Basic auth, JSON 'access_token' body", async () => {
  const connector = new GitHubOAuth2Connector({
    clientId: 'gh-client',
    clientSecret: 'gh-secret',
    redirectUri: 'https://example.com/callback',
  })

  await withFakeFetch(
    () => new Response(null, { status: 204 }),
    async (mockFetch) => {
      const result = await connector.revokeToken('token-to-revoke')

      assert(result)
      assertSpyCalls(mockFetch, 1)
      const [url, init] = mockFetch.calls[0].args as [string, RequestInit]

      // The real, genuinely different contract this connector's `revokeToken` override exists
      // for — see `GitHubOAuth2Connector.revokeToken()`'s own doc.
      assertEquals(url, 'https://api.github.com/applications/gh-client/token')
      assertEquals(init.method, 'DELETE')
      assertEquals(
        (init.headers as Record<string, string>)['Authorization'],
        `Basic ${btoa('gh-client:gh-secret')}`,
      )
      assertEquals((init.headers as Record<string, string>)['Content-Type'], 'application/json')
      assertEquals(JSON.parse(init.body as string), { access_token: 'token-to-revoke' })
    },
  )
})
