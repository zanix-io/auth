// deno-lint-ignore-file no-explicit-any
import { assert, assertEquals, assertMatch } from '@std/assert'
import { GoogleOAuth2Connector } from 'modules/connectors/google/mod.ts'

// ------------------------------
// Mock RestClient

// ------------------------------
class MockRestClient {
  public calls: any[] = []

  public http = {
    post: <T>(url: string, opts: any): T => {
      this.calls.push({ type: 'post', url, opts })

      // Mock response for token exchange
      if (url.includes('token')) {
        return {
          access_token: 'mock_access',
          refresh_token: 'mock_refresh',
          id_token: 'mock_id_token',
          expires_in: 3600,
          token_type: 'Bearer',
        } as T
      }

      throw new Error('Unexpected POST URL')
    },

    get: <T>(url: string): T => {
      this.calls.push({ type: 'get', url })

      // Mock response for token info
      if (url.includes('tokeninfo')) {
        return {
          sub: '123456',
          email: 'mock@example.com',
          email_verified: true,
          name: 'Mock User',
          picture: 'http://example.com/pic.jpg',
        } as T
      }

      throw new Error('Unexpected GET URL')
    },
  }
}

// ------------------------------
// Concrete implementation
// ------------------------------
class TestGoogleConnector extends GoogleOAuth2Connector {
  constructor(mock: any) {
    super({
      clientId: 'test-client',
      clientSecret: 'test-secret',
      redirectUri: 'https://example.com/callback',
    })
    Deno.env.set('JWT_KEY', 'secret')
    // Replace RestClient internals with our mock
    // @ts-ignore private override
    this.http = mock.http
  }
}

// ------------------------------
// Tests
// ------------------------------

Deno.test('generateAuthUrl() should include clientId, redirectUri and state', () => {
  const connector = new TestGoogleConnector(new MockRestClient())
  const url = connector.generateAuthUrl('test_state', 'openid email')

  assertMatch(url, /client_id=test-client/)
  assertMatch(url, /redirect_uri=https%3A%2F%2Fexample\.com%2Fcallback/)
  assertMatch(url, /state=test_state/)
  assertMatch(url, /scope=openid\+email/)
  assertMatch(url, /response_type=code/)
})

Deno.test("getTokens() should POST to Google's token endpoint and return tokens", async () => {
  const mock = new MockRestClient()
  const connector = new TestGoogleConnector(mock)

  const tokens = await connector.getTokens('auth_code_123')

  assertEquals(tokens.access_token, 'mock_access')
  assertEquals(tokens.id_token, 'mock_id_token')

  assertEquals(mock.calls.length, 1)
  assertEquals(mock.calls[0].type, 'post')
})

Deno.test('verifyIdToken() should GET tokeninfo and return user info', async () => {
  const mock = new MockRestClient()
  const connector = new TestGoogleConnector(mock)

  const user = await connector.verifyIdToken('mock_id_token')

  assertEquals(user.email, 'mock@example.com')
  assertEquals(user.email_verified, true)

  assertEquals(mock.calls.length, 1)
  assertEquals(mock.calls[0].type, 'get')
})

Deno.test('authenticate() should return tokens and user info', async () => {
  const mock = new MockRestClient()
  const connector = new TestGoogleConnector(mock)

  const locals: any = {}
  const result = await connector.authenticate('auth_code_999', { locals } as any)

  assert(result.sessionTokens.accessToken)
  assert(result.sessionTokens.refreshToken)
  assertEquals(locals.session.type, 'user')
  assertEquals(locals.session.status, 'active')
  assertEquals(locals.session.rateLimit, 100)
  assertEquals(locals.session.subject, 'mock@example.com')
  assert(locals.session.payload.exp)
  assert(locals.session.payload.iss)
  assertEquals(result.tokens.access_token, 'mock_access')
  assertEquals(result.user.email, 'mock@example.com')

  assertEquals(mock.calls.length, 2) // getTokens + verifyIdToken
})
