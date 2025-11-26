// deno-lint-ignore-file no-explicit-any
import { assert, assertEquals, assertMatch } from '@std/assert'
import { GoogleOAuth2Connector } from 'modules/connectors/google/mod.ts'

// ------------------------------
// Mock RestClient

// ------------------------------
class MockRestClient {
  public calls: any[] = []

  public http = {
    get: <T>(url: string): T => {
      this.calls.push({ type: 'get', url })

      // Mock response for token info
      if (url.includes('userinfo')) {
        return {
          id: '123456',
          email: 'mock@example.com',
          verified_email: true,
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
  assertMatch(url, /response_type=token/)
})

Deno.test('userInfo() should GET userInfo and return user info', async () => {
  const mock = new MockRestClient()
  const connector = new TestGoogleConnector(mock)

  const user = await connector.getUserInfo('mock_id_token')

  assertEquals(user.email, 'mock@example.com')
  assertEquals(user.verified_email, true)

  assertEquals(mock.calls.length, 1)
  assertEquals(mock.calls[0].type, 'get')
})

Deno.test('authenticate() should return tokens and user info', async () => {
  const mock = new MockRestClient()
  const connector = new TestGoogleConnector(mock)

  const locals: any = {}
  const result = await connector.authenticate({ locals } as any, 'token')

  assert(result.session.accessToken)
  assert(result.session.refreshToken)
  assertEquals(locals.session.type, 'user')
  assertEquals(locals.session.status, 'active')
  assertEquals(locals.session.rateLimit, 100)
  assertEquals(locals.session.subject, 'mock@example.com')
  assert(locals.session.payload.exp)
  assert(locals.session.payload.iss)
  assertEquals(result.user.email, 'mock@example.com')

  assertEquals(mock.calls.length, 1) // userInfo
})
