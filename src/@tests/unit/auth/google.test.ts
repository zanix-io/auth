// deno-lint-ignore-file no-explicit-any
import { assert, assertEquals, assertMatch, assertThrows } from '@std/assert'
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
  const { url } = connector.generateAuthUrl({
    state: 'test_state',
    scope: 'openid email',
  })

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

Deno.test('revokeToken() POSTs to the Google revoke endpoint and resolves true', async () => {
  const calls: any[] = []
  class RevokeMockRestClient {
    public http = {
      post: <T>(url: string, options: unknown): T => {
        calls.push({ url, options })
        return true as T
      },
    }
  }
  const connector = new TestGoogleConnector(new RevokeMockRestClient())

  const result = await connector.revokeToken('some-token')

  assert(result)
  assertEquals(calls.length, 1)
  assertMatch(calls[0].url, /revoke/)
})

Deno.test('constructor throws when required OAuth2 properties are missing', () => {
  Deno.env.delete('GOOGLE_OAUTH2_CLIENT_ID')
  Deno.env.delete('GOOGLE_OAUTH2_CLIENT_SECRET')
  Deno.env.delete('GOOGLE_OAUTH2_REDIRECT_URI')

  assertThrows(() => new GoogleOAuth2Connector({}))
})

Deno.test('generateAuthUrl() honors a GOOGLE_OAUTH2_AUTH_URL env var override', () => {
  Deno.env.set('GOOGLE_OAUTH2_AUTH_URL', 'https://proxy.example.com/authorize')

  const connector = new TestGoogleConnector(new MockRestClient())
  const { url } = connector.generateAuthUrl()

  assertMatch(url, /^https:\/\/proxy\.example\.com\/authorize\?/)

  Deno.env.delete('GOOGLE_OAUTH2_AUTH_URL')
})

Deno.test('GOOGLE_OAUTH2_RESPONSE_TYPE=code switches to the authorization-code flow', () => {
  Deno.env.set('GOOGLE_OAUTH2_RESPONSE_TYPE', 'code')

  const connector = new TestGoogleConnector(new MockRestClient())
  const { url } = connector.generateAuthUrl()

  assertMatch(url, /response_type=code/)

  Deno.env.delete('GOOGLE_OAUTH2_RESPONSE_TYPE')
})

Deno.test('an invalid GOOGLE_OAUTH2_RESPONSE_TYPE is ignored, default token still applies', () => {
  Deno.env.set('GOOGLE_OAUTH2_RESPONSE_TYPE', 'not-a-real-value')

  const connector = new TestGoogleConnector(new MockRestClient())
  const { url } = connector.generateAuthUrl()

  assertMatch(url, /response_type=token/)

  Deno.env.delete('GOOGLE_OAUTH2_RESPONSE_TYPE')
})

Deno.test('validateCode() exchanges the code, no session built', async () => {
  const calls: any[] = []
  class ExchangeMockRestClient {
    public http = {
      post: <T>(url: string): T => {
        calls.push({ type: 'post', url })
        return { access_token: 'exchanged-google-token' } as T
      },
      get: <T>(url: string): T => {
        calls.push({ type: 'get', url })
        return { id: '123456', email: 'mock@example.com', verified_email: true } as T
      },
    }
  }
  const connector = new TestGoogleConnector(new ExchangeMockRestClient())

  const user = await connector.validateCode('the-auth-code')

  assertEquals(calls.length, 2)
  assertEquals(calls[0].type, 'post')
  assertMatch(calls[0].url, /\/token$/)
  assertEquals(calls[1].type, 'get')
  assertEquals(user.email, 'mock@example.com')
})
