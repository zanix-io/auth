// deno-lint-ignore-file no-explicit-any
import { assert, assertEquals, assertMatch, assertThrows } from '@std/assert'
import { GitHubOAuth2Connector } from 'modules/connectors/github/mod.ts'
import { InternalError } from '@zanix/errors'

// ------------------------------
// Mock RestClient

// ------------------------------
class MockRestClient {
  public calls: any[] = []

  public http = {
    get: <T>(url: string): T => {
      this.calls.push({ type: 'get', url })

      // Mock response for user info
      if (url.includes('/user')) {
        return {
          id: 123456,
          login: 'octocat',
          email: 'mock@example.com',
          name: 'Mock User',
          avatar_url: 'http://example.com/pic.jpg',
        } as T
      }

      throw new Error('Unexpected GET URL')
    },
  }
}

// ------------------------------
// Concrete implementation
// ------------------------------
class TestGitHubConnector extends GitHubOAuth2Connector {
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

console.error = () => {}

// ------------------------------
// Tests
// ------------------------------

Deno.test('generateAuthUrl() includes clientId/redirectUri/state, defaults to code flow', () => {
  const connector = new TestGitHubConnector(new MockRestClient())
  const { url } = connector.generateAuthUrl({
    state: 'test_state',
    scope: 'read:user user:email',
  })

  assertMatch(url, /client_id=test-client/)
  assertMatch(url, /redirect_uri=https%3A%2F%2Fexample\.com%2Fcallback/)
  assertMatch(url, /state=test_state/)
  assertMatch(url, /scope=read%3Auser\+user%3Aemail/)
  assertMatch(url, /response_type=code/)
  assertMatch(url, /^https:\/\/github\.com\/login\/oauth\/authorize\?/)
})

Deno.test('userInfo() should GET userInfo and return user info', async () => {
  const mock = new MockRestClient()
  const connector = new TestGitHubConnector(mock)

  const user = await connector.getUserInfo('mock_id_token')

  assertEquals(user.login, 'octocat')
  assertEquals(user.email, 'mock@example.com')

  assertEquals(mock.calls.length, 1)
  assertEquals(mock.calls[0].type, 'get')
  assertMatch(mock.calls[0].url, /api\.github\.com\/user$/)
})

Deno.test('authenticate() returns tokens and user info, keyed by the numeric id', async () => {
  const mock = new MockRestClient()
  const connector = new TestGitHubConnector(mock)

  const locals: any = {}
  const result = await connector.authenticate({ locals } as any, 'token')

  assert(result.session.accessToken)
  assert(result.session.refreshToken)
  assertEquals(locals.session.type, 'user')
  assertEquals(locals.session.status, 'active')
  assertEquals(locals.session.rateLimit, 100)
  assertEquals(locals.session.subject, '123456')
  assert(locals.session.payload.exp)
  assert(locals.session.payload.iss)
  assertEquals(result.user.login, 'octocat')

  assertEquals(mock.calls.length, 1) // userInfo
})

Deno.test('revokeToken() DELETEs with client_id, Basic auth, JSON body', async () => {
  const calls: any[] = []
  class RevokeMockRestClient {
    public http = {
      delete: <T>(url: string, options: any): T => {
        calls.push({ url, options })
        return undefined as T
      },
    }
  }
  const connector = new TestGitHubConnector(new RevokeMockRestClient())

  const result = await connector.revokeToken('some-token')

  assert(result)
  assertEquals(calls.length, 1)
  assertEquals(calls[0].url, 'https://api.github.com/applications/test-client/token')
  assertEquals(
    calls[0].options.headers['Authorization'],
    `Basic ${btoa('test-client:test-secret')}`,
  )
  assertEquals(calls[0].options.headers['Content-Type'], 'application/json')
  assertEquals(JSON.parse(calls[0].options.body), { access_token: 'some-token' })
})

Deno.test('constructor throws when required OAuth2 properties are missing', () => {
  Deno.env.delete('GITHUB_OAUTH2_CLIENT_ID')
  Deno.env.delete('GITHUB_OAUTH2_CLIENT_SECRET')
  Deno.env.delete('GITHUB_OAUTH2_REDIRECT_URI')

  assertThrows(() => new GitHubOAuth2Connector({}))
})

Deno.test('generateAuthUrl() honors a GITHUB_OAUTH2_AUTH_URL env var override', () => {
  Deno.env.set('GITHUB_OAUTH2_AUTH_URL', 'https://proxy.example.com/authorize')

  const connector = new TestGitHubConnector(new MockRestClient())
  const { url } = connector.generateAuthUrl()

  assertMatch(url, /^https:\/\/proxy\.example\.com\/authorize\?/)

  Deno.env.delete('GITHUB_OAUTH2_AUTH_URL')
})

Deno.test('GITHUB_OAUTH2_RESPONSE_TYPE=token throws at construction with the real authUrl', () => {
  Deno.env.set('GITHUB_OAUTH2_RESPONSE_TYPE', 'token')

  // Specifically `InternalError`, not just any `Error` — locks in the fix that replaced a plain
  // `Error` here (a construction-time config invariant).
  const error = assertThrows(
    () => new TestGitHubConnector(new MockRestClient()),
    InternalError,
    "responseType 'token'",
  )
  assertEquals(error.code, 'GITHUB_OAUTH2_UNSUPPORTED_RESPONSE_TYPE')

  Deno.env.delete('GITHUB_OAUTH2_RESPONSE_TYPE')
})

Deno.test('responseType: token allowed when authUrl is customized (e.g. a proxy)', () => {
  const connector = new GitHubOAuth2Connector({
    clientId: 'test-client',
    clientSecret: 'test-secret',
    redirectUri: 'https://example.com/callback',
    authUrl: 'https://ghe.example.com/login/oauth/authorize',
    responseType: 'token',
  })
  const { url } = connector.generateAuthUrl()

  assertMatch(url, /response_type=token/)
})

Deno.test('an invalid GITHUB_OAUTH2_RESPONSE_TYPE is ignored, default code still applies', () => {
  Deno.env.set('GITHUB_OAUTH2_RESPONSE_TYPE', 'not-a-real-value')

  const connector = new TestGitHubConnector(new MockRestClient())
  const { url } = connector.generateAuthUrl()

  assertMatch(url, /response_type=code/)

  Deno.env.delete('GITHUB_OAUTH2_RESPONSE_TYPE')
})

Deno.test('validateCode() exchanges the code, no session built', async () => {
  const calls: any[] = []
  class ExchangeMockRestClient {
    public http = {
      post: <T>(url: string): T => {
        calls.push({ type: 'post', url })
        return { access_token: 'exchanged-github-token' } as T
      },
      get: <T>(url: string): T => {
        calls.push({ type: 'get', url })
        return { id: 123456, login: 'octocat', email: 'mock@example.com' } as T
      },
    }
  }
  const connector = new TestGitHubConnector(new ExchangeMockRestClient())

  const user = await connector.validateCode('the-auth-code')

  assertEquals(calls.length, 2)
  assertEquals(calls[0].type, 'post')
  assertMatch(calls[0].url, /\/access_token$/)
  assertEquals(calls[1].type, 'get')
  assertEquals(user.login, 'octocat')
})
