// deno-lint-ignore-file no-explicit-any
import { assert, assertEquals, assertMatch, assertThrows } from '@std/assert'
import { OAuth2Connector, type OAuth2ConnectorOptions } from 'modules/connectors/oauth2.ts'

type DummyUserInfo = { id: string; mail: string }

// ------------------------------
// Mock RestClient
// ------------------------------
class MockRestClient {
  public calls: any[] = []

  public http = {
    get: <T>(url: string): T => {
      this.calls.push({ type: 'get', url })

      if (url.includes('userinfo')) {
        return { id: '1', mail: 'dummy@example.com' } as T
      }

      throw new Error('Unexpected GET URL')
    },
  }
}

// ------------------------------
// Concrete dummy implementation
// ------------------------------
class TestOAuth2Connector extends OAuth2Connector<DummyUserInfo> {
  constructor(mock: any, options: OAuth2ConnectorOptions = {}) {
    super({
      authUrl: 'https://dummy.example.com/authorize',
      userInfoUrl: 'https://dummy.example.com/userinfo',
      revokeUrl: 'https://dummy.example.com/revoke',
      defaultScope: 'read:user',
    }, {
      clientId: 'test-client',
      clientSecret: 'test-secret',
      redirectUri: 'https://example.com/callback',
      ...options,
    })
    Deno.env.set('JWT_KEY', 'secret')
    // @ts-ignore private override
    this.http = mock.http
  }

  protected getSubject(user: DummyUserInfo): string {
    return user.mail
  }
}

Deno.test('generateAuthUrl() defaults to response_type=token and no extra params', () => {
  const connector = new TestOAuth2Connector(new MockRestClient())
  const { url } = connector.generateAuthUrl({ state: 'test_state' })

  assertMatch(url, /^https:\/\/dummy\.example\.com\/authorize\?/)
  assertMatch(url, /client_id=test-client/)
  assertMatch(url, /redirect_uri=https%3A%2F%2Fexample\.com%2Fcallback/)
  assertMatch(url, /state=test_state/)
  assertMatch(url, /scope=read%3Auser/)
  assertMatch(url, /response_type=token/)
  assert(!url.includes('include_granted_scopes'))
})

Deno.test('generateAuthUrl() honors a per-instance responseType override', () => {
  const connector = new TestOAuth2Connector(new MockRestClient(), { responseType: 'code' })
  const { url } = connector.generateAuthUrl()

  assertMatch(url, /response_type=code/)
})

Deno.test('a per-instance endpoint override wins over the subclass defaults', () => {
  const connector = new TestOAuth2Connector(new MockRestClient(), {
    authUrl: 'https://override.example.com/authorize',
  })
  const { url } = connector.generateAuthUrl()

  assertMatch(url, /^https:\/\/override\.example\.com\/authorize\?/)
})

Deno.test('getUserInfo() GETs the user-info endpoint and returns user info', async () => {
  const mock = new MockRestClient()
  const connector = new TestOAuth2Connector(mock)

  const user = await connector.getUserInfo('mock_token')

  assertEquals(user.mail, 'dummy@example.com')
  assertEquals(mock.calls.length, 1)
  assertEquals(mock.calls[0].type, 'get')
})

Deno.test('authenticate() uses the subclass getSubject() to build the session', async () => {
  const mock = new MockRestClient()
  const connector = new TestOAuth2Connector(mock)

  const locals: any = {}
  const result = await connector.authenticate({ locals } as any, 'token')

  assert(result.session.accessToken)
  assert(result.session.refreshToken)
  assertEquals(locals.session.subject, 'dummy@example.com')
  assertEquals(result.user.mail, 'dummy@example.com')
})

Deno.test('revokeToken() POSTs to the revoke endpoint and resolves true', async () => {
  const calls: any[] = []
  class RevokeMockRestClient {
    public http = {
      post: <T>(url: string, options: unknown): T => {
        calls.push({ url, options })
        return true as T
      },
    }
  }
  const connector = new TestOAuth2Connector(new RevokeMockRestClient())

  const result = await connector.revokeToken('some-token')

  assert(result)
  assertEquals(calls.length, 1)
  assertMatch(calls[0].url, /revoke/)
})

Deno.test('constructor throws when required OAuth2 properties are missing', () => {
  class IncompleteConnector extends OAuth2Connector<DummyUserInfo> {
    constructor(options: OAuth2ConnectorOptions = {}) {
      super({
        authUrl: 'https://dummy.example.com/authorize',
        userInfoUrl: 'https://dummy.example.com/userinfo',
        revokeUrl: 'https://dummy.example.com/revoke',
        defaultScope: 'read:user',
      }, options)
    }

    protected getSubject(user: DummyUserInfo): string {
      return user.mail
    }
  }

  assertThrows(() => new IncompleteConnector({}))
})
