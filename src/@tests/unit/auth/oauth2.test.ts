// deno-lint-ignore-file no-explicit-any
import { assert, assertEquals, assertMatch, assertRejects, assertThrows } from '@std/assert'
import { OAuth2Connector, type OAuth2ConnectorOptions } from 'modules/connectors/oauth2.ts'
import { InternalError } from '@zanix/errors'

type DummyUserInfo = { id: string; mail: string }

console.error = () => {}

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
    post: <T>(url: string, options: unknown): T => {
      this.calls.push({ type: 'post', url, options })

      if (url.includes('token')) {
        return { access_token: 'exchanged-token' } as T
      }

      throw new Error('Unexpected POST URL')
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
      tokenUrl: 'https://dummy.example.com/token',
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

/**
 * Regression coverage for a confirmed defense: the default `state` (when the caller doesn't pass
 * one) comes from `generateUUID()` (`@zanix/helpers`, backed by the real `crypto.randomUUID()`
 * Web Crypto CSPRNG) — never `Math.random()` or a predictable source. `crypto.randomUUID` is
 * stubbed with a controlled, deterministic fake so this assertion proves the returned `state`
 * genuinely derives from whatever the Web Crypto API produced, rather than being independently
 * computed.
 */
Deno.test({
  name: 'generateAuthUrl() derives its default state from crypto.randomUUID(), not Math.random',
  fn: () => {
    const connector = new TestOAuth2Connector(new MockRestClient())
    const original = crypto.randomUUID.bind(crypto)
    const fakeUuid = '11111111-2222-4333-8444-555555555555'
    crypto.randomUUID = (() => fakeUuid) as typeof crypto.randomUUID

    try {
      const { state, url } = connector.generateAuthUrl()
      assertEquals(state, fakeUuid)
      assertMatch(url, new RegExp(`state=${fakeUuid}`))
    } finally {
      crypto.randomUUID = original
    }
  },
})

Deno.test('generateAuthUrl() honors a per-instance responseType override', () => {
  const connector = new TestOAuth2Connector(new MockRestClient(), {
    responseType: 'code',
  })
  const { url } = connector.generateAuthUrl()

  assertMatch(url, /response_type=code/)
})

Deno.test('generateAuthUrl() honors a PER-CALL responseType, over the instance default', () => {
  // Same connector, same instance — two different call sites can each request a different flow
  // without needing a second connector or reconstructing anything.
  const connector = new TestOAuth2Connector(new MockRestClient()) // instance default: 'token'

  assertMatch(connector.generateAuthUrl().url, /response_type=token/)
  assertMatch(connector.generateAuthUrl({ responseType: 'code' }).url, /response_type=code/)
  // The instance default still applies on the next call with no override — the per-call
  // override doesn't leak into later calls.
  assertMatch(connector.generateAuthUrl().url, /response_type=token/)
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

// --- authorization-code flow (R2: audience verification) --------------------------------------

/**
 * Regression coverage for a confirmed risk: `authenticate()` (the implicit-flow path) trusts any
 * bearer token it's handed, with no verification that it was issued for THIS app — a token valid
 * for a different OAuth2 app registered with the same provider could be replayed here. This suite
 * proves the fix's actual mechanism: `authenticateWithCode()` never accepts a raw token from the
 * caller at all — it only ever gets a token from `exchangeCode()`'s own POST to `tokenUrl`, made
 * with THIS connector's `clientSecret`.
 */
Deno.test('exchangeCode() POSTs to tokenUrl with client credentials, returns token', async () => {
  const mock = new MockRestClient()
  const connector = new TestOAuth2Connector(mock) as any

  const token = await connector.exchangeCode('the-auth-code')

  assertEquals(token, 'exchanged-token')
  assertEquals(mock.calls.length, 1)
  assertEquals(mock.calls[0].type, 'post')
  assertMatch(mock.calls[0].url, /\/token$/)

  const body = mock.calls[0].options.body as URLSearchParams
  assertEquals(body.get('grant_type'), 'authorization_code')
  assertEquals(body.get('code'), 'the-auth-code')
  assertEquals(body.get('client_id'), 'test-client')
  assertEquals(body.get('client_secret'), 'test-secret')
  assertEquals(body.get('redirect_uri'), 'https://example.com/callback')
  assertEquals(mock.calls[0].options.headers['Accept'], 'application/json')
})

Deno.test('authenticateWithCode() exchanges code, never trusts a raw caller token', async () => {
  const mock = new MockRestClient()
  const connector = new TestOAuth2Connector(mock)

  const locals: any = {}
  const result = await connector.authenticateWithCode({ locals } as any, 'the-auth-code')

  assertEquals(mock.calls[0].type, 'post') // exchange first
  assertMatch(mock.calls[0].url, /\/token$/)
  assertEquals(mock.calls[1].type, 'get') // then userinfo, with the EXCHANGED token
  assertMatch(mock.calls[1].url, /userinfo/)

  assertEquals(result.user.mail, 'dummy@example.com')
  assertEquals(locals.session.subject, 'dummy@example.com')
})

Deno.test('validateCode() exchanges code then returns user info (no session built)', async () => {
  const mock = new MockRestClient()
  const connector = new TestOAuth2Connector(mock)

  const user = await connector.validateCode('the-auth-code')

  assertEquals(mock.calls[0].type, 'post') // exchange first
  assertMatch(mock.calls[0].url, /\/token$/)
  assertEquals(mock.calls[1].type, 'get') // then userinfo, with the EXCHANGED token
  assertMatch(mock.calls[1].url, /userinfo/)
  assertEquals(mock.calls.length, 2) // nothing else — no session, unlike authenticateWithCode

  assertEquals(user.mail, 'dummy@example.com')
})

Deno.test('exchangeCode() throws a clear error when tokenUrl is not configured', async () => {
  class NoTokenUrlConnector extends OAuth2Connector<DummyUserInfo> {
    constructor(mock: any) {
      super({
        authUrl: 'https://dummy.example.com/authorize',
        userInfoUrl: 'https://dummy.example.com/userinfo',
        revokeUrl: 'https://dummy.example.com/revoke',
        defaultScope: 'read:user',
        // no tokenUrl
      }, {
        clientId: 'test-client',
        clientSecret: 'test-secret',
        redirectUri: 'https://example.com/callback',
      })
      // @ts-ignore private override
      this.http = mock.http
    }
    protected getSubject(user: DummyUserInfo): string {
      return user.mail
    }
  }

  const connector = new NoTokenUrlConnector(new MockRestClient()) as any
  // Specifically `InternalError`, not just any `Error` — locks in the fix that replaced a plain
  // `Error` here (a construction-time config invariant, not the flow caller's mistake).
  const error = await assertRejects(
    () => connector.exchangeCode('the-auth-code'),
    InternalError,
    'tokenUrl',
  )
  assertEquals(error.code, 'OAUTH2_TOKEN_URL_NOT_CONFIGURED')
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
