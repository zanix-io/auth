// deno-lint-ignore-file no-explicit-any
import { assert, assertEquals, assertRejects } from '@std/assert'
import { GoogleOAuth2Connector } from 'modules/connectors/google/mod.ts'
import { ZanixAuthProvider } from 'modules/providers/auth.ts'
import { google } from 'modules/providers/extensions/google.ts'
import { otp } from 'modules/providers/extensions/otp.ts'
import { totp } from 'modules/providers/extensions/totp.ts'
import { session } from 'modules/providers/extensions/session.ts'
import { generateTOTP, generateTOTPSecret } from 'utils/totp.ts'

console.warn = () => {}

Deno.test('ZanixAuthProvider.use() resolves the connector class from authConnectors', () => {
  const calls: unknown[] = []
  const fakeThis: any = {
    getProviderConnector: (connectorClass: unknown, verbose?: boolean) => {
      calls.push([connectorClass, verbose])
      return 'connector-instance'
    },
  }

  const result = (ZanixAuthProvider.prototype as any).use.call(
    fakeThis,
    'google-oauth2',
  )

  assertEquals(result, 'connector-instance')
  assertEquals(calls, [[GoogleOAuth2Connector, false]])
})

Deno.test('google extension delegates its methods to use()', async () => {
  const calls: unknown[] = []
  const fakeThis: any = {
    context: { fake: 'ctx' },
    use: (connector: string) => {
      calls.push(connector)
      return {
        generateAuthUrl: (opts: unknown) => ({
          url: 'mock-url',
          state: 's',
          opts,
        }),
        getUserInfo: (token: string) => ({ email: 'mock@x.com', token }),
        authenticate: (
          ctx: unknown,
          token: string,
          sessionOptions: unknown,
        ) => ({
          user: { email: 'mock@x.com' },
          session: { ctx, token, sessionOptions },
        }),
      }
    },
  }

  const flow = google.call(fakeThis)

  assertEquals((flow.generateAuthUrl({ state: 's' }) as any).opts, {
    state: 's',
  })
  assertEquals((await flow.validateToken('tok') as any).token, 'tok')
  const authResult = await flow.authenticate('tok', {}) as any
  assertEquals(authResult.session, {
    ctx: fakeThis.context,
    token: 'tok',
    sessionOptions: {},
  })
  assertEquals(calls, ['google-oauth2', 'google-oauth2', 'google-oauth2'])
})

function createLocalCacheMock() {
  const store = new Map<string, unknown>()
  return {
    local: {
      get: (key: string) => store.get(key),
      set: (key: string, value: unknown) => {
        store.set(key, value)
      },
      delete: (key: string) => store.delete(key),
    },
  } as any
}

Deno.test('otp extension delegates generate/verify/authenticate to their utils', async () => {
  Deno.env.delete('REDIS_URI')
  Deno.env.set('JWT_KEY', 'my-secret')

  const fakeThis: any = {
    cache: createLocalCacheMock(),
    context: { locals: {} },
  }

  const flow = otp.call(fakeThis)

  const code = await flow.generate({ target: 'user@example.com' })
  assert(code)

  assertEquals(await flow.verify('user@example.com', 'wrong-code'), false)

  const tokens = await flow.authenticate('user@example.com', code, {})
  assert(tokens.accessToken)
  assert(tokens.refreshToken)

  Deno.env.delete('JWT_KEY')
})

Deno.test('otp extension authenticate() throws when the OTP is invalid', async () => {
  Deno.env.delete('REDIS_URI')

  const fakeThis: any = {
    cache: createLocalCacheMock(),
    context: { locals: {} },
  }

  const flow = otp.call(fakeThis)

  await assertRejects(() => flow.authenticate('user@example.com', 'never-generated', {}))
})

Deno.test('totp extension delegates generate/verify/authenticate to their utils', async () => {
  Deno.env.set('JWT_KEY', 'my-secret')

  const fakeThis: any = {
    context: { locals: {} },
  }

  const flow = totp.call(fakeThis)

  const secret = flow.generateSecret()
  assert(secret)

  const uri = flow.getProvisioningUri(secret, 'user@example.com', {
    issuer: 'MyApp',
  })
  assert(uri.startsWith('otpauth://totp/'))

  assertEquals(await flow.verify(secret, 'wrong-code'), false)

  const code = await generateTOTP(secret)
  assertEquals(await flow.verify(secret, code), true)
  const tokens = await flow.authenticate(secret, code, {
    subject: 'user@example.com',
  })
  assert(tokens.accessToken)
  assert(tokens.refreshToken)

  Deno.env.delete('JWT_KEY')
})

Deno.test('totp extension authenticate() throws when the code is invalid', async () => {
  const fakeThis: any = {
    context: { locals: {} },
  }

  const flow = totp.call(fakeThis)
  const secret = generateTOTPSecret()

  await assertRejects(() => flow.authenticate(secret, '000000', { subject: 'user@example.com' }))
})

Deno.test('session extension delegates its methods to sessions utils', async () => {
  Deno.env.set('JWT_KEY', 'my-secret')

  const fakeThis: any = {
    cache: createLocalCacheMock(),
    kvLocal: undefined,
    context: { locals: {} },
  }

  const flow = session.call(fakeThis)

  const tokens = await flow.generateTokens({ subject: 'user@example.com' })
  assert(tokens.accessToken)
  assert(tokens.refreshToken)

  const refreshed = await flow.refreshTokens(tokens.refreshToken)
  assert(refreshed.accessToken)

  const revokeCtx: any = { locals: {} }
  const revokeFlow = session.call({ ...fakeThis, context: revokeCtx })
  const revoked = await revokeFlow.revokeToken(tokens.refreshToken)
  assert(revoked.jti)

  Deno.env.delete('JWT_KEY')
})
