// deno-lint-ignore-file no-explicit-any
import { assert, assertEquals, assertRejects } from '@std/assert'
import { HttpError } from '@zanix/errors'
import { mintAccessToken, mintAccessTokenBase } from 'utils/sessions/mint-access-token.ts'
import { createAppToken, generateSessionTokens } from 'utils/sessions/create.ts'
import { decodeJWT } from 'utils/jwt/decode.ts'
import { CACHE_KEYS } from 'utils/constants.ts'

console.warn = () => {}

function createCtx() {
  return { locals: {}, cookies: {} } as any
}

async function mintRefreshToken(permissions?: string[], id?: string) {
  const { refreshToken } = await generateSessionTokens(createCtx(), {
    subject: 'user@example.com',
    permissions,
    id,
    accessExpiration: '30m',
  })
  return refreshToken
}

Deno.test('mintAccessTokenBase throws when there is no refresh token available', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  await assertRejects(
    () => mintAccessTokenBase(createCtx(), undefined),
    HttpError,
  )

  Deno.env.delete('JWT_KEY')
})

Deno.test('mintAccessTokenBase throws FORBIDDEN for a non-refresh token', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  const accessOnlyToken = await createAppToken({
    subject: 'user@example.com',
    type: 'user',
    expiration: '1h',
  })

  await assertRejects(
    () => mintAccessTokenBase(createCtx(), accessOnlyToken),
    HttpError,
  )

  Deno.env.delete('JWT_KEY')
})

Deno.test('mintAccessTokenBase: mints a real access token carrying the embedded claims', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  const refreshToken = await mintRefreshToken(['admin'])
  const ctx = createCtx()

  const result = await mintAccessTokenBase(ctx, refreshToken)

  assert(result.accessToken)
  const { payload } = decodeJWT(result.accessToken)
  assertEquals(payload.sub, 'user@example.com')
  assertEquals(payload.aud, ['admin'])
  assertEquals(ctx.locals.session.scope, ['admin'])
  assertEquals(ctx.locals.session.subject, 'user@example.com')

  Deno.env.delete('JWT_KEY')
})

/**
 * Regression coverage: this call used to build the access-token payload by hand, independently
 * from `generateSessionTokens`/`buildAccessTokenClaims`'s own derivation — and silently dropped
 * `jit` (the `id`/`payload.jit` custom claim) in the process. Both now share
 * `toAccessTokenPayload`, so a session minted with a custom `id` carries it through here too.
 */
Deno.test('mintAccessTokenBase: carries the session id (jit) through, same as a fresh mint would', async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  const refreshToken = await mintRefreshToken(['admin'], 'custom-session-id')
  const { accessToken } = await mintAccessTokenBase(createCtx(), refreshToken)

  const { payload } = decodeJWT(accessToken)
  assertEquals(payload.jit, 'custom-session-id')

  Deno.env.delete('JWT_KEY')
})

Deno.test("mintAccessTokenBase: respects the session's own accessExpiration", async () => {
  Deno.env.set('JWT_KEY', 'my secret')

  const refreshToken = await mintRefreshToken(['admin'])
  const { accessToken } = await mintAccessTokenBase(createCtx(), refreshToken)

  const { payload } = decodeJWT(accessToken)
  assert(payload.exp)
  assert(payload.iat)
  assertEquals(payload.exp - payload.iat, 1800) // '30m'

  Deno.env.delete('JWT_KEY')
})

Deno.test(
  'mintAccessTokenBase: never rotates or blocklists the refresh token — the same token can be ' +
    'used again right after',
  async () => {
    Deno.env.set('JWT_KEY', 'my secret')

    const refreshToken = await mintRefreshToken(['admin'])
    const blocklisted = new Map<string, unknown>()
    const cache = {
      local: {
        get: (key: string) => blocklisted.get(key),
        set: (key: string, value: unknown) => blocklisted.set(key, value),
      },
    } as any

    const first = await mintAccessTokenBase(createCtx(), refreshToken, { cache })
    assert(first.accessToken)

    // The SAME refresh token, presented again right after — must succeed again, never rejected as
    // blocklisted, since minting an access token here never touches the refresh token at all.
    const second = await mintAccessTokenBase(createCtx(), refreshToken, { cache })
    assert(second.accessToken)
    assertEquals(blocklisted.size, 0)

    Deno.env.delete('JWT_KEY')
  },
)

Deno.test(
  "mintAccessTokenBase: a token already in another rotation's grace window returns that real " +
    'access token as-is, without minting a redundant one',
  async () => {
    Deno.env.set('JWT_KEY', 'my secret')

    const refreshToken = await mintRefreshToken(['admin'])
    const alreadyIssuedAccessToken = await createAppToken({
      subject: 'user@example.com',
      type: 'user',
      expiration: '30m',
    })

    const store = new Map<string, unknown>()
    store.set(`${CACHE_KEYS.jwtBlockList}:${decodeJWT(refreshToken).payload.jti}`, true)
    store.set(`${CACHE_KEYS.jwtRotationGrace}:${decodeJWT(refreshToken).payload.jti}`, {
      accessToken: alreadyIssuedAccessToken,
      refreshToken: 'rotated-refresh-token',
    })
    const cache = {
      local: {
        get: (key: string) => store.get(key),
        set: (key: string, value: unknown) => store.set(key, value),
      },
    } as any

    const result = await mintAccessTokenBase(createCtx(), refreshToken, { cache })

    assertEquals(result.accessToken, alreadyIssuedAccessToken)

    Deno.env.delete('JWT_KEY')
  },
)

// ── The real, exported entry point: mintAccessToken wraps the Base above ──

Deno.test(
  'mintAccessToken: a blocklisted token with no grace entry rejects with HttpError(UNAUTHORIZED), ' +
    'never a bare PermissionDenied',
  async () => {
    Deno.env.set('JWT_KEY', 'my secret')

    const refreshToken = await mintRefreshToken(['admin'])

    const cache = {
      local: { get: (key: string) => key.includes(CACHE_KEYS.jwtBlockList) ? true : undefined },
    } as any

    const error = await assertRejects(
      () => mintAccessToken(createCtx(), refreshToken, { cache }),
      HttpError,
    )
    assertEquals(error.status.value, 401)

    Deno.env.delete('JWT_KEY')
  },
)
