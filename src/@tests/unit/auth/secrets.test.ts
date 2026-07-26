import { assertEquals, assertThrows } from '@std/assert'
import { HttpError } from '@zanix/errors'
import { getSecretByToken } from 'utils/jwt/secrets.ts'
import { createJWT } from 'utils/jwt/create.ts'

Deno.test('getSecretByToken resolves JWT_KEY when the token header has no kid', async () => {
  Deno.env.set('JWT_KEY', 'my-secret')

  const token = await createJWT({}, 'my-secret')
  const secret = getSecretByToken(token)

  assertEquals(secret, 'my-secret')

  Deno.env.delete('JWT_KEY')
})

Deno.test('getSecretByToken resolves a versioned JWT_KEY_<kid> from the token header', async () => {
  Deno.env.set('JWT_KEY_V1', 'versioned-secret')

  const token = await createJWT({}, 'sign-secret', { keyID: 'V1' })
  const secret = getSecretByToken(token)

  assertEquals(secret, 'versioned-secret')

  Deno.env.delete('JWT_KEY_V1')
})

Deno.test('getSecretByToken resolves JWK_PUB for non-user session types', async () => {
  Deno.env.set('JWK_PUB', 'public-key')

  const token = await createJWT({}, 'sign-secret')
  const secret = getSecretByToken(token, 'api')

  assertEquals(secret, 'public-key')

  Deno.env.delete('JWK_PUB')
})

Deno.test('getSecretByToken throws when the resolved key is missing', async () => {
  Deno.env.delete('JWT_KEY')

  const token = await createJWT({}, 'sign-secret')

  assertThrows(() => getSecretByToken(token), HttpError)
})
