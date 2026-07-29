import { assert, assertEquals, assertRejects } from '@std/assert'
import { generateRSAKeys } from '@zanix/helpers'
import { PermissionDenied } from '@zanix/errors'
import {
  createServiceAssertion,
  exchangeServiceCredential,
} from 'utils/sessions/service-exchange.ts'
import { createJWT } from 'utils/jwt/create.ts'
import { decodeJWT } from 'utils/jwt/decode.ts'
import { getSecretByToken } from 'utils/jwt/secrets.ts'
import { SERVICE_EXCHANGE_AUDIENCE } from 'utils/constants.ts'
import { jwtKeys } from 'utils/jwt/keys-rotation.ts'

console.error = () => {}

const SERVICE_ID = 'test-service'

// `exchangeServiceCredential` mints its access token via `createAppToken`, which needs
// `@zanix/auth`'s OWN signing key (JWK_PRI) — distinct from the per-service keys under test here.
// `JWK_PUB` (the matching verification key) is also set so a minted token can be round-tripped
// through `getSecretByToken` within the same test, exactly like a real deployment would.
const withAuthSigningKey = async <T>(fn: () => Promise<T>): Promise<T> => {
  jwtKeys.JWK_PRI.clear()
  const { privateKey, publicKey } = await generateRSAKeys()
  Deno.env.set('JWK_PRI', btoa(privateKey))
  Deno.env.set('JWK_PUB', btoa(publicKey))
  try {
    return await fn()
  } finally {
    Deno.env.delete('JWK_PRI')
    Deno.env.delete('JWK_PUB')
    jwtKeys.JWK_PRI.clear()
  }
}

Deno.test('createServiceAssertion: signs a self-consistent RS256 assertion', async () => {
  const { privateKey } = await generateRSAKeys()

  const assertion = await createServiceAssertion({ serviceId: SERVICE_ID, privateKey })
  const { header, payload } = decodeJWT(assertion)

  assertEquals(header.alg, 'RS256')
  // No explicit `keyId` given: `kid` defaults to `serviceId` — today's single-key convention.
  assertEquals(header.kid, SERVICE_ID)
  assertEquals(payload.iss, SERVICE_ID)
  assertEquals(payload.sub, SERVICE_ID)
  assertEquals(payload.aud, SERVICE_EXCHANGE_AUDIENCE)
})

Deno.test('createServiceAssertion: keyId becomes kid; iss/sub stay serviceId', async () => {
  const { privateKey } = await generateRSAKeys()

  const assertion = await createServiceAssertion({
    serviceId: SERVICE_ID,
    privateKey,
    keyId: 'key2',
  })
  const { header, payload } = decodeJWT(assertion)

  assertEquals(header.kid, 'key2')
  assertEquals(payload.iss, SERVICE_ID)
  assertEquals(payload.sub, SERVICE_ID)
})

Deno.test('exchangeServiceCredential: mints an api token for a valid assertion', async () => {
  await withAuthSigningKey(async () => {
    const { privateKey, publicKey } = await generateRSAKeys()
    Deno.env.set(`JWK_PUB_${SERVICE_ID}`, btoa(publicKey))

    const assertion = await createServiceAssertion({ serviceId: SERVICE_ID, privateKey })
    const credential = await exchangeServiceCredential(assertion)

    assertEquals(credential.serviceId, SERVICE_ID)
    assert(credential.expiresIn > 0)

    const { header, payload } = decodeJWT(credential.accessToken)
    assertEquals(header.alg, 'RS256')
    assertEquals(payload.sub, SERVICE_ID)
    assertEquals(payload.aud, undefined)

    Deno.env.delete(`JWK_PUB_${SERVICE_ID}`)
  })
})

Deno.test('exchangeServiceCredential: grants SERVICE_PERMISSIONS_<id> if set', async () => {
  await withAuthSigningKey(async () => {
    const { privateKey, publicKey } = await generateRSAKeys()
    Deno.env.set(`JWK_PUB_${SERVICE_ID}`, btoa(publicKey))
    Deno.env.set(`SERVICE_PERMISSIONS_${SERVICE_ID}`, ' triggers:read , triggers:write ')

    const assertion = await createServiceAssertion({ serviceId: SERVICE_ID, privateKey })
    const credential = await exchangeServiceCredential(assertion)

    const { payload } = decodeJWT(credential.accessToken)
    assertEquals(payload.aud, ['triggers:read', 'triggers:write'])

    Deno.env.delete(`JWK_PUB_${SERVICE_ID}`)
    Deno.env.delete(`SERVICE_PERMISSIONS_${SERVICE_ID}`)
  })
})

Deno.test('exchangeServiceCredential: defaults rateLimit to 100 (same as user)', async () => {
  await withAuthSigningKey(async () => {
    const { privateKey, publicKey } = await generateRSAKeys()
    Deno.env.set(`JWK_PUB_${SERVICE_ID}`, btoa(publicKey))

    const assertion = await createServiceAssertion({ serviceId: SERVICE_ID, privateKey })
    const credential = await exchangeServiceCredential(assertion)

    const { payload } = decodeJWT(credential.accessToken)
    assertEquals(payload.rateLimit, 100)

    Deno.env.delete(`JWK_PUB_${SERVICE_ID}`)
  })
})

Deno.test('exchangeServiceCredential: grants SERVICE_RATE_LIMIT_<id> when configured', async () => {
  await withAuthSigningKey(async () => {
    const { privateKey, publicKey } = await generateRSAKeys()
    Deno.env.set(`JWK_PUB_${SERVICE_ID}`, btoa(publicKey))
    Deno.env.set(`SERVICE_RATE_LIMIT_${SERVICE_ID}`, '5000')

    const assertion = await createServiceAssertion({ serviceId: SERVICE_ID, privateKey })
    const credential = await exchangeServiceCredential(assertion)

    const { payload } = decodeJWT(credential.accessToken)
    assertEquals(payload.rateLimit, 5000)

    Deno.env.delete(`JWK_PUB_${SERVICE_ID}`)
    Deno.env.delete(`SERVICE_RATE_LIMIT_${SERVICE_ID}`)
  })
})

Deno.test('exchangeServiceCredential: rejects an unregistered service', async () => {
  const { privateKey } = await generateRSAKeys()
  const assertion = await createServiceAssertion({ serviceId: 'unregistered-service', privateKey })

  await assertRejects(() => exchangeServiceCredential(assertion))
})

Deno.test('exchangeServiceCredential: rejects an assertion with no kid header', async () => {
  const { privateKey } = await generateRSAKeys()
  const assertion = await createJWT(
    { iss: SERVICE_ID, sub: SERVICE_ID, aud: SERVICE_EXCHANGE_AUDIENCE },
    privateKey,
    { algorithm: 'RS256' }, // no keyID -> no kid header
  )

  await assertRejects(
    () => exchangeServiceCredential(assertion),
    PermissionDenied,
    'does not identify a valid service',
  )
})

Deno.test('exchangeServiceCredential: rejects when sub does not match iss', async () => {
  const { privateKey } = await generateRSAKeys()
  const assertion = await createJWT(
    { iss: 'someone-else', sub: SERVICE_ID, aud: SERVICE_EXCHANGE_AUDIENCE },
    privateKey,
    { algorithm: 'RS256', keyID: SERVICE_ID },
  )

  await assertRejects(
    () => exchangeServiceCredential(assertion),
    PermissionDenied,
    'does not identify a valid service',
  )
})

Deno.test('exchangeServiceCredential: rejects an assertion signed by the wrong key', async () => {
  const { publicKey } = await generateRSAKeys()
  const { privateKey: wrongPrivateKey } = await generateRSAKeys()
  Deno.env.set(`JWK_PUB_${SERVICE_ID}`, btoa(publicKey))

  const assertion = await createServiceAssertion({
    serviceId: SERVICE_ID,
    privateKey: wrongPrivateKey,
  })

  await assertRejects(() => exchangeServiceCredential(assertion), PermissionDenied)

  Deno.env.delete(`JWK_PUB_${SERVICE_ID}`)
})

Deno.test('exchangeServiceCredential: rejects the wrong audience', async () => {
  const { privateKey, publicKey } = await generateRSAKeys()
  Deno.env.set(`JWK_PUB_${SERVICE_ID}`, btoa(publicKey))

  const assertion = await createJWT(
    { iss: SERVICE_ID, sub: SERVICE_ID, aud: 'some-other-audience' },
    privateKey,
    { algorithm: 'RS256', keyID: SERVICE_ID },
  )

  await assertRejects(() => exchangeServiceCredential(assertion), PermissionDenied)

  Deno.env.delete(`JWK_PUB_${SERVICE_ID}`)
})

Deno.test('exchangeServiceCredential: honors JWK_PRI rotation end to end', async () => {
  // Distinct from `withAuthSigningKey` above (a bare, non-rotating `JWK_PRI`) — this exercises
  // @zanix/auth's OWN key-rotation machinery (`JWK_PRI_V1`) during the mint step, then proves the
  // round trip: the minted token's `kid` must be the rotation version, not `SERVICE_ID`, and
  // `getSecretByToken` must resolve it back to the matching `JWK_PUB_V1` — the exact gap a plain
  // `withAuthSigningKey` test never exercises.
  jwtKeys.JWK_PRI.clear()
  const authKeys = await generateRSAKeys()
  Deno.env.set('JWK_PRI_V1', btoa(authKeys.privateKey))
  Deno.env.set('JWK_PUB_V1', btoa(authKeys.publicKey))

  const { privateKey, publicKey } = await generateRSAKeys()
  Deno.env.set(`JWK_PUB_${SERVICE_ID}`, btoa(publicKey))

  try {
    const assertion = await createServiceAssertion({ serviceId: SERVICE_ID, privateKey })
    const credential = await exchangeServiceCredential(assertion)

    const { header } = decodeJWT(credential.accessToken)
    assertEquals(header.kid, 'V1', "minted token's kid must be the rotation version, not serviceId")

    const resolved = getSecretByToken(credential.accessToken, 'api')
    assertEquals(atob(resolved), authKeys.publicKey, 'must resolve back to the matching JWK_PUB_V1')
  } finally {
    Deno.env.delete(`JWK_PUB_${SERVICE_ID}`)
    Deno.env.delete('JWK_PRI_V1')
    Deno.env.delete('JWK_PUB_V1')
    jwtKeys.JWK_PRI.clear()
  }
})

Deno.test('exchangeServiceCredential: rejects an expired assertion', async () => {
  const { privateKey, publicKey } = await generateRSAKeys()
  Deno.env.set(`JWK_PUB_${SERVICE_ID}`, btoa(publicKey))

  const assertion = await createServiceAssertion({
    serviceId: SERVICE_ID,
    privateKey,
    expiration: '1s',
  })

  const realNow = Date.now
  Date.now = () => realNow() + 2_000
  await assertRejects(() => exchangeServiceCredential(assertion), PermissionDenied)
  Date.now = realNow

  Deno.env.delete(`JWK_PUB_${SERVICE_ID}`)
})

// ── Service-credential key rotation (JWK_PUB_<serviceId>_<keyId>), with overlap support ──

Deno.test('exchangeServiceCredential: rejects an unknown keyId', async () => {
  const { privateKey } = await generateRSAKeys()
  const assertion = await createServiceAssertion({
    serviceId: SERVICE_ID,
    privateKey,
    keyId: 'key1',
  })
  // Nothing registered under JWK_PUB_test-service_key1 at all.
  await assertRejects(() => exchangeServiceCredential(assertion))
})

Deno.test('exchangeServiceCredential: verifies against JWK_PUB_<serviceId>_<keyId>', async () => {
  await withAuthSigningKey(async () => {
    const { privateKey, publicKey } = await generateRSAKeys()
    Deno.env.set(`JWK_PUB_${SERVICE_ID}_key1`, btoa(publicKey))

    const assertion = await createServiceAssertion({
      serviceId: SERVICE_ID,
      privateKey,
      keyId: 'key1',
    })
    const credential = await exchangeServiceCredential(assertion)

    assertEquals(credential.serviceId, SERVICE_ID)

    Deno.env.delete(`JWK_PUB_${SERVICE_ID}_key1`)
  })
})

Deno.test('exchangeServiceCredential: both keys verify during a rotation overlap', async () => {
  await withAuthSigningKey(async () => {
    const oldKeys = await generateRSAKeys()
    const newKeys = await generateRSAKeys()
    // Both registered at once — the actual "overlap window" a real rotation relies on.
    Deno.env.set(`JWK_PUB_${SERVICE_ID}_key1`, btoa(oldKeys.publicKey))
    Deno.env.set(`JWK_PUB_${SERVICE_ID}_key2`, btoa(newKeys.publicKey))

    try {
      // An assertion signed with the OLD key (e.g. already in flight before the switch)...
      const oldAssertion = await createServiceAssertion({
        serviceId: SERVICE_ID,
        privateKey: oldKeys.privateKey,
        keyId: 'key1',
      })
      const oldCredential = await exchangeServiceCredential(oldAssertion)
      assertEquals(oldCredential.serviceId, SERVICE_ID)

      // ...and one signed with the NEW key both succeed, in either order, throughout the window.
      const newAssertion = await createServiceAssertion({
        serviceId: SERVICE_ID,
        privateKey: newKeys.privateKey,
        keyId: 'key2',
      })
      const newCredential = await exchangeServiceCredential(newAssertion)
      assertEquals(newCredential.serviceId, SERVICE_ID)
    } finally {
      Deno.env.delete(`JWK_PUB_${SERVICE_ID}_key1`)
      Deno.env.delete(`JWK_PUB_${SERVICE_ID}_key2`)
    }
  })
})

Deno.test('exchangeServiceCredential: retiring old key rejects it, new key works', async () => {
  await withAuthSigningKey(async () => {
    const oldKeys = await generateRSAKeys()
    const newKeys = await generateRSAKeys()
    Deno.env.set(`JWK_PUB_${SERVICE_ID}_key2`, btoa(newKeys.publicKey))
    // key1 deliberately never registered — simulates retiring it after the overlap window closes.

    const oldAssertion = await createServiceAssertion({
      serviceId: SERVICE_ID,
      privateKey: oldKeys.privateKey,
      keyId: 'key1',
    })
    await assertRejects(() => exchangeServiceCredential(oldAssertion))

    // The new key still works — retiring key1 doesn't disturb key2.
    const newAssertion = await createServiceAssertion({
      serviceId: SERVICE_ID,
      privateKey: newKeys.privateKey,
      keyId: 'key2',
    })
    const credential = await exchangeServiceCredential(newAssertion)
    assertEquals(credential.serviceId, SERVICE_ID)

    Deno.env.delete(`JWK_PUB_${SERVICE_ID}_key2`)
  })
})

Deno.test('exchangeServiceCredential: one key cannot authenticate as another service', async () => {
  const { privateKey, publicKey } = await generateRSAKeys()
  // Registered under "service-a"'s key1...
  Deno.env.set('JWK_PUB_service-a_key1', btoa(publicKey))

  // ...but the assertion claims to be "service-b" (same keyId, different identity). The lookup is
  // scoped by serviceId (from `iss`/`sub`), so this must never resolve to service-a's key.
  const assertion = await createServiceAssertion({
    serviceId: 'service-b',
    privateKey,
    keyId: 'key1',
  })

  await assertRejects(() => exchangeServiceCredential(assertion))

  Deno.env.delete('JWK_PUB_service-a_key1')
})

Deno.test('exchangeServiceCredential: rotating a key leaves minted tokens valid', async () => {
  await withAuthSigningKey(async () => {
    const oldKeys = await generateRSAKeys()
    Deno.env.set(`JWK_PUB_${SERVICE_ID}_key1`, btoa(oldKeys.publicKey))

    const assertion = await createServiceAssertion({
      serviceId: SERVICE_ID,
      privateKey: oldKeys.privateKey,
      keyId: 'key1',
    })
    const credential = await exchangeServiceCredential(assertion)

    // Rotate: key1 is retired entirely (a new key2 takes over, or nothing replaces it at all —
    // either way, key1 is gone).
    Deno.env.delete(`JWK_PUB_${SERVICE_ID}_key1`)

    // The access token minted BEFORE the rotation is untouched by it — it was signed with
    // `@zanix/auth`'s own JWK_PRI, never the service's own key, and still verifies normally.
    const secret = getSecretByToken(credential.accessToken, 'api')
    assert(secret, 'the minted access token must still resolve a verification key after rotation')
    const { payload } = decodeJWT(credential.accessToken)
    assertEquals(payload.sub, SERVICE_ID)
  })
})
