import { assert, assertEquals, assertFalse, assertMatch, assertNotEquals } from '@std/assert'
import { generateTOTP, generateTOTPSecret, getTOTPProvisioningUri, verifyTOTP } from 'utils/totp.ts'
import { base32Decode } from '@zanix/helpers'

// RFC 6238 Appendix B test vector: ASCII secret "12345678901234567890", SHA-1, 8 digits.
// Base32-encoding that ASCII secret ourselves (via generateTOTPSecret's own alphabet) lets us
// verify our HMAC-SHA1 + dynamic-truncation math against the spec's own published values.
const RFC_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' // base32("12345678901234567890")

Deno.test('generateTOTPSecret() returns a unique Base32 string of the expected length', () => {
  const secret = generateTOTPSecret()
  assertMatch(secret, /^[A-Z2-7]+$/)
  assertEquals(secret.length, 32) // 20 bytes -> ceil(20*8/5) = 32 base32 chars, unpadded

  const other = generateTOTPSecret()
  assertNotEquals(secret, other)

  const shortSecret = generateTOTPSecret(10)
  assertEquals(shortSecret.length, 16) // 10 bytes -> 16 base32 chars
})

/**
 * Regression coverage for a confirmed defense: `generateTOTPSecret` fills its bytes with the real
 * `crypto.getRandomValues` Web Crypto CSPRNG — never `Math.random()` or a predictable source.
 * `crypto.getRandomValues` is stubbed with a controlled, deterministic byte sequence; decoding the
 * resulting secret back to bytes (via `base32Decode`, the exact inverse of what
 * `generateTOTPSecret` itself calls) and comparing it to the stubbed bytes proves the secret
 * genuinely derives from whatever the Web Crypto API produced.
 */
Deno.test({
  name: 'generateTOTPSecret() derives its bytes from crypto.getRandomValues, not Math.random',
  fn: () => {
    const stubBytes = Array.from({ length: 20 }, (_, i) => (i * 7) % 256)
    const original = crypto.getRandomValues.bind(crypto)
    crypto.getRandomValues = (<T extends ArrayBufferView | null>(arr: T): T => {
      const view = arr as unknown as Uint8Array
      for (let i = 0; i < view.length; i++) view[i] = stubBytes[i]
      return arr
    }) as Crypto['getRandomValues']

    try {
      const secret = generateTOTPSecret()
      const decoded = Array.from(new Uint8Array(base32Decode(secret)))
      assertEquals(decoded, stubBytes)
    } finally {
      crypto.getRandomValues = original
    }
  },
})

Deno.test('getTOTPProvisioningUri() defaults the issuer to DEFAULT_AUTH_ISSUER', () => {
  const uri = getTOTPProvisioningUri('SECRET123', 'user@example.com')

  assertMatch(uri, /^otpauth:\/\/totp\/zanix-auth:user%40example\.com\?/)
  assertMatch(uri, /secret=SECRET123/)
  assertMatch(uri, /issuer=zanix-auth/)
  assertMatch(uri, /digits=6/)
  assertMatch(uri, /period=30/)
})

Deno.test('getTOTPProvisioningUri() prefixes the label and adds issuer when given', () => {
  const uri = getTOTPProvisioningUri('SECRET123', 'user@example.com', {
    issuer: 'MyApp',
    digits: 8,
    period: 60,
  })

  assertMatch(uri, /^otpauth:\/\/totp\/MyApp:user%40example\.com\?/)
  assertMatch(uri, /issuer=MyApp/)
  assertMatch(uri, /digits=8/)
  assertMatch(uri, /period=60/)
})

Deno.test('generateTOTP() matches the RFC 6238 published test vectors', async () => {
  assertEquals(
    await generateTOTP(RFC_SECRET, { time: 59, digits: 8 }),
    '94287082',
  )
  assertEquals(
    await generateTOTP(RFC_SECRET, { time: 1111111109, digits: 8 }),
    '07081804',
  )
})

Deno.test('generateTOTP() defaults to a 6-digit code (last 6 of the 8-digit vector)', async () => {
  assertEquals(await generateTOTP(RFC_SECRET, { time: 59 }), '287082')
})

Deno.test('verifyTOTP() accepts the current step and rejects a wrong code', async () => {
  const code = await generateTOTP(RFC_SECRET, { time: 59 })

  assert(await verifyTOTP(RFC_SECRET, code, { time: 59 }))
  assertFalse(await verifyTOTP(RFC_SECRET, '000000', { time: 59 }))
  assertFalse(await verifyTOTP(RFC_SECRET, '', { time: 59 }))
})

Deno.test('verifyTOTP() tolerates drift within the default window, rejects beyond it', async () => {
  const code = await generateTOTP(RFC_SECRET, { time: 59 })

  assert(await verifyTOTP(RFC_SECRET, code, { time: 59 + 30 })) // next step
  assert(await verifyTOTP(RFC_SECRET, code, { time: 59 - 30 })) // previous step
  assertFalse(await verifyTOTP(RFC_SECRET, code, { time: 59 + 60 })) // two steps away
})

Deno.test('verifyTOTP() honors a window: 0 override to reject any drift', async () => {
  const code = await generateTOTP(RFC_SECRET, { time: 59 })

  assert(await verifyTOTP(RFC_SECRET, code, { time: 59, window: 0 }))
  assertFalse(await verifyTOTP(RFC_SECRET, code, { time: 59 + 30, window: 0 }))
})
