import { assertEquals, assertFalse } from '@std/assert'
import { getRotatingKey, jwtKeys } from 'utils/jwt/keys-rotation.ts'

// Helper: clean env vars used by these tests
function clearEnv() {
  jwtKeys.JWK_PRI.clear()
  jwtKeys.JWT_KEY.clear()
  const vars = [
    'JWT_KEY',
    'JWK_PRI',
    'JWT_KEY_V1',
    'JWT_KEY_V2',
    'JWT_KEY_V3',
    'JWK_PRI_V1',
    'JWK_PRI_V2',
    'JWK_ROTATION_CYCLE',
  ]
  for (const v of vars) Deno.env.delete(v)
}

Deno.test('getRotatingKey → returns undefined when nothing exists', () => {
  clearEnv()

  const { value } = getRotatingKey('JWT_KEY')
  assertFalse(value)
})

Deno.test('getRotatingKey → selects the unique key', () => {
  clearEnv()
  Deno.env.set('JWT_KEY', 'K1')
  Deno.env.set('JWK_ROTATION_CYCLE', '10') // rotation disabled

  let key = getRotatingKey('JWT_KEY')
  assertFalse(key.version)
  assertEquals(key.value, 'K1')

  // Mock Date.now() to simulate a specific rotation moment
  const realNow = Date.now

  // CYCLE 1
  Date.now = () => 10_000
  key = getRotatingKey('JWT_KEY')
  assertFalse(key.version)
  assertEquals(key.value, 'K1')

  Date.now = () => 20_000
  key = getRotatingKey('JWT_KEY')
  assertFalse(key.version)
  assertEquals(key.value, 'K1')

  Date.now = realNow
})

Deno.test('getRotatingKey → selects versioned key without rotation (cycle = 0)', () => {
  clearEnv()
  Deno.env.set('JWT_KEY_V1', 'K1')
  Deno.env.set('JWT_KEY_V2', 'K2')
  Deno.env.set('JWK_ROTATION_CYCLE', '0') // rotation disabled

  const key = getRotatingKey('JWT_KEY')

  assertEquals(key, { value: 'K1', version: 'V1' })
})

Deno.test('getRotatingKey → selects rotating JWT_KEY based on cycle', () => {
  clearEnv()
  Deno.env.set('JWT_KEY', 'K0') // This value is not used in versioned mode
  Deno.env.set('JWT_KEY_V1', 'K1')
  Deno.env.set('JWT_KEY_V2', 'K2')
  Deno.env.set('JWT_KEY_V3', 'K3')

  // 10-second cycle
  Deno.env.set('JWK_ROTATION_CYCLE', '10')

  // Mock Date.now() to simulate a specific rotation moment
  const realNow = Date.now

  // CYCLE 1
  Date.now = () => 10_000 // → 10000 / 10 = 1000 → 1000 % 3 = 1 → pick K2
  let key = getRotatingKey('JWT_KEY')
  assertEquals(key.version, 'V2')
  assertEquals(key.value, 'K2')

  Date.now = () => 20_000 // → 20000 / 10 = 2000 → 2000 % 3 = 2 → pick K3
  key = getRotatingKey('JWT_KEY')
  assertEquals(key.version, 'V3')
  assertEquals(key.value, 'K3')

  Date.now = () => 30_000 // → 30000 / 10 = 3000 → 3000 % 3 = 0 → pick K1
  key = getRotatingKey('JWT_KEY')
  assertEquals(key.version, 'V1')
  assertEquals(key.value, 'K1')

  // CYCLE 2
  Date.now = () => 40_000 // → 40000 / 10 = 4000 → 4000 % 3 = 1 → pick K2
  key = getRotatingKey('JWT_KEY')
  assertEquals(key.version, 'V2')
  assertEquals(key.value, 'K2')

  Date.now = () => 50_000 // → 50000 / 10 = 5000 → 5000 % 3 = 2 → pick K3
  key = getRotatingKey('JWT_KEY')
  assertEquals(key.version, 'V3')
  assertEquals(key.value, 'K3')

  Date.now = () => 60_000 // → 60000 / 10 = 6000 → 6000 % 3 = 0 → pick K1
  key = getRotatingKey('JWT_KEY')
  assertEquals(key.version, 'V1')
  assertEquals(key.value, 'K1')

  Date.now = realNow // restore
})

Deno.test('getRotatingKey → selects rotating JWT_PRI based on cycle', () => {
  clearEnv()
  Deno.env.set('JWK_PRI_V1', 'K1')
  Deno.env.set('JWK_PRI_V2', 'K2')

  // 10-second cycle
  Deno.env.set('JWK_ROTATION_CYCLE', '10')

  // Mock Date.now() to simulate a specific rotation moment
  const realNow = Date.now

  // CYCLE 1
  Date.now = () => 20_000 // → 10000 / 10 = 2000 → 2000 % 2 = 0 → pick K1
  let key = getRotatingKey('JWK_PRI')
  assertEquals(key.version, 'V1')
  assertEquals(key.value, 'K1')

  Date.now = () => 30_000 // → 10000 / 10 = 3000 → 3000 % 2 = 0 → pick K2
  key = getRotatingKey('JWK_PRI')
  assertEquals(key.version, 'V2')
  assertEquals(key.value, 'K2')

  // CYCLE 2

  Date.now = () => 40_000 // → 40000 / 10 = 4000 → 4000 % 2 = 0 → pick K1
  key = getRotatingKey('JWK_PRI')
  assertEquals(key.version, 'V1')
  assertEquals(key.value, 'K1')

  Date.now = () => 50_000 // → 50000 / 10 = 5000 → 5000 % 2 = 0 → pick K2
  key = getRotatingKey('JWK_PRI')
  assertEquals(key.version, 'V2')
  assertEquals(key.value, 'K2')

  Date.now = realNow // restore
})
