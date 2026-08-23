import { assertEquals, assertMatch } from '@std/assert'
import { randomCode } from 'utils/otp.ts'

/**
 * Regression coverage for a confirmed risk: `randomCode` used to reduce a raw random byte mod 10
 * directly (`byte % 10`) — since `256 % 10 !== 0`, that gives digits 0-5 a 26/256 chance and
 * digits 6-9 only 25/256, a real (if small) skew away from uniform. It now uses rejection
 * sampling (`MAX_UNBIASED_BYTE = 249`, discarding bytes 250-255) instead.
 *
 * `crypto.getRandomValues` is stubbed with fully controlled byte sequences so these assertions are
 * exact and deterministic — never a statistical/flaky check against real randomness.
 */

function withStubbedRandomValues(bytes: number[], fn: () => void) {
  const original = crypto.getRandomValues.bind(crypto)
  let cursor = 0
  crypto.getRandomValues = (<T extends ArrayBufferView | null>(arr: T): T => {
    const view = arr as unknown as Uint8Array
    for (let i = 0; i < view.length; i++) view[i] = bytes[cursor++]
    return arr
  }) as Crypto['getRandomValues']
  try {
    fn()
  } finally {
    crypto.getRandomValues = original
  }
}

Deno.test('randomCode: every digit is 0-9, correct length', () => {
  const code = randomCode(6)
  assertEquals(code.length, 6)
  assertMatch(code, /^[0-9]{6}$/)
})

Deno.test('randomCode: rejects a too-high byte (250-255) instead of reducing it', () => {
  // First byte (250) must be discarded, not turned into digit 0 (250 % 10 === 0) — the next
  // in-range byte (7) is what should actually produce the digit.
  withStubbedRandomValues([250, 7, /* padding for the length+4 batch */ 0, 0, 0], () => {
    assertEquals(randomCode(1), '7')
  })
})

Deno.test('randomCode: rejects every byte 250-255, keeps going until an in-range one', () => {
  withStubbedRandomValues([250, 251, 252, 253, 254, 255, 3], () => {
    assertEquals(randomCode(1), '3')
  })
})

Deno.test('randomCode: draws a fresh batch when the first one is exhausted by rejections', () => {
  // length: 1 draws a batch of 5 (length + 4); all 5 rejected forces a second batch draw.
  withStubbedRandomValues([250, 250, 250, 250, 250, /* 2nd batch, length: 1 */ 8], () => {
    assertEquals(randomCode(1), '8')
  })
})

Deno.test('randomCode: an in-range byte reduces via mod 10 exactly', () => {
  // length: 4 draws a batch of 8 (length + 4); only the first 4 (all in-range, none rejected) are
  // ever actually consumed, so the rest is unused padding.
  withStubbedRandomValues([0, 9, 249, 100, 0, 0, 0, 0], () => {
    assertEquals(
      randomCode(4),
      '0' /* 0 % 10 */ + '9' /* 9 % 10 */ + '9' /* 249 % 10 */ + '0', /* 100 % 10 */
    )
  })
})
