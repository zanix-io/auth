import { assertEquals } from '@std/assert'
import { getRateLimitIdentity } from 'utils/sessions/rate-limit.ts'

Deno.test('getRateLimitIdentity returns the session id by default', () => {
  assertEquals(getRateLimitIdentity({ id: 'jti-1', subject: 'ana' }), 'jti-1')
  assertEquals(getRateLimitIdentity({ id: 'jti-1', subject: 'ana' }, 'session'), 'jti-1')
})

Deno.test('getRateLimitIdentity returns a subject identity for key "subject"', () => {
  assertEquals(getRateLimitIdentity({ id: 'jti-1', subject: 'ana' }, 'subject'), 'subject:ana')
})

Deno.test('getRateLimitIdentity falls back to the session id without a usable subject', () => {
  assertEquals(getRateLimitIdentity({ id: 'jti-1' }, 'subject'), 'jti-1')
  assertEquals(getRateLimitIdentity({ id: 'jti-1', subject: '' }, 'subject'), 'jti-1')
  assertEquals(getRateLimitIdentity({ id: 'jti-1', subject: 42 }, 'subject'), 'jti-1')
})

Deno.test('getRateLimitIdentity never collides a subject with a session id of the same text', () => {
  assertEquals(getRateLimitIdentity({ id: 'ana', subject: 'ana' }, 'subject') !== 'ana', true)
})
