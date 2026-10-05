import { assertEquals } from '@std/assert'
import { missingScopes } from 'utils/scope.ts'

Deno.test('missingScopes returns [] for empty required, whatever is held', () => {
  assertEquals(missingScopes([], []), [])
  assertEquals(missingScopes([], ['read']), [])
  assertEquals(missingScopes([]), [])
})

Deno.test('missingScopes returns every required scope when nothing is held', () => {
  assertEquals(missingScopes(['read', 'write'], []), ['read', 'write'])
  assertEquals(missingScopes(['read', 'write'], undefined), ['read', 'write'])
})

Deno.test('missingScopes returns only the required scopes that are not held', () => {
  assertEquals(missingScopes(['read', 'write'], ['read', 'admin']), ['write'])
  assertEquals(missingScopes(['read'], ['read']), [])
})

Deno.test('missingScopes: a held "*" covers every required scope', () => {
  assertEquals(missingScopes(['read', 'write', 'iam:x'], ['*']), [])
  assertEquals(missingScopes(['read', '*'], ['*']), [])
})

Deno.test('missingScopes: nothing but "*" covers a required "*"', () => {
  assertEquals(missingScopes(['*'], ['read', 'write']), ['*'])
  assertEquals(missingScopes(['read', '*'], ['read']), ['*'])
})

Deno.test('missingScopes: there are no prefix wildcards', () => {
  assertEquals(missingScopes(['iam:x'], ['iam:*']), ['iam:x'])
  assertEquals(missingScopes(['iam:*'], ['iam:x']), ['iam:*'])
})

Deno.test('missingScopes returns no repeats, in order of first appearance', () => {
  assertEquals(missingScopes(['b', 'a', 'b', 'c', 'a'], ['c']), ['b', 'a'])
})

Deno.test('missingScopes accepts sets and tolerates duplicated held scopes', () => {
  assertEquals(missingScopes(new Set(['a', 'b']), new Set(['a'])), ['b'])
  assertEquals(missingScopes(['a'], ['a', 'a']), [])
})

Deno.test('missingScopes does not modify its inputs', () => {
  const required = ['b', 'a', 'b']
  const held = ['a']
  missingScopes(required, held)
  assertEquals(required, ['b', 'a', 'b'])
  assertEquals(held, ['a'])
})
