import { assertEquals } from '@std/assert'
import { scopeValidation } from 'utils/scope.ts'

Deno.test('returns OK when userScopes shares at least one scope with baseScopes', () => {
  const baseScopes = new Set(['read', 'write', 'admin'])
  const userScopes = new Set(['read', 'profile'])

  const result = scopeValidation(baseScopes, userScopes)

  assertEquals(result, 'OK')
})

Deno.test('returns an error message when userScopes has no matching scopes in baseScopes', () => {
  const baseScopes = new Set(['read', 'write', 'admin'])
  const userScopes = new Set(['guest', 'profile'])

  const result = scopeValidation(baseScopes, userScopes)
  assertEquals(
    result,
    'Insufficient permissions. Requires any of [read, write, admin], but received [guest, profile].',
  )
})

Deno.test('returns OK when all userScopes are within baseScopes', () => {
  const baseScopes = new Set(['read', 'write', 'admin'])
  const userScopes = new Set(['read', 'write'])

  const result = scopeValidation(baseScopes, userScopes)

  assertEquals(result, 'OK')
})

Deno.test('returns an error message when userScopes is empty', () => {
  const baseScopes = new Set(['read', 'write', 'admin'])
  const userScopes = new Set<string>()

  const result = scopeValidation(baseScopes, userScopes)

  assertEquals(result, 'Insufficient permissions. Requires any of [read, write, admin].')
})

Deno.test('returns an error message when userScopes is undefined', () => {
  const baseScopes = new Set(['read', 'write', 'admin'])

  const result = scopeValidation(baseScopes)

  assertEquals(result, 'Insufficient permissions. Requires any of [read, write, admin].')
})

Deno.test('returns OK when both sets are empty', () => {
  const baseScopes = new Set<string>()
  const userScopes = new Set<string>()

  const result = scopeValidation(baseScopes, userScopes)

  assertEquals(result, 'OK')
})

Deno.test('returns OK when identical sets are provided', () => {
  const baseScopes = new Set(['read', 'write'])
  const userScopes = new Set(['read', 'write'])

  const result = scopeValidation(baseScopes, userScopes)

  assertEquals(result, 'OK')
})

Deno.test('returns OK when user has wildcard', () => {
  const baseScopes = new Set(['admin'])
  const userScopes = new Set(['*'])

  const result = scopeValidation(baseScopes, userScopes)

  assertEquals(result, 'OK')
})

Deno.test('returns OK when baseScopes is empty', () => {
  const baseScopes = new Set([])
  const userScopes = new Set(['admin'])

  const result = scopeValidation(baseScopes, userScopes)

  assertEquals(result, 'OK')
})
