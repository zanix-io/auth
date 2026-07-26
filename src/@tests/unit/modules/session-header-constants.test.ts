import { assertEquals } from '@std/assert'
import { apiSessionHeaders, userSessionHeaders } from '../../../../mod.ts'

Deno.test('userSessionHeaders reflects the user session header names', () => {
  assertEquals(userSessionHeaders, {
    sub: 'X-Znx-User-Id',
    session: 'X-Znx-User-Session-Status',
    token: 'X-Znx-App-Token',
  })
})

Deno.test('apiSessionHeaders reflects the api session header names (not the user ones)', () => {
  assertEquals(apiSessionHeaders, {
    sub: 'X-Znx-Api-Id',
    session: 'X-Znx-Api-Session-Status',
    token: undefined,
  })
})
