import { assert, assertEquals, assertMatch } from '@std/assert'
import { getDefaultSessionHeaders, getSessionHeaders } from 'utils/sessions/headers.ts'

Deno.test('getSessionHeaders returns default headers without cookies', () => {
  const headers = getSessionHeaders({ cookiesAccepted: false, type: 'user', subject: 'anonymous' })

  assertEquals(headers['X-Znx-User-Id'], 'anonymous')
  assertEquals(headers['X-Znx-User-Session-Status'], 'unconfirmed')
  assert(!headers['Set-Cookie'])
})

Deno.test('getSessionHeaders includes cookies when requested', () => {
  const now = Math.floor(Date.now() / 1000)
  const expiration = now + 3600

  const headers = getSessionHeaders({
    cookiesAccepted: true,
    type: 'user',
    sessionStatus: 'active',
    subject: 'alice',
    expiration,
  })

  assertEquals(headers['X-Znx-User-Id'], 'alice')
  assertEquals(headers['X-Znx-User-Session-Status'], 'active')
  assert(headers['Set-Cookie'])

  assertMatch(headers['Set-Cookie'], /Max-Age=3600/)
  assertMatch(
    headers['Set-Cookie'],
    /X-Znx-User-Session-Status=active; X-Znx-User-Id=alice; Max-Age=\d+; Path=\/; HttpOnly; SameSite=Strict/,
  )
})

Deno.test('getSessionHeaders handles API type correctly', () => {
  const headers = getSessionHeaders({ cookiesAccepted: false, type: 'api', subject: 'anonymous' })

  assertEquals(headers['X-Znx-Api-Id'], 'anonymous')
  assertEquals(headers['X-Znx-Api-Session-Status'], 'unconfirmed')
})

Deno.test('getSessionHeaders caps Max-Age at 0 if expiration is in the past', () => {
  const past = Math.floor(Date.now() / 1000) - 100
  const headers = getSessionHeaders({
    cookiesAccepted: true,
    type: 'user',
    expiration: past,
    subject: 'anonymous',
  })

  assertMatch(headers['Set-Cookie'], /Max-Age=0;/)
})

Deno.test('getSessionHeaders caps Max-Age at 10 if expiration is in the future', () => {
  const future = Math.floor(Date.now() / 1000) + 10
  const headers = getSessionHeaders({
    cookiesAccepted: true,
    type: 'user',
    expiration: future,
    subject: 'anonymous',
  })

  assertMatch(headers['Set-Cookie'], /Max-Age=10;/)
})

Deno.test(
  'getDefaultSessionHeaders returns default headers without cookies and headers',
  async () => {
    const apiHeaders = await getDefaultSessionHeaders(
      {
        headers: { get: (name: string) => name === 'X-Znx-User-Id' ? 'my-user' : null } as never,
        type: 'api',
        cookiesAccepted: false,
      },
    )

    assertEquals(apiHeaders['X-Znx-Api-Session-Status'], 'unconfirmed')
    assert(apiHeaders['X-Znx-Api-Id'].startsWith('anonymous-'))

    const userHeaders = await getDefaultSessionHeaders(
      {
        headers: { get: (name: string) => name === 'X-Znx-Api-Id' ? 'my-user' : null } as never,
        type: 'user',
        cookiesAccepted: false,
      },
    )

    assertEquals(userHeaders['X-Znx-User-Session-Status'], 'unconfirmed')
    assert(userHeaders['X-Znx-User-Id'].startsWith('anonymous-'))
  },
)

Deno.test('getDefaultSessionHeaders returns default headers with cookies', async () => {
  const apiHeaders = await getDefaultSessionHeaders(
    {
      headers: { get: (name: string) => name === 'X-Znx-Api-Id' ? 'my-api' : null } as never,
      type: 'api',
      cookiesAccepted: true,
    },
  )

  assert(apiHeaders['X-Znx-Api-Id'].startsWith('my-api'))
  assertMatch(
    apiHeaders['Set-Cookie'],
    /^X-Znx-Api-Session-Status=unconfirmed; X-Znx-Api-Id=my-api; Max-Age=0;/,
  )

  const userHeaders = await getDefaultSessionHeaders(
    {
      headers: {
        get: (name: string) => name === 'Cookie' ? 'X-Znx-User-Id=my-user;' : null,
      } as never,
      type: 'user',
      cookiesAccepted: true,
    },
  )

  assert(userHeaders['X-Znx-User-Id'].startsWith('my-user'))
  assertMatch(
    userHeaders['Set-Cookie'],
    /^X-Znx-User-Session-Status=unconfirmed; X-Znx-User-Id=my-user; Max-Age=0;/,
  )
})
