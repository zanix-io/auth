import { assertEquals } from '@std/assert'
import { JWT_KEY_ENV } from 'utils/constants.ts'
import { createRefreshToken } from 'utils/sessions/create.ts'
import { peekSessionPermissions } from 'utils/sessions/peek-permissions.ts'

const OPERATOR_EMAIL = 'operator@example.com'

Deno.test('peekSessionPermissions: [] with no cookie header at all', async () => {
  const request = new Request('http://localhost/')
  assertEquals(await peekSessionPermissions(request), [])
})

Deno.test('peekSessionPermissions: [] when the cookie jar has no app-token entry', async () => {
  const request = new Request('http://localhost/', { headers: { cookie: 'other=1; another=2' } })
  assertEquals(await peekSessionPermissions(request), [])
})

Deno.test('peekSessionPermissions: [] with a malformed/tampered token', async () => {
  Deno.env.set(JWT_KEY_ENV, 'peek-test-secret')
  try {
    const request = new Request('http://localhost/', {
      headers: { cookie: 'X-Znx-App-Token=not.a.real.jwt' },
    })
    assertEquals(await peekSessionPermissions(request), [])
  } finally {
    Deno.env.delete(JWT_KEY_ENV)
  }
})

Deno.test(
  'peekSessionPermissions: reads the real permissions off a real, validly-signed refresh-token cookie',
  async () => {
    Deno.env.set(JWT_KEY_ENV, 'peek-test-secret')
    try {
      const token = await createRefreshToken({
        subject: OPERATOR_EMAIL,
        type: 'user',
        expiration: '1y',
        payload: {
          access: {
            subject: OPERATOR_EMAIL,
            permissions: ['zanix:admin', 'zanix:admin:triggers'],
          },
        },
      })
      const request = new Request('http://localhost/', {
        headers: { cookie: `X-Znx-App-Token=${token}` },
      })
      assertEquals(await peekSessionPermissions(request), [
        'zanix:admin',
        'zanix:admin:triggers',
      ])
    } finally {
      Deno.env.delete(JWT_KEY_ENV)
    }
  },
)

Deno.test(
  'peekSessionPermissions: a single, non-array permission still comes back wrapped in an array',
  async () => {
    Deno.env.set(JWT_KEY_ENV, 'peek-test-secret')
    try {
      const token = await createRefreshToken({
        subject: OPERATOR_EMAIL,
        type: 'user',
        expiration: '1y',
        payload: { access: { subject: OPERATOR_EMAIL, permissions: 'zanix:admin' } },
      })
      const request = new Request('http://localhost/', {
        headers: { cookie: `X-Znx-App-Token=${token}` },
      })
      assertEquals(await peekSessionPermissions(request), ['zanix:admin'])
    } finally {
      Deno.env.delete(JWT_KEY_ENV)
    }
  },
)

Deno.test('peekSessionPermissions: [] for a real session that was granted no permissions', async () => {
  Deno.env.set(JWT_KEY_ENV, 'peek-test-secret')
  try {
    const token = await createRefreshToken({
      subject: OPERATOR_EMAIL,
      type: 'user',
      expiration: '1y',
      payload: { access: { subject: OPERATOR_EMAIL } },
    })
    const request = new Request('http://localhost/', {
      headers: { cookie: `X-Znx-App-Token=${token}` },
    })
    assertEquals(await peekSessionPermissions(request), [])
  } finally {
    Deno.env.delete(JWT_KEY_ENV)
  }
})
