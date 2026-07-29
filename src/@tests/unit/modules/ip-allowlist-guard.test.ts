// deno-lint-ignore-file no-explicit-any
import { assertEquals, assertThrows } from '@std/assert'
import { InternalError } from '@zanix/errors'
import { ipAllowlistGuard } from 'modules/middlewares/ip-allowlist.guard.ts'

console.error = () => {}

function createCtx(headers: Record<string, string> = {}) {
  return {
    id: 'req-1',
    req: { headers: new Headers(headers) },
  } as any
}

Deno.test('ipAllowlistGuard: empty allowlist passes through by default', async () => {
  const guard = ipAllowlistGuard()
  const result = await guard(createCtx())
  assertEquals(result, {})
})

Deno.test('ipAllowlistGuard: throws without trustProxyHeader when allow is configured', () => {
  assertThrows(
    () => ipAllowlistGuard({ allow: ['10.0.0.1'] }),
    InternalError,
  )
})

Deno.test('ipAllowlistGuard: does not throw when allow is set with trustProxyHeader true', () => {
  ipAllowlistGuard({ allow: ['10.0.0.1'], trustProxyHeader: true })
})

Deno.test('ipAllowlistGuard: allows an exact IP match', async () => {
  const guard = ipAllowlistGuard({ allow: ['203.0.113.5'], trustProxyHeader: true })
  const result = await guard(createCtx({ 'x-forwarded-for': '203.0.113.5' }))
  assertEquals(result, {})
})

Deno.test('ipAllowlistGuard: rejects a non-matching exact IP with a 403', async () => {
  const guard = ipAllowlistGuard({ allow: ['203.0.113.5'], trustProxyHeader: true })
  const result = await guard(createCtx({ 'x-forwarded-for': '203.0.113.6' }))
  assertEquals(result.response?.status, 403)
})

Deno.test('ipAllowlistGuard: allows an IP inside a configured CIDR range', async () => {
  const guard = ipAllowlistGuard({ allow: ['10.0.0.0/8'], trustProxyHeader: true })
  const result = await guard(createCtx({ 'x-forwarded-for': '10.4.5.6' }))
  assertEquals(result, {})
})

Deno.test('ipAllowlistGuard: rejects an IP outside every configured CIDR range', async () => {
  const guard = ipAllowlistGuard({
    allow: ['10.0.0.0/8', '192.168.1.0/24'],
    trustProxyHeader: true,
  })
  const result = await guard(createCtx({ 'x-forwarded-for': '203.0.113.1' }))
  assertEquals(result.response?.status, 403)
})

Deno.test('ipAllowlistGuard: matches the second CIDR entry when the first misses', async () => {
  const guard = ipAllowlistGuard({
    allow: ['10.0.0.0/8', '192.168.1.0/24'],
    trustProxyHeader: true,
  })
  const result = await guard(createCtx({ 'x-forwarded-for': '192.168.1.42' }))
  assertEquals(result, {})
})

Deno.test('ipAllowlistGuard: falls back to ADMIN_IP_ALLOWLIST when allow is omitted', async () => {
  Deno.env.set('ADMIN_IP_ALLOWLIST', '10.0.0.0/8, 192.168.1.5')
  try {
    const guard = ipAllowlistGuard({ trustProxyHeader: true })
    const insideRange = await guard(createCtx({ 'x-forwarded-for': '10.1.2.3' }))
    assertEquals(insideRange, {})

    const exactMatch = await guard(createCtx({ 'x-forwarded-for': '192.168.1.5' }))
    assertEquals(exactMatch, {})

    const outsideRange = await guard(createCtx({ 'x-forwarded-for': '8.8.8.8' }))
    assertEquals(outsideRange.response?.status, 403)
  } finally {
    Deno.env.delete('ADMIN_IP_ALLOWLIST')
  }
})

Deno.test('ipAllowlistGuard: explicit allow overrides ADMIN_IP_ALLOWLIST', async () => {
  Deno.env.set('ADMIN_IP_ALLOWLIST', '203.0.113.5')
  try {
    const guard = ipAllowlistGuard({ allow: ['10.0.0.1'], trustProxyHeader: true })
    const result = await guard(createCtx({ 'x-forwarded-for': '203.0.113.5' }))
    assertEquals(result.response?.status, 403)
  } finally {
    Deno.env.delete('ADMIN_IP_ALLOWLIST')
  }
})

Deno.test('ipAllowlistGuard: empty allow array is a pass-through', async () => {
  const guard = ipAllowlistGuard({ allow: [] })
  const result = await guard(createCtx({ 'x-forwarded-for': '1.2.3.4' }))
  assertEquals(result, {})
})

Deno.test('ipAllowlistGuard: prefers x-real-ip over x-forwarded-for', async () => {
  const guard = ipAllowlistGuard({
    allow: ['203.0.113.5'],
    trustProxyHeader: true,
  })

  const result = await guard(
    createCtx({
      'x-real-ip': '203.0.113.5',
      'x-forwarded-for': '9.9.9.9',
    }),
  )

  assertEquals(result, {})
})

Deno.test('ipAllowlistGuard: falls back to cf-connecting-ip', async () => {
  const guard = ipAllowlistGuard({ allow: ['203.0.113.9'], trustProxyHeader: true })
  const result = await guard(createCtx({ 'cf-connecting-ip': '203.0.113.9' }))
  assertEquals(result, {})
})

Deno.test('ipAllowlistGuard: falls back to x-real-ip when the other two are absent', async () => {
  const guard = ipAllowlistGuard({ allow: ['203.0.113.10'], trustProxyHeader: true })
  const result = await guard(createCtx({ 'x-real-ip': '203.0.113.10' }))
  assertEquals(result, {})
})

Deno.test('ipAllowlistGuard: rejects when no known proxy header is present at all', async () => {
  const guard = ipAllowlistGuard({ allow: ['203.0.113.10'], trustProxyHeader: true })
  const result = await guard(createCtx())
  assertEquals(result.response?.status, 403)
})

Deno.test('ipAllowlistGuard: prefers cf-connecting-ip over other trusted headers', async () => {
  const guard = ipAllowlistGuard({
    allow: ['203.0.113.5'],
    trustProxyHeader: true,
  })

  const result = await guard(
    createCtx({
      'cf-connecting-ip': '203.0.113.5',
      'x-real-ip': '9.9.9.9',
      'x-forwarded-for': '8.8.8.8',
    }),
  )

  assertEquals(result, {})
})

Deno.test('ipAllowlistGuard: uses only the configured trusted headers', async () => {
  const guard = ipAllowlistGuard({
    allow: ['203.0.113.5'],
    trustProxyHeader: true,
    trustedHeaders: ['x-real-ip'],
  })

  const result = await guard(
    createCtx({
      'cf-connecting-ip': '203.0.113.5',
      'x-real-ip': '203.0.113.5',
    }),
  )
  assertEquals(result, {})
})

Deno.test('ipAllowlistGuard: uses the first x-forwarded-for entry', async () => {
  const guard = ipAllowlistGuard({
    allow: ['203.0.113.5'],
    trustProxyHeader: true,
  })

  const result = await guard(
    createCtx({
      'x-forwarded-for': '203.0.113.5, 10.0.0.1, 127.0.0.1',
    }),
  )

  assertEquals(result, {})
})

Deno.test('ipAllowlistGuard: trims whitespace around the client IP', async () => {
  const guard = ipAllowlistGuard({
    allow: ['203.0.113.5'],
    trustProxyHeader: true,
  })

  const result = await guard(
    createCtx({
      'x-forwarded-for': '   203.0.113.5   ',
    }),
  )

  assertEquals(result, {})
})

Deno.test('ipAllowlistGuard: accepts IPv4-mapped IPv6 addresses', async () => {
  const guard = ipAllowlistGuard({
    allow: ['203.0.113.5'],
    trustProxyHeader: true,
  })

  const result = await guard(
    createCtx({
      'x-forwarded-for': '::ffff:203.0.113.5',
    }),
  )

  assertEquals(result, {})
})

Deno.test('ipAllowlistGuard: strips the port from IPv4 addresses', async () => {
  const guard = ipAllowlistGuard({
    allow: ['203.0.113.5'],
    trustProxyHeader: true,
  })

  const result = await guard(
    createCtx({
      'x-forwarded-for': '203.0.113.5:443',
    }),
  )

  assertEquals(result, {})
})

Deno.test('ipAllowlistGuard: ignores invalid CIDR entries', async () => {
  const guard = ipAllowlistGuard({
    allow: ['10.0.0.0/99'],
    trustProxyHeader: true,
  })

  const result = await guard(
    createCtx({
      'x-forwarded-for': '10.0.0.1',
    }),
  )

  assertEquals(result.response?.status, 403)
})

Deno.test('ipAllowlistGuard: rejects invalid client IPs', async () => {
  const guard = ipAllowlistGuard({
    allow: ['10.0.0.0/8'],
    trustProxyHeader: true,
  })

  const result = await guard(
    createCtx({
      'x-forwarded-for': 'not-an-ip',
    }),
  )

  assertEquals(result.response?.status, 403)
})

Deno.test('ipAllowlistGuard: ignores empty trusted headers', async () => {
  const guard = ipAllowlistGuard({
    allow: ['203.0.113.5'],
    trustProxyHeader: true,
  })

  const result = await guard(
    createCtx({
      'cf-connecting-ip': '',
      'x-real-ip': '203.0.113.5',
    }),
  )

  assertEquals(result, {})
})

Deno.test('ipAllowlistGuard: treats a bare IP as a /32 network', async () => {
  const guard = ipAllowlistGuard({
    allow: ['203.0.113.5'],
    trustProxyHeader: true,
  })

  const allowed = await guard(createCtx({
    'x-forwarded-for': '203.0.113.5',
  }))

  const rejected = await guard(createCtx({
    'x-forwarded-for': '203.0.113.6',
  }))

  assertEquals(allowed, {})
  assertEquals(rejected.response?.status, 403)
})

Deno.test('ipAllowlistGuard: ignores headers that are not configured as trusted', async () => {
  const guard = ipAllowlistGuard({
    allow: ['203.0.113.5'],
    trustProxyHeader: true,
    trustedHeaders: ['x-real-ip'],
  })

  const result = await guard(
    createCtx({
      'cf-connecting-ip': '203.0.113.5',
      'x-forwarded-for': '203.0.113.5',
    }),
  )

  assertEquals(result.response?.status, 403)
})
