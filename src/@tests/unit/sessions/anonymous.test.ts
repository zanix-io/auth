import { assert, assertEquals, assertMatch, assertRejects } from '@std/assert'
import { getAnonymousSessionId } from 'utils/sessions/anonymous.ts'
import { InternalError } from '@zanix/errors'

console.error = () => {}

function createHeaders(values: Record<string, string>) {
  return { get: (key: string) => values[key] ?? null } as never
}

// --- trustProxyHeader has no default: omitting it is a bug, not a safe fallback ----------------

/**
 * Regression coverage for a confirmed vulnerability, and for the gap in its first fix: without an
 * explicit decision, `x-forwarded-for`/`cf-connecting-ip`/`x-real-ip` are fully
 * attacker-controlled — keying the anonymous session id off them let a single client mint
 * unlimited distinct rate-limit buckets for free by rotating a spoofed header value. The first fix
 * closed that by silently defaulting to a shared id when `trustProxyHeader` was left unset — which
 * closed the spoofing bug by accident, but meant no caller was ever actually forced to decide, and
 * any caller that bypassed the one guard enforcing it (`rateLimitGuard`) got the shared-id
 * behavior with nobody choosing it. There is no safe default anymore: omitting the decision throws.
 */
Deno.test(
  'getAnonymousSessionId throws when trustProxyHeader is left unset',
  async () => {
    const error = await assertRejects(
      () => getAnonymousSessionId(createHeaders({ 'x-forwarded-for': '203.0.113.5' })),
      InternalError,
    )
    assertEquals(error.code, 'ANONYMOUS_SESSION_TRUST_PROXY_UNDECIDED')
  },
)

// --- trustProxyHeader: false — the explicit, deliberate shared-id fallback ----------------------

Deno.test(
  'getAnonymousSessionId shares one id when trustProxyHeader is explicitly false, regardless of spoofed headers',
  async () => {
    const first = await getAnonymousSessionId(
      createHeaders({ 'x-forwarded-for': '203.0.113.5' }),
      { trustProxyHeader: false },
    )
    const second = await getAnonymousSessionId(
      createHeaders({ 'x-forwarded-for': '198.51.100.9' }),
      { trustProxyHeader: false },
    )
    const third = await getAnonymousSessionId(createHeaders({}), { trustProxyHeader: false })

    assertEquals(first, second)
    assertEquals(first, third)
    assert(first.startsWith('anonymous-'))
  },
)

// --- trustProxyHeader: true — the original IP+UA-derived behavior, opted into ------------------

Deno.test('getAnonymousSessionId uses the x-forwarded-for IP when well-formed', async () => {
  const id = await getAnonymousSessionId(
    createHeaders({ 'x-forwarded-for': '203.0.113.5' }),
    { trustProxyHeader: true },
  )
  assertMatch(id, /^anonymous-/)
})

Deno.test('getAnonymousSessionId falls back to invalid-ip on a malformed IP', async () => {
  const id = await getAnonymousSessionId(
    createHeaders({ 'x-forwarded-for': 'not-an-ip-address' }),
    { trustProxyHeader: true },
  )
  assert(id.startsWith('anonymous-'))
})

Deno.test('getAnonymousSessionId keeps unknown-ip when no IP header is present', async () => {
  const id = await getAnonymousSessionId(createHeaders({}), { trustProxyHeader: true })
  assert(id.startsWith('anonymous-'))
})

Deno.test('getAnonymousSessionId: trusted IPs that differ produce different ids', async () => {
  const a = await getAnonymousSessionId(
    createHeaders({ 'x-forwarded-for': '203.0.113.5' }),
    { trustProxyHeader: true },
  )
  const b = await getAnonymousSessionId(
    createHeaders({ 'x-forwarded-for': '198.51.100.9' }),
    { trustProxyHeader: true },
  )
  assert(a !== b, 'expected distinct trusted IPs to produce distinct session ids')
})
