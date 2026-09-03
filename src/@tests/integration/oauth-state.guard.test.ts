// deno-lint-ignore-file no-explicit-any
import { assert, assertEquals, assertExists, assertThrows } from '@std/assert'
import { HttpError } from '@zanix/errors'

import {
  OAUTH_STATE_COOKIE_NAME,
  OAUTH_STATE_LOCALS_KEY,
  oauthStateIssueGuard,
  oauthStateVerifyGuard,
} from 'modules/middlewares/oauth-state.guard.ts'

// `oauthStateIssueGuard`/`oauthStateVerifyGuard` are two halves of one protocol: the value
// `oauthStateIssueGuard` mints and persists as a cookie is exactly what `oauthStateVerifyGuard`
// later reads back and compares against the provider's own callback query param. What's under test
// here is that real round trip — issuing, verifying, and the cookie relay between them — so this
// suite lives in `integration/`, not `unit/`, per `zanix-test-tier-conventions`, the same reasoning
// `page-session.guard.test.ts` applies to its own guard composition.

function createCtx(
  { method = 'GET', cookies = {}, query }: {
    method?: string
    cookies?: Record<string, string>
    query?: string
  } = {},
): any {
  const url = new URL('https://example.com/login/google/callback')
  if (query !== undefined) url.searchParams.set('state', query)

  return {
    req: new Request(url, { method }),
    url,
    cookies,
    locals: {},
  }
}

function extractCookieValue(setCookie: string | undefined, name: string): string | undefined {
  if (!setCookie?.startsWith(`${name}=`)) return undefined
  return setCookie.slice(name.length + 1).split(';')[0]
}

Deno.test('oauthStateIssueGuard: no-ops on GET, minting nothing', () => {
  const guard = oauthStateIssueGuard()
  const ctx = createCtx({ method: 'GET' })

  const result = guard(ctx)

  assertEquals(result, {})
  assertEquals(ctx.locals[OAUTH_STATE_LOCALS_KEY], undefined)
})

Deno.test(
  'oauthStateIssueGuard: mints a fresh state on POST, persisting it in both the cookie and locals',
  () => {
    const guard = oauthStateIssueGuard()
    const ctx = createCtx({ method: 'POST' })

    const result = guard(ctx) as { headers?: Record<string, string> }

    const state = ctx.locals[OAUTH_STATE_LOCALS_KEY] as string
    assertExists(state)
    const cookieValue = extractCookieValue(result.headers?.['Set-Cookie'], OAUTH_STATE_COOKIE_NAME)
    assertEquals(cookieValue, state)
  },
)

Deno.test(
  'oauthStateIssueGuard: mints a NEW state on every POST, even with a stale, unconsumed cookie present',
  () => {
    const guard = oauthStateIssueGuard()
    const first = guard(createCtx({ method: 'POST' })) as { headers?: Record<string, string> }
    const firstState = extractCookieValue(first.headers?.['Set-Cookie'], OAUTH_STATE_COOKIE_NAME)
    assertExists(firstState)

    const second = guard(
      createCtx({ method: 'POST', cookies: { [OAUTH_STATE_COOKIE_NAME]: firstState } }),
    ) as { headers?: Record<string, string> }
    const secondState = extractCookieValue(second.headers?.['Set-Cookie'], OAUTH_STATE_COOKIE_NAME)

    assertExists(secondState)
    assert(secondState !== firstState, 'a fresh POST must never reuse a stale, unconsumed state')
  },
)

Deno.test('oauthStateVerifyGuard: rejects with BAD_REQUEST when no cookie was ever set', () => {
  const guard = oauthStateVerifyGuard()
  const error = assertThrows(() => guard(createCtx({ query: 'some-state' })), HttpError)
  assertEquals(error.status.value, 400)
})

Deno.test(
  'oauthStateVerifyGuard: rejects with BAD_REQUEST when the callback carries no state param',
  () => {
    const guard = oauthStateVerifyGuard()
    const ctx = createCtx({ cookies: { [OAUTH_STATE_COOKIE_NAME]: 'the-real-state' } })
    const error = assertThrows(() => guard(ctx), HttpError)
    assertEquals(error.status.value, 400)
  },
)

Deno.test(
  'oauthStateVerifyGuard: rejects with FORBIDDEN when both are present but mismatched',
  () => {
    const guard = oauthStateVerifyGuard()
    const ctx = createCtx({
      cookies: { [OAUTH_STATE_COOKIE_NAME]: 'the-real-state' },
      query: 'a-different-state',
    })
    const error = assertThrows(() => guard(ctx), HttpError)
    assertEquals(error.status.value, 403)
  },
)

Deno.test('oauthStateVerifyGuard: succeeds and clears the cookie when both match', () => {
  const guard = oauthStateVerifyGuard()
  const ctx = createCtx({
    cookies: { [OAUTH_STATE_COOKIE_NAME]: 'the-real-state' },
    query: 'the-real-state',
  })

  const result = guard(ctx) as { headers?: Record<string, string> }

  assert(result.headers?.['Set-Cookie']?.startsWith(`${OAUTH_STATE_COOKIE_NAME}=;`))
  assert(result.headers?.['Set-Cookie']?.includes('Max-Age=0'))
})

Deno.test('oauthStateIssueGuard + oauthStateVerifyGuard: a full round trip succeeds', () => {
  const issue = oauthStateIssueGuard()
  const verify = oauthStateVerifyGuard()

  const issueCtx = createCtx({ method: 'POST' })
  const issueResult = issue(issueCtx) as { headers?: Record<string, string> }
  const state = extractCookieValue(issueResult.headers?.['Set-Cookie'], OAUTH_STATE_COOKIE_NAME)
  assertExists(state)

  const verifyCtx = createCtx({ cookies: { [OAUTH_STATE_COOKIE_NAME]: state }, query: state })
  const verifyResult = verify(verifyCtx) as { headers?: Record<string, string> }

  assert(verifyResult.headers?.['Set-Cookie']?.startsWith(`${OAUTH_STATE_COOKIE_NAME}=;`))
})

Deno.test(
  'oauthStateVerifyGuard: single-use — a replayed callback fails the missing-cookie branch on ' +
    'its second attempt, even though its state genuinely matched the first time',
  () => {
    const verify = oauthStateVerifyGuard()
    const state = 'the-real-state'

    // First attempt: the cookie is still present, matches, and the response above clears it
    // (`Max-Age=0`).
    const firstCtx = createCtx({ cookies: { [OAUTH_STATE_COOKIE_NAME]: state }, query: state })
    verify(firstCtx)

    // A real browser sends no cookie at all on a replay of the same URL — the cookie above was
    // already cleared — even though the URL still carries the original, once-valid `?state=...`.
    const replayCtx = createCtx({ query: state })
    const error = assertThrows(() => verify(replayCtx), HttpError)
    assertEquals(error.status.value, 400)
  },
)
