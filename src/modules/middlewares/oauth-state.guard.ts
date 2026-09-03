import type { GuardContext, MiddlewareGlobalGuard } from '@zanix/server'

import { HttpError } from '@zanix/errors'
import { assertZnxCookieName, generateUUID } from '@zanix/helpers'

/**
 * Name of the cookie carrying the OAuth2 CSRF `state` value between {@linkcode oauthStateIssueGuard}
 * and {@linkcode oauthStateVerifyGuard}. Fixed, not configurable — matches the `X-Znx-<Word>-...`
 * namespace every framework-owned Zanix cookie uses, and validated once, at module load, via
 * `@zanix/utils`'s `assertZnxCookieName` (`@zanix/helpers`'s own re-export) so a typo here fails
 * loudly at startup rather than silently making `@zanix/server`'s own `cookiesGuard` drop the
 * cookie in production. Also registered under `@zanix/utils`'s own `SENSITIVE_KEY_PATTERN`, so a
 * `state` value never reaches a log/error response unredacted.
 */
export const OAUTH_STATE_COOKIE_NAME = 'X-Znx-Oauth-State'
assertZnxCookieName(OAUTH_STATE_COOKIE_NAME, 'oauthStateIssueGuard', 'Oauth-State')

/**
 * The `ctx.locals` key {@linkcode oauthStateIssueGuard} stashes a freshly minted `state` value
 * under, for the consuming `@zanix/space` page's own `action` to read back and forward into
 * `OAuth2Connector.generateAuthUrl({ state })` — the same "guard writes to `locals`, page reads it
 * back" relay `@zanix/space`'s own `csrfGuard`/`CSRF_TOKEN_LOCALS_KEY` already establishes for its
 * CSRF token.
 */
export const OAUTH_STATE_LOCALS_KEY = 'oauthState'

/**
 * How long the `state` cookie lives before it's considered abandoned — long enough to cover a real
 * provider redirect round trip (the user leaving to the provider's own login/consent screen and
 * coming back), short enough that an abandoned attempt's cookie doesn't linger.
 */
const OAUTH_STATE_MAX_AGE_SECONDS = 60 * 10

/**
 * The attribute set for the OAuth2 `state` cookie: `HttpOnly`/`Secure` like every Zanix
 * session/token cookie — never read by client JS, never sent over plain HTTP — but
 * `SameSite=Lax`, not `Strict`. A `Strict` cookie is dropped by the browser on the cross-site
 * top-level navigation the OAuth2 provider's own redirect-back performs (that navigation
 * originates from the PROVIDER's own site, not this one) — using `Strict` here would make the
 * cookie never actually reach the callback leg it exists to protect. `Lax` still blocks the CSRF
 * shape these guards defend against: a third-party page can't read or set this cookie from a
 * different origin, it can only ever ride along a real top-level browser navigation — exactly what
 * the legitimate provider redirect-back also is, so this relaxation costs nothing here. Kept local
 * rather than built from a shared constant — this exact `HttpOnly` + `Lax` combination has exactly
 * one consumer in this package.
 */
const OAUTH_STATE_COOKIE_ATTRIBUTES = 'Path=/; HttpOnly; Secure; SameSite=Lax'

/**
 * Builds the `Set-Cookie` string that clears the OAuth2 `state` cookie — shared by both guards:
 * {@linkcode oauthStateIssueGuard} overwrites any stale, unconsumed leftover from an abandoned
 * attempt before minting a fresh value, and {@linkcode oauthStateVerifyGuard} clears it for good
 * once consumed.
 */
function clearOauthStateCookie(): string {
  return `${OAUTH_STATE_COOKIE_NAME}=; Max-Age=0; ${OAUTH_STATE_COOKIE_ATTRIBUTES}`
}

/**
 * Creates and returns a middleware guard that mints a fresh, random OAuth2 `state` value on every
 * `POST` to an OAuth2 login start page, persists it as the short-lived {@linkcode
 * OAUTH_STATE_COOKIE_NAME} cookie, and stashes the same value under {@linkcode
 * OAUTH_STATE_LOCALS_KEY} for that page's own `action` to read back and forward, unchanged, into
 * `OAuth2Connector.generateAuthUrl({ state })` — so the resulting authorization redirect's own
 * `state` query param and this cookie always carry the exact same value. `state` is the round-trip
 * value the OAuth2 authorization-code flow itself defines for exactly this purpose: proving the
 * callback that eventually arrives is the continuation of a flow this app actually started, not
 * one an attacker initiated and is trying to complete against a victim's session.
 *
 * No-ops on any method other than `POST` — a `GET` to the same start page only renders the login
 * confirmation screen and has nothing to mint yet. A new value is minted on every `POST`, even when
 * an unconsumed cookie from a previous, abandoned attempt is still present — silently overwritten
 * rather than reused, so restarting the flow can never accidentally revalidate against a stale
 * value {@linkcode oauthStateVerifyGuard} would otherwise still accept.
 *
 * Apply via `@Guard(oauthStateIssueGuard())` on the login start page's controller class (a
 * class-level `@Guard` wires to both `GET`/`POST` for that page — this guard's own `GET` no-op
 * covers the other half).
 *
 * @example
 * ```ts
 * @Page()
 * @Guard(oauthStateIssueGuard())
 * export default class OauthLoginPage extends SpacePageController {
 *   action = (ctx: PageActionContext) => {
 *     const state = ctx.locals[OAUTH_STATE_LOCALS_KEY] as string
 *     const { url } = this.providers.get('auth').google.generateAuthUrl({ state })
 *     return Promise.resolve(Response.redirect(url, 302))
 *   }
 * }
 * ```
 */
export function oauthStateIssueGuard(): MiddlewareGlobalGuard {
  return (ctx: GuardContext) => {
    if (ctx.req.method !== 'POST') return {}

    const state = generateUUID()
    ctx.locals[OAUTH_STATE_LOCALS_KEY] = state

    return {
      headers: {
        'Set-Cookie':
          `${OAUTH_STATE_COOKIE_NAME}=${state}; Max-Age=${OAUTH_STATE_MAX_AGE_SECONDS}; ${OAUTH_STATE_COOKIE_ATTRIBUTES}`,
      },
    }
  }
}

/**
 * Creates and returns a middleware guard that verifies the OAuth2 provider's own `?state=...`
 * callback query param against the value {@linkcode oauthStateIssueGuard} persisted, before the
 * consuming page ever exchanges the authorization code via `OAuth2Connector.validateCode()`/
 * `.authenticateWithCode()` — closing the classic OAuth2 CSRF an attacker-initiated authorization
 * flow could otherwise complete against a victim's own session.
 *
 * Rejects two distinct ways:
 * - **Missing** (either side: no cookie was ever set, or the provider's own redirect carries no
 *   `state` at all) → {@link HttpError} `BAD_REQUEST` — a direct navigation to this URL, a stale
 *   bookmark, or a browser that dropped the cookie, never necessarily an attack.
 * - **Mismatch** (both present, but different) → {@link HttpError} `FORBIDDEN` — a real, active
 *   CSRF attempt, not a client/protocol accident.
 *
 * Single-use: clears the cookie the moment it's successfully consumed, so a replayed callback (the
 * exact same `?code=...&state=...` URL, resubmitted via a browser back button or captured from
 * history/logs) always fails the **missing**-cookie branch above on its second attempt, even though
 * its `state` genuinely matched the first time.
 *
 * Apply via `@Guard(oauthStateVerifyGuard())` on the OAuth2 callback page's controller class.
 *
 * @throws {HttpError} `BAD_REQUEST` when either the cookie or the `state` query param is missing.
 * @throws {HttpError} `FORBIDDEN` when both are present but don't match.
 *
 * @example
 * ```ts
 * @Page()
 * @Guard(oauthStateVerifyGuard())
 * export default class OauthCallbackPage extends SpacePageController {
 *   loader = async (ctx: PageContext) => {
 *     const code = ctx.url.searchParams.get('code')!
 *     await this.providers.get('auth').google.authenticateWithCode(code)
 *   }
 * }
 * ```
 */
export function oauthStateVerifyGuard(): MiddlewareGlobalGuard {
  return (ctx: GuardContext) => {
    const cookieState = ctx.cookies[OAUTH_STATE_COOKIE_NAME]
    const queryState = ctx.url.searchParams.get('state')

    if (!cookieState || !queryState) {
      throw new HttpError('BAD_REQUEST', { message: 'Missing OAuth2 state parameter.' })
    }
    if (cookieState !== queryState) {
      throw new HttpError('FORBIDDEN', { message: 'Invalid OAuth2 state parameter.' })
    }

    return { headers: { 'Set-Cookie': clearOauthStateCookie() } }
  }
}
