import type { GitHubUserInfo } from 'typings/connectors.ts'

import { OAuth2Connector, type OAuth2ConnectorOptions } from '../oauth2.ts'
import { InternalError } from '@zanix/errors'

const ROUTES = {
  auth: 'https://github.com/login/oauth/authorize',
  revoke: 'https://api.github.com/applications/{client_id}/token',
  userInfo: 'https://api.github.com/user',
  token: 'https://github.com/login/oauth/access_token',
}

/** Env var for {@link GitHubOAuth2Connector}'s `clientId`. Presence gates whether
 * `registerGitHubOAuth2Connector()` (`github/core.ts`) registers a default connector at all. */
export const GITHUB_OAUTH2_CLIENT_ID_ENV = 'GITHUB_OAUTH2_CLIENT_ID'
/** Env var for {@link GitHubOAuth2Connector}'s `clientSecret`. */
export const GITHUB_OAUTH2_CLIENT_SECRET_ENV = 'GITHUB_OAUTH2_CLIENT_SECRET'
/** Env var for {@link GitHubOAuth2Connector}'s `redirectUri`. */
export const GITHUB_OAUTH2_REDIRECT_URI_ENV = 'GITHUB_OAUTH2_REDIRECT_URI'
/** Env var overriding {@link GitHubOAuth2Connector}'s `authUrl`, defaulting to GitHub's real
 * authorization endpoint. */
export const GITHUB_OAUTH2_AUTH_URL_ENV = 'GITHUB_OAUTH2_AUTH_URL'
/** Env var overriding {@link GitHubOAuth2Connector}'s `userInfoUrl`, defaulting to GitHub's real
 * user-info endpoint. */
export const GITHUB_OAUTH2_USERINFO_URL_ENV = 'GITHUB_OAUTH2_USERINFO_URL'
/** Env var overriding {@link GitHubOAuth2Connector}'s `revokeUrl` template, defaulting to GitHub's
 * real revoke endpoint. */
export const GITHUB_OAUTH2_REVOKE_URL_ENV = 'GITHUB_OAUTH2_REVOKE_URL'
/** Env var overriding {@link GitHubOAuth2Connector}'s `tokenUrl`, defaulting to GitHub's real
 * token endpoint. */
export const GITHUB_OAUTH2_TOKEN_URL_ENV = 'GITHUB_OAUTH2_TOKEN_URL'
/** Env var selecting {@link GitHubOAuth2Connector}'s `responseType` (`'token'` or `'code'`) —
 * see {@link envResponseType}. */
export const GITHUB_OAUTH2_RESPONSE_TYPE_ENV = 'GITHUB_OAUTH2_RESPONSE_TYPE'

/** Reads `GITHUB_OAUTH2_RESPONSE_TYPE`, ignoring anything other than the two real values —
 * `OAuth2Connector`'s own default (`'token'`) already covers everything else, including unset.
 * Kept for parity with `GoogleOAuth2Connector`'s own env-driven override, even though GitHub itself
 * only ever supports the code flow — see this class's own doc for why `'token'` isn't a real option
 * here despite the type allowing it. */
function envResponseType(): 'token' | 'code' | undefined {
  const value = Deno.env.get(GITHUB_OAUTH2_RESPONSE_TYPE_ENV)
  return value === 'token' || value === 'code' ? value : undefined
}

/**
 * Connector for handling GitHub OAuth2 authentication flows.
 * Extends {@link OAuth2Connector} with GitHub's specific endpoints and how to derive the session
 * subject from {@link GitHubUserInfo}.
 *
 * **Defaults to the authorization-code flow (`responseType: 'code'`), unlike
 * `GoogleOAuth2Connector`'s implicit-flow default** — GitHub's own OAuth2 implementation has no
 * implicit flow at all ("The implicit grant type is not supported" —
 * https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps). Its
 * `/login/oauth/authorize` redirect always comes back with `?code=...`, never a bearer token
 * directly, so `responseType: 'token'` + `authenticate()` cannot work against real GitHub — only
 * `authenticateWithCode()`/`validateCode()` do. `GITHUB_OAUTH2_RESPONSE_TYPE`/`options.responseType`
 * still accept the `'token' | 'code'` type shared with the base class, but the constructor throws
 * immediately if the resolved value is `'token'` AND `authUrl` is left at its default (real
 * GitHub) — better a clear config error at boot than a silent, confusing failure the first time a
 * real user tries to log in. A custom `authUrl` (a proxy that genuinely does support the implicit
 * flow, or a test double) opts back out of this guard, since that's a deliberate choice this class
 * has no basis to second-guess. The guard is construction-time only either way:
 * `generateAuthUrl({ responseType: 'token' })` as an explicit per-call override is a different,
 * more deliberate risk shape, not guarded here.
 */
export class GitHubOAuth2Connector extends OAuth2Connector<GitHubUserInfo> {
  // Own copies of what `revokeToken`'s GitHub-specific contract (see its own doc) needs —
  // `OAuth2Connector` keeps its equivalents as real (`#`-prefixed) private fields, unreachable from
  // a subclass, so these are resolved here the exact same way the base class's own constructor just
  // did, rather than reaching into its internals.
  #clientId: string
  #clientSecret: string
  #revokeUrl: string

  /**
   * Creates a new GitHubOAuth2Connector instance.
   *
   * @param {object} [options] - Connector configuration options.
   * @param {string} [options.clientId] - GitHub OAuth2 Client ID. Defaults to env `GITHUB_OAUTH2_CLIENT_ID`.
   * @param {string} [options.clientSecret] - GitHub OAuth2 Client Secret. Defaults to env `GITHUB_OAUTH2_CLIENT_SECRET`.
   * @param {string} [options.redirectUri] - OAuth2 redirect URI. Defaults to env `GITHUB_OAUTH2_REDIRECT_URI`.
   * @param {string} [options.authUrl] - Authorization endpoint. Defaults to env `GITHUB_OAUTH2_AUTH_URL`,
   *   then GitHub's real endpoint. Only useful for enterprise proxies or testing.
   * @param {string} [options.userInfoUrl] - User-info endpoint. Defaults to env `GITHUB_OAUTH2_USERINFO_URL`,
   *   then GitHub's real endpoint.
   * @param {string} [options.revokeUrl] - Token-revocation endpoint template, with a literal
   *   `{client_id}` placeholder substituted with the resolved `clientId` (see {@link revokeToken}).
   *   Defaults to env `GITHUB_OAUTH2_REVOKE_URL`, then GitHub's real endpoint.
   * @param {string} [options.tokenUrl] - Token endpoint, for `exchangeCode()`/`authenticateWithCode()`
   *   (GitHub's only supported flow — see this class's own doc for why). Defaults to
   *   env `GITHUB_OAUTH2_TOKEN_URL`, then GitHub's real endpoint.
   * @param {'token' | 'code'} [options.responseType] - Defaults to env `GITHUB_OAUTH2_RESPONSE_TYPE`,
   *   then `'code'` — GitHub has no implicit flow to fall back to (see this class's own doc).
   * @param {ConnectorOptions} [options] - Additional connector options.
   *
   * @throws {TargetError} If any required OAuth2 property is missing.
   * @throws {InternalError} If `responseType` resolves to `'token'` while `authUrl` is left at its default
   *   (real GitHub) — see this class's own doc.
   */
  constructor(options: OAuth2ConnectorOptions = {}) {
    const {
      clientId = Deno.env.get(GITHUB_OAUTH2_CLIENT_ID_ENV),
      clientSecret = Deno.env.get(GITHUB_OAUTH2_CLIENT_SECRET_ENV),
      redirectUri = Deno.env.get(GITHUB_OAUTH2_REDIRECT_URI_ENV),
      authUrl = Deno.env.get(GITHUB_OAUTH2_AUTH_URL_ENV),
      userInfoUrl = Deno.env.get(GITHUB_OAUTH2_USERINFO_URL_ENV),
      revokeUrl = Deno.env.get(GITHUB_OAUTH2_REVOKE_URL_ENV),
      tokenUrl = Deno.env.get(GITHUB_OAUTH2_TOKEN_URL_ENV),
      responseType = envResponseType(),
      ...opts
    } = options

    // Fail at construction time, not at a real user's login attempt — GitHub's OWN real OAuth2
    // implementation has no implicit flow at all (see this class's own doc), so a connector left on
    // GitHub's real `authUrl` with `responseType: 'token'` (e.g. `GITHUB_OAUTH2_RESPONSE_TYPE=token`
    // set by mistake, copy-pasted from a Google-shaped config) would build a real authorize URL that
    // never actually completes a login — a silent, confusing failure far from its real cause. Guards
    // only the DEFAULT `authUrl` case: a caller who explicitly points this connector at a custom
    // `authUrl` (an enterprise proxy that genuinely does support the implicit flow, or a test double)
    // is making a deliberate choice this class has no basis to second-guess. Scoped to
    // construction-time config only, too: `generateAuthUrl({ responseType: 'token' })` as a per-call
    // override still isn't guarded here — a different, more deliberate risk shape than an env var
    // misconfigured once and forgotten.
    if (responseType === 'token' && !authUrl) {
      // A native `Error` here previously — a construction-time config invariant (see this class's
      // own comment right above), not something a caller can hit per-request.
      throw new InternalError(
        "GitHubOAuth2Connector: responseType 'token' (the implicit flow) is not supported by " +
          "GitHub's real OAuth2 implementation — use 'code' (the default), or pass a custom " +
          '`authUrl` if this really targets a proxy that supports the implicit flow.',
        { code: 'GITHUB_OAUTH2_UNSUPPORTED_RESPONSE_TYPE' },
      )
    }

    super({
      authUrl: ROUTES.auth,
      userInfoUrl: ROUTES.userInfo,
      revokeUrl: ROUTES.revoke,
      tokenUrl: ROUTES.token,
      defaultScope: 'read:user user:email',
      responseType: 'code',
    }, {
      clientId,
      clientSecret,
      redirectUri,
      authUrl,
      userInfoUrl,
      revokeUrl,
      tokenUrl,
      responseType,
      ...opts,
    })

    // Reaching this point means `super()` already validated clientId/clientSecret are non-empty.
    this.#clientId = clientId as string
    this.#clientSecret = clientSecret as string
    this.#revokeUrl = (revokeUrl ?? ROUTES.revoke).replace('{client_id}', this.#clientId)
  }

  /**
   * Revokes a token via GitHub's own OAuth-application token-revocation contract — a genuinely
   * different shape from the base class's generic {@link OAuth2Connector.revokeToken}, which
   * assumes a Google-style `POST revokeUrl` with a form-encoded `token` param and no auth. GitHub's
   * real endpoint (https://docs.github.com/en/rest/apps/oauth-applications#delete-an-app-token)
   * instead requires:
   *  - `DELETE` (not `POST`) to `applications/{client_id}/token`, with `{client_id}` substituted
   *    for this connector's own resolved `clientId`.
   *  - HTTP Basic authentication, `clientId` as the username and `clientSecret` as the password —
   *    not the bearer token being revoked.
   *  - A JSON body `{ "access_token": token }` (not form-encoded, and keyed `access_token`, not
   *    `token`).
   *
   * Overridden here rather than relying on the inherited implementation, which would silently send
   * an unauthenticated `POST` with the literal, unsubstituted `{client_id}` placeholder still in the
   * URL — a request GitHub's real API rejects.
   *
   * @param {string} token - The access token to revoke.
   * @returns {Promise<boolean>} A promise that resolves to `true` once the revoke request succeeds.
   * @throws {Error} If the revoke request fails.
   */
  public override async revokeToken(token: string): Promise<boolean> {
    await this.http.delete<boolean>(this.#revokeUrl, {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Basic ${btoa(`${this.#clientId}:${this.#clientSecret}`)}`,
      },
      body: JSON.stringify({ access_token: token }),
    })

    return true
  }

  /** Uses the GitHub account's immutable numeric ID as the session subject — unlike Google's
   * always-present `email`, GitHub's `email` can be `null` for an account with a private email
   * setting, so it isn't a reliable subject here. */
  protected getSubject(user: GitHubUserInfo): string {
    return String(user.id)
  }
}
