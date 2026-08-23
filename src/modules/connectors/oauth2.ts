import type { AuthSessionOptions } from 'typings/auth.ts'
import type { SessionTokens } from 'typings/sessions.ts'

import { generateSessionTokens } from 'utils/sessions/create.ts'
import { type ConnectorOptions, RestClient, type ScopedContext, TargetError } from '@zanix/server'
import { generateUUID } from '@zanix/helpers'
import logger from '@zanix/logger'
import { InternalError } from '@zanix/errors'

/**
 * Fixed, per-provider OAuth2 configuration a {@link OAuth2Connector} subclass supplies as its
 * defaults (e.g. Google's real endpoint URLs). Every field can still be overridden per instance
 * via {@link OAuth2ConnectorOptions}.
 */
export type OAuth2ConnectorConfig = {
  /** The provider's authorization endpoint. */
  authUrl: string
  /** The provider's user-info endpoint. */
  userInfoUrl: string
  /** The provider's token-revocation endpoint. */
  revokeUrl: string
  /**
   * The provider's token endpoint — required only to use {@link OAuth2Connector.authenticateWithCode},
   * the authorization-code flow's own entry point. Standardized across virtually every real OAuth2
   * provider (RFC 6749 §4.1.3): `POST tokenUrl` with `grant_type=authorization_code`, `code`,
   * `client_id`, `client_secret`, `redirect_uri`.
   */
  tokenUrl?: string
  /** OAuth2 scope requested when `generateAuthUrl()` isn't given one explicitly. */
  defaultScope: string
  /**
   * OAuth2 `response_type` used when building the authorize URL.
   * Defaults to `'token'` (implicit flow) when the subclass doesn't specify one.
   */
  responseType?: 'token' | 'code'
}

/** Per-instance options for an {@link OAuth2Connector}: credentials plus optional config overrides. */
export type OAuth2ConnectorOptions =
  & {
    clientId?: string
    clientSecret?: string
    redirectUri?: string
  }
  & Partial<OAuth2ConnectorConfig>
  & ConnectorOptions

/**
 * Abstract base connector for OAuth2 authentication flows.
 *
 * Extends {@link RestClient} and implements the common OAuth2 shape — generating an authorization
 * URL, retrieving user info from an access token, revoking tokens, and completing authentication by
 * creating a local session — so a new provider only needs to supply its endpoint URLs and how to
 * derive a session subject from its own user-info shape.
 *
 * **Prefer the authorization-code flow** (`responseType: 'code'` + `tokenUrl` +
 * {@link OAuth2Connector.authenticateWithCode}) over the implicit-flow default shown below
 * wherever the provider supports it — see {@link OAuth2Connector.authenticate}'s own doc for why.
 *
 * @example
 * ```ts
 * class GitHubOAuth2Connector extends OAuth2Connector<{ id: number; email: string }> {
 *   constructor(options: OAuth2ConnectorOptions = {}) {
 *     super({
 *       authUrl: 'https://github.com/login/oauth/authorize',
 *       userInfoUrl: 'https://api.github.com/user',
 *       revokeUrl: 'https://api.github.com/applications/{client_id}/token',
 *       tokenUrl: 'https://github.com/login/oauth/access_token',
 *       defaultScope: 'read:user user:email',
 *       responseType: 'code',
 *     }, options)
 *   }
 *
 *   protected getSubject(user: { id: number; email: string }): string {
 *     return user.email
 *   }
 * }
 *
 * // In a route handler, once the provider redirects back with `?code=...`:
 * await connector.authenticateWithCode(ctx, code)
 * ```
 */
export abstract class OAuth2Connector<TUserInfo> extends RestClient {
  // `tokenUrl` stays optional here too — only `authenticateWithCode` (the authorization-code
  // flow) requires it; a connector that only ever uses `authenticate()` (implicit flow) never
  // needs to configure it.
  #config:
    & Required<Omit<OAuth2ConnectorConfig, 'tokenUrl'>>
    & Pick<OAuth2ConnectorConfig, 'tokenUrl'>

  /** @private OAuth2 client ID. */
  private clientId: string

  /** @private OAuth2 client secret. */
  private clientSecret: string

  /** @private OAuth2 redirect URI. */
  private redirectUri: string

  /**
   * Creates a new OAuth2Connector instance.
   *
   * @param defaults - The concrete provider's fixed configuration (endpoint URLs, default scope).
   * @param {object} [options] - Per-instance credentials and optional config overrides.
   * @param {string} [options.clientId] - OAuth2 client ID.
   * @param {string} [options.clientSecret] - OAuth2 client secret.
   * @param {string} [options.redirectUri] - OAuth2 redirect URI.
   *
   * @throws {TargetError} If `clientId`, `clientSecret`, or `redirectUri` is missing.
   */
  constructor(
    defaults: OAuth2ConnectorConfig,
    options: OAuth2ConnectorOptions = {},
  ) {
    const {
      clientId,
      clientSecret,
      redirectUri,
      authUrl = defaults.authUrl,
      userInfoUrl = defaults.userInfoUrl,
      revokeUrl = defaults.revokeUrl,
      tokenUrl = defaults.tokenUrl,
      defaultScope = defaults.defaultScope,
      responseType = defaults.responseType ?? 'token',
      ...opts
    } = options

    super(opts)

    const { startMode } = this['_znx_props_']

    if (!clientId || !clientSecret || !redirectUri) {
      throw new TargetError(
        'OAuth2 properties or envars should be defined (clientId, clientSecret, redirectUri)',
        startMode,
        {},
      )
    }

    this.clientId = clientId
    this.clientSecret = clientSecret
    this.redirectUri = redirectUri
    this.#config = {
      authUrl,
      userInfoUrl,
      revokeUrl,
      tokenUrl,
      defaultScope,
      responseType,
    }

    if (responseType === 'token') {
      // The implicit flow (the default) hands the client a bearer token directly, with no
      // server-side step that ties it to THIS connector's own `clientId` — `authenticate()`
      // therefore trusts whatever token it's given, verified only by the provider, never by this
      // app. Prefer `responseType: 'code'` + `tokenUrl` + `authenticateWithCode()`: the token
      // exchange there uses `clientSecret` server-side, so the token it returns is provably
      // scoped to this app by construction — no separate audience check needed. Logged once per
      // connector instance, at construction, rather than per `authenticate()` call, so it stays
      // visible without flooding logs on every login.
      logger.warn(
        `${this.coreDisplayName()} uses the OAuth2 implicit flow (responseType: 'token') — ` +
          'authenticate() trusts any bearer token it receives without verifying it was issued ' +
          "for this app. Prefer 'code' + tokenUrl + authenticateWithCode() where the provider " +
          'supports it.',
        'noSave',
      )
    }
  }

  /**
   * Hook for provider-specific extra authorize-URL params (e.g. Google's
   * `include_granted_scopes`/`prompt`). Returns none by default.
   */
  protected extraAuthParams(): Record<string, string> {
    return {}
  }

  /** Derives the session subject (e.g. an email) from the provider's user-info shape. */
  protected abstract getSubject(user: TUserInfo): string

  /**
   * Generates the OAuth2 authorization URL.
   *
   * @param {string} [options.state] - A random string to maintain state between request and
   *   callback. Defaults to a newly generated UUID.
   * @param {string} [options.scope] - OAuth2 scopes to request. Defaults to the provider's
   *   configured `defaultScope`.
   * @param {'token' | 'code'} [options.responseType] - Overrides this connector's own configured
   *   `responseType` for just this call — e.g. requesting the authorization-code flow from one
   *   call site while another still uses the connector's own default. Defaults to whatever the
   *   connector was constructed with (see {@link OAuth2ConnectorConfig.responseType}).
   *
   * @returns The complete authorization URL and the `state` used to build it.
   */
  public generateAuthUrl(
    options: { state?: string; scope?: string; responseType?: 'token' | 'code' } = {},
  ): { url: string; state: string } {
    const {
      state = generateUUID(),
      scope = this.#config.defaultScope,
      responseType = this.#config.responseType,
    } = options
    const params = new URLSearchParams({
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      response_type: responseType,
      scope,
      state,
      ...this.extraAuthParams(),
    })

    return { url: `${this.#config.authUrl}?${params.toString()}`, state }
  }

  /**
   * Retrieves the associated user information for a given access token.
   *
   * @param {string} token - The OAuth2 access token to verify.
   *
   * @returns {Promise<TUserInfo>} A promise that resolves with the user information retrieved
   *   from the provider. If the token is invalid or expired, the promise rejects.
   *
   * @throws {Error} If the user-info request fails.
   */
  public async getUserInfo(token: string): Promise<TUserInfo> {
    return await this.http.get<TUserInfo>(this.#config.userInfoUrl, {
      headers: { 'Authorization': `Bearer ${token}` },
    })
  }

  /**
   * Revokes a token using the provider's token-revocation endpoint.
   *
   * @param {string} token - The token to revoke.
   *
   * @returns {Promise<boolean>} A promise that resolves to `true` once the revoke request succeeds.
   * @throws {Error} If the revoke request fails.
   */
  public async revokeToken(token: string): Promise<boolean> {
    await this.http.post<boolean>(this.#config.revokeUrl, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({ token }),
    })

    return true
  }

  /**
   * Performs the full OAuth2 authentication flow and initializes the local session for the
   * authenticated user, from an ALREADY-OBTAINED access token (the implicit flow's own shape:
   * the client got `token` directly from the provider's redirect, with no server-side exchange
   * step). This method trusts `token` was really issued for THIS app to whatever degree the
   * provider's user-info endpoint alone attests — it never independently verifies the token's
   * audience/`client_id`, since no such check is standardized across providers. If a provider
   * that also issues tokens to OTHER, unrelated OAuth2 apps is in play, a token obtained for one
   * of those could be replayed here to authenticate as its owner.
   *
   * Prefer {@link authenticateWithCode} wherever the provider supports the authorization-code
   * flow (`tokenUrl` configured): the token it hands to this same logic is provably scoped to
   * this app already, by construction, since only this app's own `clientSecret` could have
   * exchanged it — no audience check needed.
   *
   * This method handles the authentication process by:
   *  1. Retrieving the user's profile info using the provided access token.
   *  2. Creating local session tokens (access and refresh tokens) for the authenticated user,
   *     using either the provided configuration or default settings.
   *
   * @param {ScopedContext} ctx - The scoped request context where user session data will be stored.
   *
   * @param {string} token - The OAuth2 access token obtained from the client-side auth flow.
   *
   * @param {AuthSessionOptions} [sessionOptions={}] - Optional configuration object for
   *   customizing session token creation.
   *
   * @returns {Promise<{ user: TUserInfo, session: SessionTokens }>}
   *   A promise that resolves with an object containing:
   *   - `user`: The user's profile information retrieved from the provider.
   *   - `session`: The newly generated local session tokens (access and refresh).
   *
   * @throws {Error}
   *   Throws if the following errors occur:
   *   - The access token is invalid or the user-info request fails.
   *   - Session creation encounters an error (e.g., invalid session options or unexpected issues
   *     with token generation).
   */
  public async authenticate(
    ctx: ScopedContext,
    token: string,
    sessionOptions?: Partial<AuthSessionOptions>,
  ): Promise<{
    user: TUserInfo
    session: SessionTokens
  }> {
    const user = await this.getUserInfo(token)

    const session = await generateSessionTokens(ctx, {
      subject: this.getSubject(user),
      ...sessionOptions,
    })

    return {
      user,
      session,
    }
  }

  /**
   * Exchanges an authorization `code` (the authorization-code flow's own redirect param) for a
   * real access token, via a standard RFC 6749 §4.1.3 POST to `tokenUrl` — the same shape
   * virtually every real OAuth2 provider implements: `grant_type=authorization_code`, `code`,
   * `client_id`, `client_secret`, `redirect_uri`. Sent with `Accept: application/json` since a
   * couple of real providers (e.g. GitHub) otherwise default to a form-encoded response.
   *
   * Doing this exchange server-side, with `clientSecret`, is what makes the returned token
   * provably scoped to THIS connector's own `clientId` — only a party holding the secret could
   * have completed it, unlike a token handed to the client directly (the implicit flow
   * {@link authenticate} takes). See {@link authenticateWithCode} for the one-call version that
   * exchanges and authenticates together.
   *
   * @param code - The authorization code from the provider's redirect.
   * @returns The real access token.
   * @throws {InternalError} If `tokenUrl` wasn't configured (via `defaults`/`options`).
   * @throws {HttpError} If the exchange request itself fails.
   */
  protected async exchangeCode(code: string): Promise<string> {
    if (!this.#config.tokenUrl) {
      // A native `Error` here previously — a construction-time config invariant, not something
      // the flow's own caller (whoever's exchanging a code) could have caused.
      throw new InternalError(
        `${this.coreDisplayName()}: \`tokenUrl\` must be configured to use the OAuth2 ` +
          'authorization-code flow (exchangeCode/authenticateWithCode).',
        { code: 'OAUTH2_TOKEN_URL_NOT_CONFIGURED' },
      )
    }

    const { access_token } = await this.http.post<{ access_token: string }>(
      this.#config.tokenUrl,
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Accept': 'application/json',
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          client_id: this.clientId,
          client_secret: this.clientSecret,
          redirect_uri: this.redirectUri,
        }),
      },
    )

    return access_token
  }

  /**
   * {@link getUserInfo}'s own authorization-code-flow counterpart: exchanges `code` for a real
   * access token (see {@link exchangeCode}) and retrieves the associated user info with it — but,
   * unlike {@link getUserInfo}, the token behind that lookup is provably scoped to this app by
   * construction, with no separate audience check needed. For a caller that builds its own
   * session afterward (permissions, a custom payload, its own DB writes) instead of using
   * {@link authenticate}'s generic one, this is the direct, one-line replacement for
   * `getUserInfo(token)`/`validateToken(token)` in that flow.
   *
   * @param code - The authorization code from the provider's redirect.
   * @returns The user info, same shape {@link getUserInfo} returns.
   * @throws {Error} If `tokenUrl` isn't configured, the exchange fails, or the user-info request
   *   itself fails.
   */
  public async validateCode(code: string): Promise<TUserInfo> {
    const token = await this.exchangeCode(code)
    return this.getUserInfo(token)
  }

  /**
   * The authorization-code flow's own entry point — exchanges `code` for a real access token
   * (see {@link exchangeCode}) and then runs the exact same session-creation logic
   * {@link authenticate} does. This is the recommended path wherever the provider supports it:
   * the token this hands to `getUserInfo` is provably scoped to this app already, with no
   * separate audience check needed, unlike {@link authenticate}'s own implicit-flow input.
   *
   * @param {ScopedContext} ctx - The scoped request context where user session data will be stored.
   * @param {string} code - The authorization code from the provider's redirect (`?code=...`).
   * @param {AuthSessionOptions} [sessionOptions={}] - Optional configuration object for
   *   customizing session token creation.
   * @returns Same shape as {@link authenticate}.
   * @throws {Error} If `tokenUrl` isn't configured, the exchange fails, or (same as
   *   {@link authenticate}) the resulting token/session step fails.
   */
  public async authenticateWithCode(
    ctx: ScopedContext,
    code: string,
    sessionOptions?: Partial<AuthSessionOptions>,
  ): Promise<{
    user: TUserInfo
    session: SessionTokens
  }> {
    const token = await this.exchangeCode(code)
    return this.authenticate(ctx, token, sessionOptions)
  }
}
