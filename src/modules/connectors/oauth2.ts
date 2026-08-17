import type { AuthSessionOptions } from 'typings/auth.ts'
import type { SessionTokens } from 'typings/sessions.ts'

import { generateSessionTokens } from 'utils/sessions/create.ts'
import { type ConnectorOptions, RestClient, type ScopedContext, TargetError } from '@zanix/server'
import { generateUUID } from '@zanix/helpers'

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
 * @example
 * ```ts
 * class GitHubOAuth2Connector extends OAuth2Connector<{ id: number; email: string }> {
 *   constructor(options: OAuth2ConnectorOptions = {}) {
 *     super({
 *       authUrl: 'https://github.com/login/oauth/authorize',
 *       userInfoUrl: 'https://api.github.com/user',
 *       revokeUrl: 'https://api.github.com/applications/{client_id}/token',
 *       defaultScope: 'read:user user:email',
 *     }, options)
 *   }
 *
 *   protected getSubject(user: { id: number; email: string }): string {
 *     return user.email
 *   }
 * }
 * ```
 */
export abstract class OAuth2Connector<TUserInfo> extends RestClient {
  #config: Required<OAuth2ConnectorConfig>

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
      defaultScope,
      responseType,
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
   *
   * @returns The complete authorization URL and the `state` used to build it.
   */
  public generateAuthUrl(
    options: { state?: string; scope?: string } = {},
  ): { url: string; state: string } {
    const { state = generateUUID(), scope = this.#config.defaultScope } = options
    const params = new URLSearchParams({
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      response_type: this.#config.responseType,
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
   * authenticated user.
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
}
