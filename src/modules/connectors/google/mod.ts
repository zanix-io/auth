import type { GoogleTokens, GoogleUserInfo } from 'typings/connectors.ts'
import type { SessionTokens } from 'typings/sessions.ts'
import type { AuthSessionOptions } from 'typings/auth.ts'

import { generateSessionTokens } from 'utils/sessions/create.ts'
import { type ConnectorOptions, RestClient, type ScopedContext, TargetError } from '@zanix/server'
import { generateUUID } from '@zanix/helpers'

const ROUTES = {
  auth: 'https://accounts.google.com/o/oauth2/v2/auth',
  revoke: 'https://oauth2.googleapis.com/revoke',
  token: 'https://oauth2.googleapis.com/token',
  tokenInfo: 'https://oauth2.googleapis.com/tokeninfo',
}

/**
 * Base connector for handling Google OAuth2 authentication flows.
 * Extends {@link RestClient} and provides utility methods for generating
 * authorization URLs, exchanging authorization codes for tokens, and verifying ID tokens.
 */
export class GoogleOAuth2Connector extends RestClient {
  /** @private Google OAuth2 Client ID. */
  private clientId: string

  /** @private Google OAuth2 Client Secret. */
  private clientSecret: string

  /** @private Redirect URI registered in Google Cloud Console. */
  private redirectUri: string

  /**
   * Creates a new GoogleOAuth2Connector instance.
   *
   * @param {object} [options] - Connector configuration options.
   * @param {string} [options.clientId] - Google OAuth2 Client ID. Defaults to env `GOOGLE_OAUTH2_CLIENT_ID`.
   * @param {string} [options.clientSecret] - Google OAuth2 Client Secret. Defaults to env `GOOGLE_OAUTH2_CLIENT_SECRET`.
   * @param {string} [options.redirectUri] - OAuth2 redirect URI. Defaults to env `GOOGLE_OAUTH2_REDIRECT_URI`.
   * @param {ConnectorOptions} [options] - Additional connector options.
   *
   * @throws {TargetError} If any required OAuth2 property is missing.
   */
  constructor(
    options: {
      clientId?: string
      clientSecret?: string
      redirectUri?: string
    } & ConnectorOptions = {},
  ) {
    const {
      clientId = Deno.env.get('GOOGLE_OAUTH2_CLIENT_ID'),
      clientSecret = Deno.env.get('GOOGLE_OAUTH2_CLIENT_SECRET'),
      redirectUri = Deno.env.get('GOOGLE_OAUTH2_REDIRECT_URI'),
      ...opts
    } = options

    super(opts)

    const { startMode } = this['_znx_props_']

    if (!clientId || !clientSecret || !redirectUri) {
      throw new TargetError(
        'Google OAUTH2 Properties or envars should be defined (clientId, clientSecret, redirectUri)',
        startMode,
        {},
      )
    }

    this.clientId = clientId
    this.clientSecret = clientSecret
    this.redirectUri = redirectUri
  }

  /**
   * Generates the Google OAuth2 authorization URL.
   *
   * @param {string} [state] - A random string to maintain state between request and callback.
   *                           Defaults to a newly generated UUID.
   * @param {string} [scope='openid email profile'] - OAuth2 scopes to request.
   *
   * @returns {string} The complete Google OAuth2 authorization URL.
   */
  public generateAuthUrl(
    state: string = generateUUID(),
    scope: string = 'openid email profile',
  ): string {
    const params = new URLSearchParams({
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      response_type: 'code',
      access_type: 'offline',
      include_granted_scopes: 'true',
      prompt: 'consent',
      scope,
      state,
    })

    return `${ROUTES.auth}?${params.toString()}`
  }

  /**
   * Exchanges an authorization code for access, refresh, and ID tokens.
   *
   * @param {string} code - The authorization code returned by Google's OAuth2 redirect.
   *
   * @returns {Promise<GoogleTokens>} A promise resolving to Google OAuth2 tokens.
   */
  public async getTokens(code: string): Promise<GoogleTokens> {
    const response = await this.http.post<GoogleTokens>(ROUTES.token, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: this.clientId,
        client_secret: this.clientSecret,
        grant_type: 'authorization_code',
        redirect_uri: this.redirectUri,
        code,
      }),
    })

    return response
  }

  /**
   * Verifies and decodes a Google ID token using Google's token verification endpoint.
   *
   * @param {string} idToken - The ID token to verify.
   *
   * @returns {Promise<GoogleUserInfo>} A promise resolving to user information extracted from the ID token.
   */
  public async verifyIdToken(idToken: string): Promise<GoogleUserInfo> {
    const response = await this.http.get<GoogleUserInfo>(`${ROUTES.tokenInfo}?id_token=${idToken}`)

    return response
  }

  /**
   * Revokes a Google token using Google's token revoke endpoint.
   *
   * @param {string} token - The token to revoke.
   *
   * @returns {Promise<boolean>} A promise that resolves to `true` if the token was successfully revoked, or `false` otherwise.
   */
  public async revokeToken(token: string): Promise<boolean> {
    await this.http.post<boolean>(ROUTES.revoke, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({ token }),
    })

    return true
  }

  /**
   * Performs the full Google OAuth2 authentication flow and initializes
   * the local session for the authenticated user.
   *
   * This convenience method:
   *  1. Exchanges the received Google authorization code for OAuth2 tokens.
   *  2. Verifies and decodes the ID token to obtain user information.
   *  3. Creates local access and refresh session tokens based on the provided
   *     configuration or sensible defaults.
   *
   * @template T extends SessionTypes
   *
   * @param {string} code
   *   The authorization code returned by Google's OAuth2 redirect.
   *
   * @param {ScopedContext} ctx
   *   The scoped request context in which the local session user info
   *   will be stored.
   *
   * @param {AuthSessionOptions} [sessionOptions={}]
   *   Optional configuration for customizing the generated local session
   *   tokens (e.g., `rateLimit` or `permissions`).

   * @returns {Promise<{
   *    tokens: GoogleTokens,
   *    user: GoogleUserInfo,
   *    sessionTokens: SessionTokens
   * }>}
   *   Resolves with:
   *   - `tokens`: The raw Google OAuth2 tokens (access, refresh, and ID token).
   *   - `user`: The verified and decoded user profile extracted from the ID token.
   *   - `sessionTokens`: The newly generated local access and refresh tokens along
   *     with the effective subject.
   *
   * @throws {Error}
   *   Throws if token exchange fails, ID token validation fails, or if session
   *   creation encounters an unexpected error.
   */
  public async authenticate(
    code: string,
    ctx: ScopedContext,
    sessionOptions?: AuthSessionOptions,
  ): Promise<{
    tokens: GoogleTokens
    user: GoogleUserInfo
    session: SessionTokens
  }> {
    const tokens = await this.getTokens(code)
    const user = await this.verifyIdToken(tokens.id_token)

    const session = await generateSessionTokens(ctx, { subject: user.email, ...sessionOptions })

    return {
      tokens,
      user,
      session,
    }
  }
}
