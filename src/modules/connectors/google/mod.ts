import type { GoogleUserInfo } from 'typings/connectors.ts'
import type { SessionTokens } from 'typings/sessions.ts'
import type { AuthSessionOptions } from 'typings/auth.ts'

import { generateSessionTokens } from 'utils/sessions/create.ts'
import { type ConnectorOptions, RestClient, type ScopedContext, TargetError } from '@zanix/server'
import { generateUUID } from '@zanix/helpers'

const ROUTES = {
  auth: 'https://accounts.google.com/o/oauth2/v2/auth',
  revoke: 'https://oauth2.googleapis.com/revoke',
  userInfo: 'https://www.googleapis.com/oauth2/v1/userinfo',
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
   * @param {string} [options.state] - A random string to maintain state between request and callback.
   *                           Defaults to a newly generated UUID.
   * @param {string} [options.scope='openid email profile'] - OAuth2 scopes to request.
   *
   * @returns {string} The complete Google OAuth2 authorization URL.
   */
  public generateAuthUrl(
    options: { state?: string; scope?: string } = {},
  ): { url: string; state: string } {
    const { state = generateUUID(), scope = 'openid email profile' } = options
    const params = new URLSearchParams({
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      response_type: 'token',
      include_granted_scopes: 'true',
      prompt: 'consent',
      scope,
      state,
    })

    return { url: `${ROUTES.auth}?${params.toString()}`, state }
  }

  /**
   * Verifies a Google OAuth token and retrieves the associated user information.
   *
   * This method sends a request to the Google API to fetch user details, such as their profile
   * information, based on the provided access token.
   *
   * @param {string} token - The Google OAuth 2.0 access token to be verified.
   * The token should be a valid bearer token obtained from Google's OAuth 2.0 authentication flow.
   *
   * @returns {Promise<GoogleUserInfo>} A promise that resolves with the user information
   * retrieved from Google, such as email, name, and profile details.
   * If the token is invalid or expired, the promise will be rejected with an error.
   *
   * @throws {Error} If the token verification fails or the user information cannot be retrieved.
   */
  public async getUserInfo(token: string): Promise<GoogleUserInfo> {
    const response = await this.http.get<GoogleUserInfo>(`${ROUTES.userInfo}?alt=json`, {
      headers: { 'Authorization': `Bearer ${token}` },
    })

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
   * This method handles the entire authentication process by:
   *  1. Exchanging the received Google authorization code for OAuth2 tokens (access, refresh, and ID tokens).
   *  2. Verifying and decoding the ID token to extract user profile information (e.g., email, name).
   *  3. Creating local session tokens (access and refresh tokens) for the authenticated user,
   *     using either the provided configuration or default settings.
   *
   * @template T extends SessionTypes
   *
   * @param {string} token - The authorization code returned by Google after user authentication.
   *   This code is used to request OAuth2 tokens from Google's token endpoint.
   *
   * @param {ScopedContext} ctx - The scoped request context where user session data will be stored.
   *   Typically, this contains the user's session and other related context for the current request.
   *
   * @param {AuthSessionOptions} [sessionOptions={}] - Optional configuration object for customizing session token creation.
   *   For example, this can include rate limiting, custom permissions, or other session-related settings.
   *
   * @returns {Promise<{ user: GoogleUserInfo, sessionTokens: SessionTokens }>}
   *   A promise that resolves with an object containing:
   *   - `user`: The user's profile information retrieved and decoded from the Google ID token (e.g., email, name, profile picture).
   *   - `sessionTokens`: The newly generated local session tokens, including access and refresh tokens, along with the authenticated user's subject (usually the user's email).
   *
   * @throws {Error}
   *   Throws if the following errors occur:
   *   - Token exchange fails (e.g., invalid or expired authorization code).
   *   - ID token validation fails (e.g., invalid or malformed ID token).
   *   - Session creation encounters an error (e.g., invalid session options or unexpected issues with token generation).
   */
  public async authenticate(
    ctx: ScopedContext,
    token: string,
    sessionOptions?: Partial<AuthSessionOptions>,
  ): Promise<{
    user: GoogleUserInfo
    session: SessionTokens
  }> {
    const user = await this.getUserInfo(token)

    const session = await generateSessionTokens(ctx, { subject: user.email, ...sessionOptions })

    return {
      user,
      session,
    }
  }
}
