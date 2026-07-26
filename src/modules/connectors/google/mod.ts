import type { GoogleUserInfo } from 'typings/connectors.ts'

import { OAuth2Connector, type OAuth2ConnectorOptions } from '../oauth2.ts'

const ROUTES = {
  auth: 'https://accounts.google.com/o/oauth2/v2/auth',
  revoke: 'https://oauth2.googleapis.com/revoke',
  userInfo: 'https://www.googleapis.com/oauth2/v1/userinfo?alt=json',
}

/**
 * Connector for handling Google OAuth2 authentication flows.
 * Extends {@link OAuth2Connector} with Google's specific endpoints, extra authorization params,
 * and how to derive the session subject from {@link GoogleUserInfo}.
 */
export class GoogleOAuth2Connector extends OAuth2Connector<GoogleUserInfo> {
  /**
   * Creates a new GoogleOAuth2Connector instance.
   *
   * @param {object} [options] - Connector configuration options.
   * @param {string} [options.clientId] - Google OAuth2 Client ID. Defaults to env `GOOGLE_OAUTH2_CLIENT_ID`.
   * @param {string} [options.clientSecret] - Google OAuth2 Client Secret. Defaults to env `GOOGLE_OAUTH2_CLIENT_SECRET`.
   * @param {string} [options.redirectUri] - OAuth2 redirect URI. Defaults to env `GOOGLE_OAUTH2_REDIRECT_URI`.
   * @param {string} [options.authUrl] - Authorization endpoint. Defaults to env `GOOGLE_OAUTH2_AUTH_URL`,
   *   then Google's real endpoint. Only useful for enterprise proxies or testing.
   * @param {string} [options.userInfoUrl] - User-info endpoint. Defaults to env `GOOGLE_OAUTH2_USERINFO_URL`,
   *   then Google's real endpoint.
   * @param {string} [options.revokeUrl] - Token-revocation endpoint. Defaults to env `GOOGLE_OAUTH2_REVOKE_URL`,
   *   then Google's real endpoint.
   * @param {ConnectorOptions} [options] - Additional connector options.
   *
   * @throws {TargetError} If any required OAuth2 property is missing.
   */
  constructor(options: OAuth2ConnectorOptions = {}) {
    const {
      clientId = Deno.env.get('GOOGLE_OAUTH2_CLIENT_ID'),
      clientSecret = Deno.env.get('GOOGLE_OAUTH2_CLIENT_SECRET'),
      redirectUri = Deno.env.get('GOOGLE_OAUTH2_REDIRECT_URI'),
      authUrl = Deno.env.get('GOOGLE_OAUTH2_AUTH_URL'),
      userInfoUrl = Deno.env.get('GOOGLE_OAUTH2_USERINFO_URL'),
      revokeUrl = Deno.env.get('GOOGLE_OAUTH2_REVOKE_URL'),
      ...opts
    } = options

    super({
      authUrl: ROUTES.auth,
      userInfoUrl: ROUTES.userInfo,
      revokeUrl: ROUTES.revoke,
      defaultScope: 'openid email profile',
    }, { clientId, clientSecret, redirectUri, authUrl, userInfoUrl, revokeUrl, ...opts })
  }

  /** Google-specific authorize-URL params: request incremental scopes and force the consent screen. */
  protected override extraAuthParams(): Record<string, string> {
    return { include_granted_scopes: 'true', prompt: 'consent' }
  }

  /** Uses the user's Google account email as the session subject. */
  protected getSubject(user: GoogleUserInfo): string {
    return user.email
  }
}
