import type { GoogleUserInfo } from 'typings/connectors.ts'

import { OAuth2Connector, type OAuth2ConnectorOptions } from '../oauth2.ts'

const ROUTES = {
  auth: 'https://accounts.google.com/o/oauth2/v2/auth',
  revoke: 'https://oauth2.googleapis.com/revoke',
  userInfo: 'https://www.googleapis.com/oauth2/v1/userinfo?alt=json',
  token: 'https://oauth2.googleapis.com/token',
}

/** Env var for {@link GoogleOAuth2Connector}'s `clientId`. Presence gates whether
 * `registerGoogleOAuth2Connector()` (`google/core.ts`) registers a default connector at all. */
export const GOOGLE_OAUTH2_CLIENT_ID_ENV = 'GOOGLE_OAUTH2_CLIENT_ID'
/** Env var for {@link GoogleOAuth2Connector}'s `clientSecret`. */
export const GOOGLE_OAUTH2_CLIENT_SECRET_ENV = 'GOOGLE_OAUTH2_CLIENT_SECRET'
/** Env var for {@link GoogleOAuth2Connector}'s `redirectUri`. */
export const GOOGLE_OAUTH2_REDIRECT_URI_ENV = 'GOOGLE_OAUTH2_REDIRECT_URI'
/** Env var overriding {@link GoogleOAuth2Connector}'s `authUrl`, defaulting to Google's real
 * authorization endpoint. */
export const GOOGLE_OAUTH2_AUTH_URL_ENV = 'GOOGLE_OAUTH2_AUTH_URL'
/** Env var overriding {@link GoogleOAuth2Connector}'s `userInfoUrl`, defaulting to Google's real
 * user-info endpoint. */
export const GOOGLE_OAUTH2_USERINFO_URL_ENV = 'GOOGLE_OAUTH2_USERINFO_URL'
/** Env var overriding {@link GoogleOAuth2Connector}'s `revokeUrl`, defaulting to Google's real
 * revoke endpoint. */
export const GOOGLE_OAUTH2_REVOKE_URL_ENV = 'GOOGLE_OAUTH2_REVOKE_URL'
/** Env var overriding {@link GoogleOAuth2Connector}'s `tokenUrl`, defaulting to Google's real
 * token endpoint. */
export const GOOGLE_OAUTH2_TOKEN_URL_ENV = 'GOOGLE_OAUTH2_TOKEN_URL'
/** Env var selecting {@link GoogleOAuth2Connector}'s `responseType` (`'token'` or `'code'`) —
 * see {@link envResponseType}. */
export const GOOGLE_OAUTH2_RESPONSE_TYPE_ENV = 'GOOGLE_OAUTH2_RESPONSE_TYPE'

/** Reads `GOOGLE_OAUTH2_RESPONSE_TYPE`, ignoring anything other than the two real values —
 * `OAuth2Connector`'s own default (`'token'`) already covers everything else, including unset. */
function envResponseType(): 'token' | 'code' | undefined {
  const value = Deno.env.get(GOOGLE_OAUTH2_RESPONSE_TYPE_ENV)
  return value === 'token' || value === 'code' ? value : undefined
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
   * @param {string} [options.tokenUrl] - Token endpoint, for `exchangeCode()`/`authenticateWithCode()`
   *   (the recommended authorization-code flow — see `OAuth2Connector`'s own doc for why). Defaults to
   *   env `GOOGLE_OAUTH2_TOKEN_URL`, then Google's real endpoint.
   * @param {'token' | 'code'} [options.responseType] - Defaults to env `GOOGLE_OAUTH2_RESPONSE_TYPE`,
   *   then `'token'` (the implicit flow). Set to `'code'` (directly, or via the env var — no code
   *   change needed for a connector registered through `@zanix/auth/core`'s own default env-driven
   *   setup) to use the recommended authorization-code flow instead.
   * @param {ConnectorOptions} [options] - Additional connector options.
   *
   * @throws {TargetError} If any required OAuth2 property is missing.
   */
  constructor(options: OAuth2ConnectorOptions = {}) {
    const {
      clientId = Deno.env.get(GOOGLE_OAUTH2_CLIENT_ID_ENV),
      clientSecret = Deno.env.get(GOOGLE_OAUTH2_CLIENT_SECRET_ENV),
      redirectUri = Deno.env.get(GOOGLE_OAUTH2_REDIRECT_URI_ENV),
      authUrl = Deno.env.get(GOOGLE_OAUTH2_AUTH_URL_ENV),
      userInfoUrl = Deno.env.get(GOOGLE_OAUTH2_USERINFO_URL_ENV),
      revokeUrl = Deno.env.get(GOOGLE_OAUTH2_REVOKE_URL_ENV),
      tokenUrl = Deno.env.get(GOOGLE_OAUTH2_TOKEN_URL_ENV),
      responseType = envResponseType(),
      ...opts
    } = options

    super({
      authUrl: ROUTES.auth,
      userInfoUrl: ROUTES.userInfo,
      revokeUrl: ROUTES.revoke,
      tokenUrl: ROUTES.token,
      defaultScope: 'openid email profile',
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
