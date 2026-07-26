import type { AuthConnectors, CoreAuthConnectors, GoogleUserInfo } from 'typings/connectors.ts'
import type { OAuthFlow, OtpFlow, SessionFlow, TotpFlow } from 'typings/auth.ts'

import { ZanixCoreAuthProvider } from '@zanix/server'
import { authConnectors } from '../connectors/mod.ts'
import { session } from './extensions/session.ts'
import { otp } from './extensions/otp.ts'
import { totp } from './extensions/totp.ts'
import { google } from './extensions/google.ts'

/**
 * ZanixAuthProvider is the default authentication provider implementation for the Zanix framework.
 *
 * This class extends `@zanix/server`'s `ZanixCoreAuthProvider` (which is what makes it eligible
 * for the `'auth'` core-provider key — see `providers/core.ts`) to provide authentication
 * connectors for various providers such as Google OAuth2, One-Time Password (OTP), and TOTP
 * authenticator-app 2FA.
 *
 * It allows selecting a connector dynamically with `use()` or accessing
 * predefined connectors via properties (`google`, `otp`, `totp`).
 */
export class ZanixAuthProvider extends ZanixCoreAuthProvider {
  /**
   * Resolves a connector instance by its core-connector key (e.g. `'google-oauth2'`).
   *
   * @param connector - The core-connector key to resolve, as defined in `authConnectors`.
   * @param verbose - Whether to log when the connector instance is not available.
   * @returns The resolved connector instance for the given key.
   */
  public override use<T extends CoreAuthConnectors>(
    connector: T,
    verbose: boolean = false,
  ): AuthConnectors[T] {
    return this.getProviderConnector<AuthConnectors[T]>(authConnectors[connector], verbose)
  }

  /**
   * Google OAuth2 authentication connector.
   *
   * Provides methods for generating the Google auth URL, retrieving user info from
   * an access token, and completing the local sign-in session.
   *
   * @example
   * ```ts
   * const user = await authProvider.google.authenticate(code);
   * ```
   */
  public google: OAuthFlow<GoogleUserInfo> = google.call(this)

  /**
   * One-Time Password (OTP) authentication connector.
   *
   * Provides methods for generating, sending, and verifying OTP codes.
   *
   * @example
   * ```ts
   * const otpInstance = authProvider.otp;
   * const verified = await otpInstance.verify(target, code);
   * ```
   */
  public otp: OtpFlow = otp.call(this)

  /**
   * TOTP (Time-based One-Time Password) 2FA connector, compatible with authenticator apps such
   * as Google Authenticator and Microsoft Authenticator.
   *
   * @example
   * ```ts
   * const secret = authProvider.totp.generateSecret();
   * const uri = authProvider.totp.getProvisioningUri(secret, user.email, { issuer: 'MyApp' });
   * // ...render `uri` as a QR code for enrollment, persist `secret` on the user record...
   * const session = await authProvider.totp.authenticate(secret, code, { subject: user.email });
   * ```
   */
  public totp: TotpFlow = totp.call(this)

  /**
   * Session lifecycle methods: generate, refresh, and revoke session tokens
   * (access and refresh).
   */
  public session: SessionFlow = session.call(this)
}
