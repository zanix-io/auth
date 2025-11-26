import type { AuthConnectors, CoreAuthConnectors, GoogleUserInfo } from 'typings/connectors.ts'
import type { OAuthFlow, OtpFlow, SessionFlow } from 'typings/auth.ts'

import { ZanixProvider } from '@zanix/server'
import { authConnectors } from '../connectors/mod.ts'
import { session } from './extensions/session.ts'
import { otp } from './extensions/otp.ts'
import { google } from './extensions/google.ts'

/**
 * ZanixAuthProvider is the default authentication provider implementation for the Zanix framework.
 *
 * This class extends `ZanixProvider` to provide authentication connectors
 * for various providers such as Google OAuth2 and One-Time Password (OTP).
 *
 * It allows selecting a connector dynamically with `use()` or accessing
 * predefined connectors via properties (`google`, `otp`).
 */
export class ZanixAuthProvider extends ZanixProvider {
  public override use<T extends CoreAuthConnectors>(
    connector: T,
    verbose: boolean = false,
  ): AuthConnectors[T] {
    return this.getProviderConnector<AuthConnectors[T]>(authConnectors[connector], verbose)
  }

  /**
   * Google OAuth2 authentication connector.
   *
   * Provides methods for handling Google sign-in flows, exchanging authorization codes,
   * and verifying ID tokens.
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
   * Generates an revoke session tokens (access and refresh).
   */
  public session: SessionFlow = session.call(this)
}
