import type { ZanixAuthProvider } from '../auth.ts'
import type { AuthSessionOptions, GenerateOTPOptions } from 'typings/auth.ts'
import type { SessionTokens, SessionTypes } from 'typings/sessions.ts'
import type { ScopedContext } from '@zanix/server'

import { generateSessionTokens } from 'modules/sessions/create.ts'
import { generateOTP, verifyOTP } from 'utils/otp.ts'
import { HttpError } from '@zanix/errors'

export function otp(this: ZanixAuthProvider) {
  return {
    /**
     * Generates a numeric OTP and stores it in the configured cache provider.
     *
     * The OTP is associated with a unique `target` (such as an email, phone number,
     * or user ID) and saved with an expiration time (TTL).
     *
     * @param {GenerateOTPOptions} options - The OTP data and settings.
     */
    generate: (options: GenerateOTPOptions) => generateOTP(this.cache, options),
    /**
     * @param target
     * @param code
     */
    verify: (
      /**
       * Target identifier for the OTP delivery.
       * Typically an email address or phone number.
       */
      target: string,
      /**
       * The one-time password (OTP) code that the user provides for verification.
       */
      code: string,
    ) => verifyOTP(this.cache, target, code),
    /**
     * Performs the full OTP authentication flow and initializes
     * the local session for the authenticated user.
     */
    authenticate: async <T extends SessionTypes>(
      /**
       * The scoped request context in which the local session user info
       * will be stored.
       */
      ctx: ScopedContext,
      /**
       * Target identifier for the OTP delivery.
       * Typically an email address or phone number.
       */
      target: string,
      /**
       * The one-time password (OTP) code that the user provides for verification.
       */
      code: string,
      /** Optional configuration for customizing the generated local session */
      sessionTokens: AuthSessionOptions<T> = {},
    ): Promise<SessionTokens> => {
      const { access, refresh } = sessionTokens
      const isValid = await verifyOTP(this.cache, target, code)

      if (!isValid) {
        throw new HttpError('FORBIDDEN', {
          code: 'INVALID_OTP',
          cause: 'The provided OTP does not match the expected value.',
          meta: {
            source: 'zanix',
            code,
            target,
          },
        })
      }

      return generateSessionTokens(ctx, { access, refresh, subject: target })
    },
  }
}
