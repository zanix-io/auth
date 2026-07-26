import type { ZanixAuthProvider } from '../auth.ts'
import type { AuthSessionOptions, TotpFlow, TOTPVerifyOptions } from 'typings/auth.ts'
import type { SessionTokens } from 'typings/sessions.ts'

import { generateSessionTokens } from 'utils/sessions/create.ts'
import { generateTOTPSecret, getTOTPProvisioningUri, verifyTOTP } from 'utils/totp.ts'
import { HttpError } from '@zanix/errors'

export function totp(this: ZanixAuthProvider): TotpFlow {
  return {
    generateSecret: (length) => generateTOTPSecret(length),
    getProvisioningUri: (secret, accountName, options) =>
      getTOTPProvisioningUri(secret, accountName, options),
    verify: (secret, code, options) => verifyTOTP(secret, code, options),
    authenticate: async (
      secret: string,
      code: string,
      sessionOptions: AuthSessionOptions,
      options?: TOTPVerifyOptions,
    ): Promise<SessionTokens> => {
      const isValid = await verifyTOTP(secret, code, options)

      if (!isValid) {
        throw new HttpError('FORBIDDEN', {
          code: 'INVALID_TOTP',
          cause: 'The provided TOTP code does not match the expected value.',
          meta: {
            source: 'zanix',
          },
        })
      }

      return generateSessionTokens(this.context, sessionOptions)
    },
  }
}
