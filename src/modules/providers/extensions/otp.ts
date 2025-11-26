import type { ZanixAuthProvider } from '../auth.ts'
import type { OtpFlow } from 'typings/auth.ts'
import type { SessionTokens } from 'typings/sessions.ts'

import { generateSessionTokens } from 'utils/sessions/create.ts'
import { generateOTP, verifyOTP } from 'utils/otp.ts'
import { HttpError } from '@zanix/errors'

export function otp(this: ZanixAuthProvider): OtpFlow {
  return {
    generate: (options) => generateOTP(this.cache, options),
    verify: (target, code) => verifyOTP(this.cache, target, code),
    authenticate: async (ctx, target, code, options): Promise<SessionTokens> => {
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

      return generateSessionTokens(ctx, { ...options, subject: target })
    },
  }
}
