import type { ZanixAuthProvider } from '../auth.ts'
import type { OtpFlow } from 'typings/auth.ts'
import type { SessionTokens } from 'typings/sessions.ts'

import { generateSessionTokens } from 'utils/sessions/create.ts'
import { generateOTP, verifyOTP } from 'utils/otp.ts'
import { HttpError } from '@zanix/errors'

export function otp(this: ZanixAuthProvider): OtpFlow {
  return {
    generate: (options) => generateOTP(this.cache, options),
    verify: (target, code, options) => verifyOTP(this.cache, target, code, options),
    authenticate: async (target, code, options, verifyOptions): Promise<SessionTokens> => {
      const isValid = await verifyOTP(this.cache, target, code, verifyOptions)

      if (!isValid) {
        throw new HttpError('FORBIDDEN', {
          code: 'INVALID_OTP',
          cause: 'The provided OTP does not match the expected value.',
          meta: {
            source: 'zanix',
            // Named `otpCode`/`otpTarget`, not the generic `code`/`target` — `@zanix/logger`'s
            // default redaction pattern specifically recognizes this OTP-namespaced pair (see
            // `redact.ts`'s own doc) so the submitted code and its delivery destination never
            // reach a log/response unredacted. The bare `code`/`target` names would NOT be
            // redacted (too generic to safely blanket-match), so this naming is load-bearing,
            // not cosmetic.
            otpCode: code,
            otpTarget: target,
          },
        })
      }

      return generateSessionTokens(this.context, {
        subject: target,
        ...options,
      })
    },
  }
}
