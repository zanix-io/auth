import type { AuthSessionOptions, SessionFlow } from 'typings/auth.ts'
import type { ZanixAuthProvider } from '../auth.ts'

import { generateSessionTokens, refreshSessionTokens } from 'utils/sessions/create.ts'
import { revokeSessionToken } from 'utils/sessions/revoke.ts'

export function session(this: ZanixAuthProvider): SessionFlow {
  return {
    generateTokens: (options: AuthSessionOptions) => generateSessionTokens(this.context, options),
    refreshTokens: (token?: string) => refreshSessionTokens(this.context, token),
    revokeToken: (token?: string) =>
      revokeSessionToken(this.context, {
        cache: this.cache,
        kvDb: this.kvLocal,
        token,
      }),
  }
}
