import type { AuthSessionOptions, SessionFlow } from 'typings/auth.ts'
import type { ZanixAuthProvider } from '../auth.ts'

import { generateSessionTokens } from 'utils/sessions/create.ts'
import { refreshSessionTokens } from 'utils/sessions/refresh.ts'
import { revokeSessionToken } from 'utils/sessions/revoke.ts'

export function session(this: ZanixAuthProvider): SessionFlow {
  return {
    generateTokens: (options: AuthSessionOptions) => generateSessionTokens(this.context, options),
    refreshTokens: (token?: string) =>
      refreshSessionTokens(this.context, token, { cache: this.cache, kvDb: this.kvLocal }),
    revokeToken: (token?: string) =>
      revokeSessionToken(this.context, {
        cache: this.cache,
        kvDb: this.kvLocal,
        token,
      }),
  }
}
