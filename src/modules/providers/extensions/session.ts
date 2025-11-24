import type { AuthSessionOptions, SessionFlow } from 'typings/auth.ts'
import type { SessionTypes } from 'typings/sessions.ts'
import type { ZanixAuthProvider } from '../auth.ts'

import { generateSessionTokens } from 'utils/sessions/create.ts'
import { revokeSessionToken } from 'utils/sessions/revoke.ts'

export function session(this: ZanixAuthProvider): SessionFlow {
  return {
    generateTokens: <T extends SessionTypes>(
      sessionTokens: AuthSessionOptions<T> & { subject: string; type?: T },
    ) => generateSessionTokens(this.context, sessionTokens),
    revokeToken: (token: string, type?: SessionTypes) =>
      revokeSessionToken(this.context, {
        cache: this.cache,
        token,
        kvDb: this.kvLocal,
        sessionType: type,
      }),
  }
}
