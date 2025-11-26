import type { GoogleUserInfo } from 'typings/connectors.ts'
import type { ZanixAuthProvider } from '../auth.ts'
import type { OAuthFlow } from 'typings/auth.ts'

export function google(this: ZanixAuthProvider): OAuthFlow<GoogleUserInfo> {
  return {
    generateAuthUrl: () => this.use('google-oauth2').generateAuthUrl(),
    authenticate: (token, sessionOptions) =>
      this.use('google-oauth2').authenticate(this.context, token, sessionOptions),
  }
}
