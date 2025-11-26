import type { GoogleTokens, GoogleUserInfo } from 'typings/connectors.ts'
import type { ZanixAuthProvider } from '../auth.ts'
import type { OAuthFlow } from 'typings/auth.ts'

export function google(this: ZanixAuthProvider): OAuthFlow<GoogleTokens, GoogleUserInfo> {
  return {
    generateAuthUrl: () => this.use('google-oauth2').generateAuthUrl(),
    authenticate: (code, sessionOptions) =>
      this.use('google-oauth2').authenticate(code, this.context, sessionOptions),
  }
}
