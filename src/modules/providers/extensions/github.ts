import type { GitHubUserInfo } from 'typings/connectors.ts'
import type { ZanixAuthProvider } from '../auth.ts'
import type { OAuthFlow } from 'typings/auth.ts'

export function github(this: ZanixAuthProvider): OAuthFlow<GitHubUserInfo> {
  return {
    generateAuthUrl: (options) => this.use('github-oauth2').generateAuthUrl(options),
    validateToken: (token) => this.use('github-oauth2').getUserInfo(token),
    validateCode: (code) => this.use('github-oauth2').validateCode(code),
    authenticate: (token, sessionOptions) =>
      this.use('github-oauth2').authenticate(
        this.context,
        token,
        sessionOptions,
      ),
    authenticateWithCode: (code, sessionOptions) =>
      this.use('github-oauth2').authenticateWithCode(
        this.context,
        code,
        sessionOptions,
      ),
  }
}
