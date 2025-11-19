import type { GoogleOAuth2Connector } from 'modules/connectors/google/mod.ts'

export interface GoogleTokens {
  // deno-lint-ignore camelcase
  access_token: string
  // deno-lint-ignore camelcase
  id_token: string
  // deno-lint-ignore camelcase
  refresh_token?: string
  // deno-lint-ignore camelcase
  expires_in: number
  // deno-lint-ignore camelcase
  token_type: string
}

export interface GoogleUserInfo {
  sub: string
  email: string
  // deno-lint-ignore camelcase
  email_verified: boolean
  name?: string
  picture?: string
}

export type AuthConnectors = {
  'google-oauth2': GoogleOAuth2Connector
}

export type CoreAuthConnectors = keyof AuthConnectors
