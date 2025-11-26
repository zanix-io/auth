import type { GoogleOAuth2Connector } from 'modules/connectors/google/mod.ts'

export interface GoogleUserInfo {
  id: string
  email: string
  // deno-lint-ignore camelcase
  verified_email: boolean
  name: string
  // deno-lint-ignore camelcase
  given_name: string
  // deno-lint-ignore camelcase
  family_name: string
  picture: string
  hd: string
}

export type AuthConnectors = {
  'google-oauth2': GoogleOAuth2Connector
}

export type CoreAuthConnectors = keyof AuthConnectors
