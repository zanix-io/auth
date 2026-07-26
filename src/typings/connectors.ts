import type { GoogleOAuth2Connector } from 'modules/connectors/google/mod.ts'

/** User profile information returned by Google's OAuth2 userinfo endpoint. */
export interface GoogleUserInfo {
  /** Google account unique identifier. */
  id: string
  /** User's email address. */
  email: string
  /** Whether the email address has been verified by Google. */
  // deno-lint-ignore camelcase
  verified_email: boolean
  /** User's full display name. */
  name: string
  /** User's given (first) name. */
  // deno-lint-ignore camelcase
  given_name: string
  /** User's family (last) name. */
  // deno-lint-ignore camelcase
  family_name: string
  /** URL of the user's profile picture. */
  picture: string
  /** Hosted G Suite/Workspace domain, when the account belongs to one. */
  hd: string
}

/** Maps each core auth-connector key to its concrete connector class. */
export type AuthConnectors = {
  'google-oauth2': GoogleOAuth2Connector
}

/** The set of core auth-connector keys usable with {@link AuthConnectors}. */
export type CoreAuthConnectors = keyof AuthConnectors
