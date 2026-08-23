import type { GoogleOAuth2Connector } from 'modules/connectors/google/mod.ts'
import type { GitHubOAuth2Connector } from 'modules/connectors/github/mod.ts'

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

/**
 * User profile information returned by GitHub's `GET /user` REST endpoint
 * (https://docs.github.com/en/rest/users/users#get-the-authenticated-user).
 *
 * Unlike Google's userinfo response, `email` here can be `null` — a user with a private email
 * setting (and no public email configured) never exposes one through this endpoint, even with the
 * `user:email` scope granted. `id` is GitHub's own immutable numeric account identifier, and is the
 * only field guaranteed both present and stable, which is why `GitHubOAuth2Connector.getSubject()`
 * derives the session subject from it instead of `email` (unlike `GoogleOAuth2Connector`, where
 * `email` is always present and never changes).
 */
export interface GitHubUserInfo {
  /** GitHub account's immutable numeric identifier. */
  id: number
  /** GitHub username — mutable; a user can rename it at any time. */
  login: string
  /** User's public email address, or `null` when the account keeps it private. */
  email: string | null
  /** User's full display name, or `null` when not set. */
  name: string | null
  /** URL of the user's avatar image. */
  // deno-lint-ignore camelcase
  avatar_url: string
}

/** Maps each core auth-connector key to its concrete connector class. */
export type AuthConnectors = {
  'google-oauth2': GoogleOAuth2Connector
  'github-oauth2': GitHubOAuth2Connector
}

/** The set of core auth-connector keys usable with {@link AuthConnectors}. */
export type CoreAuthConnectors = keyof AuthConnectors
