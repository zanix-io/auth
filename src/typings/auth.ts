import type { AccessTokenOptions, RefreshTokenOptions, SessionTypes } from './sessions.ts'
import type { JWTAlgorithm, JWTVerifyOptions } from './jwt.ts'

/**
 * Configuration options for JWT validation.
 * This type defines the available options for validating JWTs, including rate limit validation,
 * role-based access control, and session token type. It extends the `JWTVerifyOptions` type to include
 * common JWT verification options-
 */
export type JWTValidationOpts = {
  /**
   * Whether to validate the rate limit. Defaults to `true`.
   * If set to `false`, the rate limit check will be skipped, and no restrictions will be applied based on session rate limit.
   */
  rateLimit?: boolean
  /**
   * Permissions required to access the protected resource.
   * Can be roles, scopes, permissions, or audience claims.
   * This can be a single string or an array of strings.
   * For example, `['admin', 'write:user']`.
   */
  permissions?: string[] | string
  /**
   * The type of session token. Defaults to `'user'`.
   * If set to `user`, the token will be extracted from the `Authorization: Bearer <token>` header.
   * If set to `api`, the token will be extracted from the `X-Znx-Authorization: Bearer <token>` header.
   *
   * Depending on the selected `type`, the corresponding algorithm is assigned for JWT verification
   *
   * - `type: "user"` → **HS256**
   * - `type: "api"`  → **RS256**
   */
  type?: SessionTypes
  /** Specify an algorithm only if it differs from the project standard. */
  algorithm?: JWTAlgorithm
} & Omit<JWTVerifyOptions, 'aud' | 'algorithm'>

export type GenerateOTPOptions = {
  /**
   * Target identifier for the OTP delivery.
   * Typically an email address or phone number.
   */
  target: string

  /**
   * Expiration time of the generated OTP, in seconds.
   * Optional; defaults to a system-defined value if not provided.
   */
  exp?: number

  /**
   * Length of the OTP (number of digits or characters).
   * Optional; defaults to the standard length defined in the system.
   */
  length?: number
}

export type AuthSessionOptions<T extends SessionTypes> = {
  /** Session access token */
  access?: Partial<AccessTokenOptions<T>>
  /** Session refresh token */
  refresh?: Partial<RefreshTokenOptions<T>>
}
