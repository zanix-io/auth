import type { AppTokenBaseAccess, SessionTokens, SessionTypes } from './sessions.ts'
import type { JWTAlgorithm, JWTPayload, JWTVerifyOptions } from './jwt.ts'
import type { ScopedContext } from '@zanix/server'

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

export type AuthSessionOptions = {
  /** User or API Id. */
  subject: string
  /** Optional extra data to save in access token's payload */
  payload?: Record<string, unknown>
} & AppTokenBaseAccess

export type OtpFlow = {
  /**
   * Generates a numeric OTP and stores it in the configured cache provider.
   *
   * The OTP is associated with a unique `target` (such as an email, phone number,
   * or user ID) and saved with an expiration time (TTL).
   *
   * @param {GenerateOTPOptions} options - The OTP data and settings.
   */
  generate: (options: GenerateOTPOptions) => Promise<string>
  /**
   * Validates an OTP code previously generated for the given target.
   *
   * The method retrieves the stored OTP from Redis (if available) or from the
   * local in-memory cache. When validation succeeds, the OTP is removed to ensure
   * one-time use.
   * @param target
   * @param code
   */
  verify: (
    /**
     * Target identifier for the OTP delivery.
     * Typically an email address or phone number.
     */
    target: string,
    /**
     * The one-time password (OTP) code that the user provides for verification.
     */
    code: string,
  ) => Promise<boolean>
  /**
   * Performs the full OTP authentication flow and initializes
   * the local session for the authenticated user.
   */
  authenticate: (
    /**
     * The scoped request context in which the local session user info
     * will be stored.
     */
    ctx: ScopedContext,
    /**
     * Target identifier for the OTP delivery.
     * Typically an email address or phone number.
     */
    target: string,
    /**
     * The one-time password (OTP) code that the user provides for verification.
     */
    code: string,
    /** Optional configuration for customizing the generated local session */
    sessionOptions: AuthSessionOptions,
  ) => Promise<SessionTokens>
}

export type SessionFlow = {
  /**
   * Generates a pair of session tokens (access and refresh) for a given subject and context.
   *
   * @param {AuthSessionOptions} options
   * Options used to generate the session tokens.
   * @returns {Promise<SessionTokens>} The generated session tokens.
   */
  generateTokens: (options: AuthSessionOptions) => Promise<SessionTokens>
  /**
   * Revokes a session token and returns its decoded payload.
   *
   * @param {string} token
   * The `refresh` token to revoke.
   *
   * @returns {Promise<JWTPayload>}
   * A promise that resolves with the revoked token's payload.
   */
  revokeToken: (token?: string) => Promise<JWTPayload>

  /**
   * Refreshes the session tokens using the provided JWT.
   *
   * @param {string} token
   * The session refresh token.
   *
   * @returns {Promise<SessionTokens>} The generated session tokens.
   */
  refreshTokens: (
    token?: string,
  ) => Promise<SessionTokens & { oldToken: string; payload: JWTPayload }>
}

export type OAuthFlow<U> = {
  /**
   * Generates the OAuth URL.
   *
   * @returns {string} The complete OAuth URL.
   */
  generateAuthUrl: () => string
  /**
   * Performs the full OAuth flow and initializes
   * the local session for the authenticated user.
   *
   * @param {string} token
   *   The OAuth token received after user login.
   *
   * @param {AuthSessionOptions} [sessionOptions={}]
   *   Optional configuration object used to customize locally generated session tokens,
   *   such as rate limiting, permissions, or subject.
   *
   * @returns {Promise<{ user: U, session: SessionTokens }>}
   *   Resolves with an object containing:
   *   - `user`: The authenticated user information extracted from the verified ID token.
   *   - `session`: The generated local session tokens (access + refresh) associated with the user.
   */
  authenticate: (
    token: string,
    sessionOptions?: AuthSessionOptions,
  ) => Promise<{
    user: U
    session: SessionTokens
  }>
}
