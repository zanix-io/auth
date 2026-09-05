import type {
  AccessTokenOptions,
  AppTokenBaseAccess,
  RefreshTokenOptions,
  SessionTokens,
  SessionTypes,
  // deno-lint-ignore no-unused-vars
  TTLDuration,
} from './sessions.ts'
import type { JWTAlgorithm, JWTPayload, JWTVerifyOptions } from './jwt.ts'

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
   *
   * Can also be an array (e.g. `['user', 'api']`) to accept either shape on the same route — the
   * first configured type whose own header actually carries a Bearer token is the one the request
   * is validated against. Accepts a `readonly` array too, so a module-level `as const` tuple (the
   * common pattern for a shared constant) can be passed directly without widening it first.
   */
  type?: SessionTypes | SessionTypes[] | readonly SessionTypes[]
  /** Specify an algorithm only if it differs from the project standard. */
  algorithm?: JWTAlgorithm
  /**
   * App this validation applies to.
   * - If undefined, the validation is considered global.
   * - If defined, it only applies to the specified app.
   */
  app?: string
} & Omit<JWTVerifyOptions, 'aud' | 'algorithm'>

/** Options for generating and storing a one-time password via {@link OtpFlow.generate}. */
export type GenerateOTPOptions = {
  /**
   * Target identifier for the OTP delivery.
   * Typically an email address or phone number.
   */
  target: string

  /**
   * Expiration time of the generated OTP, in seconds.
   * Optional; defaults to `300` seconds if not provided.
   */
  exp?: number

  /**
   * Length of the OTP (number of digits).
   * Optional; defaults to `6`.
   */
  length?: number
}

/** Options for verifying a one-time password via {@link OtpFlow.verify}/{@link OtpFlow.authenticate}. */
export type VerifyOTPOptions = {
  /**
   * How many wrong guesses this OTP tolerates before it's burned outright (deleted, rejected even
   * if it hasn't actually expired yet) — the brute-force guard for a short numeric code. Optional;
   * defaults to `5`.
   */
  maxAttempts?: number
}

/** Options used to generate a pair of session tokens for a given subject. */
export type AuthSessionOptions = {
  /** User or API Id. */
  subject: string
  /** Session Id */
  id?: string
  /** Optional extra data to save in access token's payload */
  payload?: Record<string, unknown>
  /**
   * The access token's lifetime — a {@link TTLDuration} string (e.g. `'30m'`, `'1h'`, `'45m'`) or a
   * number of seconds. Defaults to `'1h'`. Bound by the same 1-hour ceiling `createAccessToken`
   * already enforces on any value that reaches it through this option.
   */
  accessExpiration?: AccessTokenOptions<'user'>['expiration']
  /**
   * The refresh token's lifetime — a {@link TTLDuration} string (e.g. `'1w'`, `'6mo'`, `'1y'`) or a
   * number of seconds. Defaults to `'1y'`. Must be at least `MIN_REFRESH_TO_ACCESS_RATIO` times
   * `accessExpiration` — `generateSessionTokens` rejects a narrower margin, since a refresh token
   * that expires too close to the cadence it gets renewed at can lapse for real before a
   * legitimate, still-active session ever gets a chance to renew it.
   */
  refreshExpiration?: RefreshTokenOptions<'user'>['expiration']
} & AppTokenBaseAccess

/** OTP (one-time password) authentication methods exposed on `authProvider.otp`. */
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
    /** Optional verification options — currently just `maxAttempts`. */
    options?: VerifyOTPOptions,
  ) => Promise<boolean>
  /**
   * Performs the full OTP authentication flow and initializes
   * the local session for the authenticated user.
   */
  authenticate: (
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
    sessionOptions?: Partial<AuthSessionOptions>,
    /** Optional verification options — currently just `maxAttempts`. */
    verifyOptions?: VerifyOTPOptions,
  ) => Promise<SessionTokens>
}

/** Options accepted by {@link TotpFlow.verify}/{@link TotpFlow.authenticate}. */
export type TOTPVerifyOptions = {
  /**
   * Number of time steps before/after the current one to also accept, tolerating clock drift.
   * Defaults to `1` (accepts the previous, current, and next 30s step).
   */
  window?: number
  /** Unix time in seconds. Defaults to the current time. */
  time?: number
  /**
   * Number of digits in the expected code. Defaults to `6`.
   * Changing this away from `6` risks breaking compatibility with standard authenticator apps.
   */
  digits?: number
  /**
   * Time step in seconds. Defaults to `30`.
   * Changing this away from `30` risks breaking compatibility with standard authenticator apps.
   */
  period?: number
}

/**
 * TOTP (Time-based One-Time Password, RFC 6238) authentication-app 2FA methods exposed on
 * `authProvider.totp` — compatible with authenticator apps such as Google Authenticator and
 * Microsoft Authenticator.
 */
export type TotpFlow = {
  /**
   * Generates a new random TOTP secret for a user to enroll.
   *
   * @param {number} [length=20] - Number of random bytes to generate.
   */
  generateSecret: (length?: number) => string
  /**
   * Builds an `otpauth://totp/...` provisioning URI for the given secret, to render as a QR code
   * (or hand to the user as a manual-entry key) during enrollment.
   */
  getProvisioningUri: (
    /** The Base32-encoded TOTP secret, as returned by {@link TotpFlow.generateSecret}. */
    secret: string,
    /** The account identifier shown in the app (e.g. an email address). */
    accountName: string,
    /** Provisioning options (issuer, digits, period). */
    options?: { issuer?: string; digits?: number; period?: number },
  ) => string
  /**
   * Verifies a TOTP code against a secret, tolerating clock drift within `options.window`.
   */
  verify: (
    /** The Base32-encoded TOTP secret. */
    secret: string,
    /** The code the user provides for verification. */
    code: string,
    options?: TOTPVerifyOptions,
  ) => Promise<boolean>
  /**
   * Performs the full TOTP authentication flow and initializes the local session for the
   * authenticated user.
   */
  authenticate: (
    /** The Base32-encoded TOTP secret. */
    secret: string,
    /** The code the user provides for verification. */
    code: string,
    /**
     * Configuration for the generated local session. Unlike {@link OtpFlow.authenticate}, this is
     * required — a bare TOTP secret carries no natural subject the library could default to.
     */
    sessionOptions: AuthSessionOptions,
    options?: TOTPVerifyOptions,
  ) => Promise<SessionTokens>
}

/** Session lifecycle methods exposed on `authProvider.session`. */
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
   * @param {Partial<AuthSessionOptions>} [sessionOptions]
   * Fields overriding the `AuthSessionOptions` originally embedded in the refresh token (e.g.
   * freshly resolved `permissions`, after a role change), shallow-merged over it before the new
   * tokens are generated. Omit to keep reusing the original login's own values, as before.
   *
   * @returns {Promise<SessionTokens & { oldToken: string; payload: JWTPayload }>}
   * The newly generated session tokens, along with the previous refresh token
   * and its decoded payload.
   */
  refreshTokens: (
    token?: string,
    sessionOptions?: Partial<AuthSessionOptions>,
  ) => Promise<SessionTokens & { oldToken: string; payload: JWTPayload }>
}

/** OAuth authentication methods exposed on `authProvider.google` (and other OAuth connectors). */
export type OAuthFlow<U> = {
  /**
   * Generates the OAuth URL.
   *
   * @param {string} [options.state] - A random string to maintain state between request and callback.
   *                           Defaults to a newly generated UUID.
   * @param {string} [options.scope] - OAuth scopes to request.
   * @param {'token' | 'code'} [options.responseType] - Overrides the connector's own configured
   *                           `responseType` for just this call — e.g. requesting the
   *                           authorization-code flow from one call site while another still uses
   *                           the connector's own default.
   *
   * @returns The generated OAuth URL along with the `state` used to build it.
   */
  generateAuthUrl: (
    options?: { state?: string; scope?: string; responseType?: 'token' | 'code' },
  ) => { url: string; state: string }
  /**
   * Verifies a OAuth token and retrieves the associated user information.
   *
   * @returns { Promise<U>} The associated user information.
   */
  validateToken: (token: string) => Promise<U>
  /**
   * {@link OAuthFlow.validateToken}'s own authorization-code-flow counterpart: exchanges `code`
   * for a real access token server-side, then retrieves the associated user info with it — the
   * token behind that lookup is provably scoped to this app by construction, unlike a token
   * `validateToken` receives directly from the client. The direct, one-line replacement for
   * `validateToken(token)` in a flow that builds its own session afterward (permissions, a custom
   * payload, its own DB writes) instead of using {@link OAuthFlow.authenticate}'s generic one.
   *
   * @param code - The authorization code from the provider's redirect.
   * @returns The user info, same shape {@link OAuthFlow.validateToken} returns.
   */
  validateCode: (code: string) => Promise<U>
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
    sessionOptions?: Partial<AuthSessionOptions>,
  ) => Promise<{
    user: U
    session: SessionTokens
  }>
  /**
   * The authorization-code flow's own entry point — exchanges `code` for a real access token
   * server-side (using this connector's own client secret), then runs the same session-creation
   * logic {@link OAuthFlow.authenticate} does. Recommended over `authenticate()` wherever the
   * provider supports it: the token this hands off is provably scoped to this app by
   * construction, unlike a token `authenticate()` receives directly from the client.
   *
   * @param {string} code - The authorization code from the provider's redirect (`?code=...`).
   * @param {AuthSessionOptions} [sessionOptions={}] - Same as {@link OAuthFlow.authenticate}.
   * @returns Same shape as {@link OAuthFlow.authenticate}.
   */
  authenticateWithCode: (
    code: string,
    sessionOptions?: Partial<AuthSessionOptions>,
  ) => Promise<{
    user: U
    session: SessionTokens
  }>
}
