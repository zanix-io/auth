/**
 *  ______               _
 * |___  /              (_)
 *    / /   __ _  _ __   _ __  __
 *   / /   / _` || '_ \ | |\ \/ /
 * ./ /___| (_| || | | || | >  <
 * \_____/ \__,_||_| |_||_|/_/\_\
 */

/**
 * @module
 *
 * Authentication and authorization module for the Zanix ecosystem: JWT creation/verification with
 * key rotation, session management, Google OAuth2 (and a base class for custom OAuth2 providers),
 * a token blocklist, OTP, TOTP authenticator-app 2FA, scope/permission validation, and
 * rate-limiting middleware.
 *
 * Importing this entrypoint only exposes its exports — it does not register anything with the
 * Zanix framework. For the zero-config default provider/interceptor/connector registration, import
 * the `./core` subpath instead (see the package README).
 */

import { SESSION_HEADERS } from 'utils/constants.ts'

// Connectors & Providers
export { GoogleOAuth2Connector } from 'modules/connectors/google/mod.ts'
export { ZanixAuthProvider } from 'modules/providers/auth.ts'
export { OAuth2Connector } from 'modules/connectors/oauth2.ts'
export type { OAuth2ConnectorConfig, OAuth2ConnectorOptions } from 'modules/connectors/oauth2.ts'
export type { AuthConnectors, CoreAuthConnectors, GoogleUserInfo } from 'typings/connectors.ts'

// JWT
export type {
  JWT,
  JWTAlgorithm,
  JWTHeader,
  JWTOptions,
  JWTPayload,
  JWTVerifyOptions,
} from 'typings/jwt.ts'

export { createJWT } from 'utils/jwt/create.ts'
export { verifyJWT } from 'utils/jwt/verify.ts'
export { decodeJWT } from 'utils/jwt/decode.ts'

// Block List
export { addTokenToBlockList, checkTokenBlockList } from 'utils/sessions/block-list.ts'

// Sessions
export { revokeAppTokens, revokeSessionToken } from 'utils/sessions/revoke.ts'
export {
  createAccessToken,
  createAppToken,
  createRefreshToken,
  generateSessionTokens,
} from 'utils/sessions/create.ts'
export {
  getClientSubject,
  getDefaultSessionHeaders,
  getSessionHeaders,
} from 'utils/sessions/headers.ts'
export type { Headers } from 'utils/sessions/headers.ts'
export type {
  AuthSessionOptions,
  GenerateOTPOptions,
  JWTValidationOpts,
  OAuthFlow,
  OtpFlow,
  SessionFlow,
  TotpFlow,
  TOTPVerifyOptions,
} from 'typings/auth.ts'
export type {
  AppTokenBaseAccess,
  RateLimitsOptions,
  SessionStatus,
  SessionTokens,
  SessionTypes,
} from 'typings/sessions.ts'

// Utils
export { scopeValidation } from 'utils/scope.ts'
export { generateOTP, verifyOTP } from 'utils/otp.ts'
export { generateTOTP, generateTOTPSecret, getTOTPProvisioningUri, verifyTOTP } from 'utils/totp.ts'
export { getSecretByToken } from 'utils/jwt/secrets.ts'

/**
 * Represents the main session/auth headers for a user context.
 */
export const userSessionHeaders: { sub: string; session: string; token: string } =
  SESSION_HEADERS['user']
/**
 * Represents the main session/auth headers for API requests.
 */
export const apiSessionHeaders: { sub: string; session: string; token: undefined } =
  SESSION_HEADERS['api']

// Middlewares
export { sessionHeadersInterceptor } from 'modules/middlewares/headers.interceptor.ts'
export { rateLimitGuard } from 'modules/middlewares/rate-limit.guard.ts'
export { jwtValidationGuard } from 'modules/middlewares/jwt-validation.guard.ts'
export { permissionsPipe } from 'modules/middlewares/permissions.pipe.ts'

// Decorators
export { AuthTokenValidation } from 'modules/middlewares/decorators/authentication.ts'
export { RequirePermissions } from 'modules/middlewares/decorators/permissions.ts'
export { RateLimitGuard } from 'modules/middlewares/decorators/rate-limit.ts'
