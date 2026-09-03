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
 * key rotation, session management, Google/GitHub OAuth2 (and a base class for custom OAuth2
 * providers), a token blocklist, OTP, TOTP authenticator-app 2FA, scope/permission validation, and
 * rate-limiting middleware.
 *
 * Importing this entrypoint only exposes its exports — it does not register anything with the
 * Zanix framework. For the zero-config default provider/interceptor/connector registration, import
 * the `./core` subpath instead (see the package README).
 */

import { SESSION_HEADERS } from '@zanix/server'

// Connectors & Providers
export {
  GOOGLE_OAUTH2_AUTH_URL_ENV,
  GOOGLE_OAUTH2_CLIENT_ID_ENV,
  GOOGLE_OAUTH2_CLIENT_SECRET_ENV,
  GOOGLE_OAUTH2_REDIRECT_URI_ENV,
  GOOGLE_OAUTH2_RESPONSE_TYPE_ENV,
  GOOGLE_OAUTH2_REVOKE_URL_ENV,
  GOOGLE_OAUTH2_TOKEN_URL_ENV,
  GOOGLE_OAUTH2_USERINFO_URL_ENV,
  GoogleOAuth2Connector,
} from 'modules/connectors/google/mod.ts'
export {
  GITHUB_OAUTH2_AUTH_URL_ENV,
  GITHUB_OAUTH2_CLIENT_ID_ENV,
  GITHUB_OAUTH2_CLIENT_SECRET_ENV,
  GITHUB_OAUTH2_REDIRECT_URI_ENV,
  GITHUB_OAUTH2_RESPONSE_TYPE_ENV,
  GITHUB_OAUTH2_REVOKE_URL_ENV,
  GITHUB_OAUTH2_TOKEN_URL_ENV,
  GITHUB_OAUTH2_USERINFO_URL_ENV,
  GitHubOAuth2Connector,
} from 'modules/connectors/github/mod.ts'
export { ZanixAuthProvider, ZanixCoreAuthProvider } from 'modules/providers/auth.ts'
export { OAuth2Connector } from 'modules/connectors/oauth2.ts'
export type { OAuth2ConnectorConfig, OAuth2ConnectorOptions } from 'modules/connectors/oauth2.ts'
export type {
  AuthConnectors,
  CoreAuthConnectors,
  GitHubUserInfo,
  GoogleUserInfo,
} from 'typings/connectors.ts'
export { RecaptchaAdapter } from 'modules/connectors/captcha/recaptcha.ts'
export { HCaptchaAdapter } from 'modules/connectors/captcha/hcaptcha.ts'
export { TurnstileAdapter } from 'modules/connectors/captcha/turnstile.ts'
export {
  CAPTCHA_PROVIDER_ENV,
  HCAPTCHA_API_BASE_ENV,
  HCAPTCHA_SECRET_KEY_ENV,
  RECAPTCHA_API_BASE_ENV,
  RECAPTCHA_SECRET_KEY_ENV,
  resolveCaptchaAdapter,
  resolveCaptchaProvider,
  TURNSTILE_API_BASE_ENV,
  TURNSTILE_SECRET_KEY_ENV,
} from 'modules/connectors/captcha/defs.ts'
export type {
  CaptchaOptions,
  CaptchaProvider,
  CaptchaProviderAdapter,
  CaptchaVerifyResult,
} from 'typings/captcha.ts'

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
export {
  DEFAULT_AUTH_ISSUER,
  JWK_ID_ENV,
  JWK_PRI_ENV,
  JWK_PUB_ENV,
  JWK_ROTATION_CYCLE_ENV,
  JWT_KEY_ENV,
  REDIS_URI_ENV,
  ROTATION_GRACE_WINDOW_ENV,
  SERVICE_PERMISSIONS_ENV,
  SERVICE_RATE_LIMIT_ENV,
} from 'utils/constants.ts'

// Block List
export {
  addTokenToBlockList,
  addTokenToBlockListBase,
  checkTokenBlockList,
} from 'utils/sessions/block-list.ts'

// Sessions
export {
  revokeAppTokens,
  revokeAppTokensBase,
  revokeSessionToken,
  revokeSessionTokenBase,
} from 'utils/sessions/revoke.ts'
export { refreshSessionTokens, refreshSessionTokensBase } from 'utils/sessions/refresh.ts'
export {
  attachRotatedSessionToError,
  recoverRotatedSessionCookie,
} from 'utils/sessions/rotation-recovery.ts'
export {
  applySessionTokens,
  createAccessToken,
  createAppToken,
  createRefreshToken,
  generateSessionTokens,
} from 'utils/sessions/create.ts'
export {
  createServiceAssertion,
  exchangeServiceCredential,
  exchangeServiceCredentialBase,
  resolveServiceAssertionKeyId,
  resolveServiceAssertionPrivateKey,
  type ServiceCredential,
} from 'utils/sessions/service-exchange.ts'
export {
  createServiceAuthClient,
  type ServiceAuthClientOptions,
  type ServiceAuthHeaders,
} from 'utils/sessions/service-auth-client.ts'
export {
  getClientSubject,
  getDefaultSessionHeaders,
  getSessionHeaders,
} from 'utils/sessions/headers.ts'
export type { Headers } from 'utils/sessions/headers.ts'
// `AnonymousSessionOptions` itself: `getDefaultSessionHeaders`'s own options type now depends on
// it (`trustProxyHeader`/`trustedHeaders`, forwarded to its anonymous-fallback path) — exported so
// a consumer calling that function can reference the type by name, not just get its shape
// structurally. `getAnonymousSessionId`/`generateAnonymousSession` themselves stay internal, same
// as before this change — nothing else in this package exposes them publicly.
export type { AnonymousSessionOptions } from 'utils/sessions/anonymous.ts'
export type {
  AuthSessionOptions,
  GenerateOTPOptions,
  JWTValidationOpts,
  OAuthFlow,
  OtpFlow,
  SessionFlow,
  TotpFlow,
  TOTPVerifyOptions,
  VerifyOTPOptions,
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
export const userSessionHeaders: {
  sub: string
  session: string
  token: string
} = SESSION_HEADERS['user']
/**
 * Represents the main session/auth headers for API requests.
 */
export const apiSessionHeaders: {
  sub: string
  session: string
  token: undefined
} = SESSION_HEADERS['api']

// Middlewares
export { sessionHeadersInterceptor } from 'modules/middlewares/headers.interceptor.ts'
export {
  RATE_LIMIT_WINDOW_SECONDS_ENV,
  rateLimitGuard,
} from 'modules/middlewares/rate-limit.guard.ts'
export { jwtValidationGuard } from 'modules/middlewares/jwt-validation.guard.ts'
export { pageSessionGuard } from 'modules/middlewares/page-session.guard.ts'
export { permissionsPipe } from 'modules/middlewares/permissions.pipe.ts'
export { ADMIN_IP_ALLOWLIST_ENV, ipAllowlistGuard } from 'modules/middlewares/ip-allowlist.guard.ts'
export type { IpAllowlistOptions } from 'modules/middlewares/ip-allowlist.guard.ts'
export { CAPTCHA_TOKEN_HEADER, captchaGuard } from 'modules/middlewares/captcha.guard.ts'
export {
  OAUTH_STATE_COOKIE_NAME,
  OAUTH_STATE_LOCALS_KEY,
  oauthStateIssueGuard,
  oauthStateVerifyGuard,
} from 'modules/middlewares/oauth-state.guard.ts'

// Decorators
export { AuthTokenValidation } from 'modules/middlewares/decorators/authentication.ts'
export { RequirePermissions } from 'modules/middlewares/decorators/permissions.ts'
export { RateLimitGuard } from 'modules/middlewares/decorators/rate-limit.ts'
export { IpAllowlistGuard } from 'modules/middlewares/decorators/ip-allowlist.ts'
export { CaptchaGuard } from 'modules/middlewares/decorators/captcha.ts'
