/**
 *  ______               _
 * |___  /              (_)
 *    / /   __ _  _ __   _ __  __
 *   / /   / _` || '_ \ | |\ \/ /
 * ./ /___| (_| || | | || | >  <
 * \_____/ \__,_||_| |_||_|/_/\_\
 */

// Connectors & Providers
export { GoogleOAuth2Connector } from 'modules/connectors/google/mod.ts'
export { ZanixAuthProvider } from 'modules/providers/auth.ts'
export { createAuthProvider } from 'modules/providers/defs.ts'

// JWT
export type { JWT, JWTHeader, JWTPayload } from 'typings/jwt.ts'

export { createJWT } from 'utils/jwt/create.ts'
export { verifyJWT } from 'utils/jwt/verify.ts'

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

// Utils
export { scopeValidation } from 'utils/scope.ts'
export { generateOTP, verifyOTP } from 'utils/otp.ts'

// Middlewares
export { sessionHeadersInterceptor } from 'modules/middlewares/headers.interceptor.ts'
export { rateLimitGuard } from 'modules/middlewares/rate-limit.guard.ts'
export { jwtValidationGuard } from 'modules/middlewares/jwt-validation.guard.ts'
export { permissionsPipe } from 'modules/middlewares/permissions.pipe.ts'

// Decorators
export { AuthTokenValidation } from 'modules/middlewares/decorators/authentication.ts'
export { RequirePermissions } from 'modules/middlewares/decorators/permissions.ts'
export { RateLimitGuard } from 'modules/middlewares/decorators/rate-limit.ts'
