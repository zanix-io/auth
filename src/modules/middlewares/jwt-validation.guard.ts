import type { JWTValidationOpts } from 'typings/auth.ts'
import type { SessionStatus } from 'typings/sessions.ts'

import { AUTH_HEADERS, DEFAULT_AUTH_ISSUER } from 'utils/constants.ts'
import { httpErrorResponse, type MiddlewareGlobalGuard } from '@zanix/server'
import { checkTokenBlockList } from 'utils/sessions/block-list.ts'
import { defineLocalSession } from 'utils/sessions/context.ts'
import { HttpError, PermissionDenied } from '@zanix/errors'
import { rateLimitGuard } from './rate-limit.guard.ts'

import { getSecretByToken } from 'utils/jwt/secrets.ts'
import { verifyJWT } from 'utils/jwt/verify.ts'
import {
  addCookiesToResponse,
  addHeadersToResponse,
  checkAcceptedCookies,
  getClientSubject,
  getDefaultSessionHeaders,
} from 'utils/sessions/headers.ts'

/**
 * Creates a JWT validation guard that authenticates incoming requests, verifies the
 * provided access token, checks cache blocklist, applies rate limiting, and assigns
 * session context if validation succeeds.
 *
 * This guard extracts the token from different authorization headers, with `user` mode enabled
 * by default:
 *
 * - `type: "user"` → Header: `Authorization: Bearer <token>`
 * - `type: "api"`  → Header: `X-Znx-Authorization: Bearer <token>`
 *
 * Also, it supports **HMAC** and **RSA** JWT verification. Depending on the selected `type`,
 * the corresponding algorithm is assigned for JWT verification:
 *
 * - `type: "user"` → **HS256**
 * - `type: "api"`  → **RS256**
 *
 * This distinction ensure that **HMAC** is used for user-based authentication and **RSA** for API authentication,
 * providing appropriate security measures based on the request type.
 *
 * ## Key Resolution
 * The guard automatically loads the signing/verification key from environment variables:
 *
 * - For **user** tokens: `JWT_KEY` or `JWT_KEY_<kid>`
 * - For **api** tokens:  `JWK_PUB` or `JWK_PUB_<kid>`
 *
 * The `kid` (Key ID) header, if present in the JWT, determines the suffix `_<kid>`.
 *
 * ## Session Response Headers
 * When validation **fails** (missing/invalid token, blocklisted token, or rate-limited),
 * this guard builds a failure response via `getDefaultSessionHeaders`, which includes:
 *
 * - `x-znx-<type>-session-status:<SessionStatus}>` to indicate the session status.
 * - `x-znx-<type>-id` Subject Id header, when a client subject can be resolved.
 * - If `X-Znx-Cookies-Accepted: true` is present (in headers or cookies), the same
 *   session status/subject/cookie-consent cookies are sent via `Set-Cookie`.
 *
 * When validation **succeeds**, this guard only assigns `ctx.locals.session` — the
 * corresponding response headers/cookies are added afterwards by
 * {@link sessionHeadersInterceptor}, not by this guard.
 *
 * ## Permissions / Audience Validation
 * If the `permissions` option is supplied, it is matched against the `aud` claim
 * inside the JWT. The value may be a string or list of permissions/roles/scopes.
 *
 * ## Blocklist Verification
 * The guard checks whether the token ID (jti) is present in the cache blocklist.
 * If so, the request is rejected with a `FORBIDDEN` error.
 *
 * ## Automatic Rate Limit Enforcement
 * Applies rate limiting automatically on a per-user basis.
 * Rate limits can be configured using:
 *
 * - `RATE_LIMIT_WINDOW_SECONDS` environment variable
 *
 * ## Options
 *
 * @param {Object} options - Configuration options for the JWT guard.
 * @param {string|string[]} [options.permissions]
 *        Required audience or permissions the caller must have.
 *        Mapped to the JWT `aud` claim. Optional.
 *
 * @param {"api"|"user"} [options.type="user"]
 *        Determines which header is inspected and which key is used.
 *        - `"user"` → `Authorization` header and `JWT_KEY` env variables.
 *        - `"api"`  → `X-Znx-Authorization` header and `JWK_PUB` env variables.
 *
 * @param {string} [options.encryptionKey]
 *        Optional key used to decrypt sensitive payload fields.
 *        Required only when using type `api` (RSA algorithm) + payload's secure data.
 *
 * @param {string} [options.iss]
 *        Expected issuer (`iss`) claim. The guard always enforces an exact match,
 *        defaulting to `DEFAULT_AUTH_ISSUER` (`'zanix-auth'`) when omitted.
 *
 * @param {string} [options.sub]
 *        Expected subject (`sub`) claim. Optional.
 *
 * @returns {MiddlewareGuard}
 *          A middleware guard enforcing JWT validation, blocklist checks,
 *          permissions verification, and rate limiting.
 *
 * ## ⚠️ Security:
 *  Never commit encryption keys to version control. During key rotation, keep
 *  all key versions accessible until tokens are expired.
 *
 * @example
 * // Basic usage (default mode: user)
 * const guard = jwtValidationGuard();
 *
 * @example
 * // With permissions and API mode
 * const guard = jwtValidationGuard({
 *   type: "api",
 *   permissions: ["service:read"],
 * });
 */
export const jwtValidationGuard = (options: JWTValidationOpts = {}): MiddlewareGlobalGuard => {
  const {
    app,
    sub,
    permissions,
    type = 'user',
    iss = DEFAULT_AUTH_ISSUER,
    encryptionKey,
    algorithm,
    rateLimit = true,
  } = options

  const authHeaderKey = AUTH_HEADERS[type]

  const rateLimitFn = rateLimitGuard({ anonymousLimit: 0, app }) // user must be authenticated

  return async (ctx) => {
    const { req: { headers: ctxHeaders }, cookies } = ctx
    const authHeader = ctxHeaders.get(authHeaderKey)
    const cookiesAccepted = checkAcceptedCookies(ctxHeaders, cookies)

    const defaultSessionOpts = { type, cookiesAccepted, headers: ctxHeaders, cookies }
    const clientSubject = getClientSubject(ctxHeaders, cookies, type)

    const token = authHeader?.slice(7).trim()
    // deno-lint-ignore no-non-null-assertion
    if (!token || !authHeader!.startsWith('Bearer ')) {
      const { 'Set-Cookie': cookies, ...baseHeaders } = await getDefaultSessionHeaders({
        ...defaultSessionOpts,
        sessionStatus: 'failed',
      })
      const response = httpErrorResponse(
        new HttpError('UNAUTHORIZED', {
          message: `${authHeaderKey} token is missing or invalid.`,
          cause: 'No JWT provided or Authorization header is not a Bearer token.',
          meta: {
            source: 'zanix',
            method: 'jwtValidationGuard',
            authHeaderKey: authHeaderKey,
            requestId: ctx.id,
          },
        }),
        { headers: baseHeaders, contextId: ctx.id },
      )
      addCookiesToResponse(response, cookies)

      return { response }
    }

    try {
      let secret: string

      try {
        secret = getSecretByToken(token, type)
      } catch (e) {
        const { 'Set-Cookie': cookies, ...baseHeaders } = await getDefaultSessionHeaders({
          ...defaultSessionOpts,
          sessionStatus: 'failed',
        })
        if (e instanceof PermissionDenied) throw e

        const response = httpErrorResponse(e, { headers: baseHeaders, contextId: ctx.id })
        addCookiesToResponse(response, cookies)

        return { response }
      }

      const isRSA = type === 'api'
      const jwtPayload = await verifyJWT(
        token,
        isRSA ? atob(secret) : secret,
        {
          algorithm: algorithm || (isRSA ? 'RS256' : 'HS256'),
          sub: sub || clientSubject || '',
          aud: permissions,
          encryptionKey,
          iss,
        },
      )

      // check token in block list
      const isInBlockList = await checkTokenBlockList(
        jwtPayload.jti,
        ctx.providers.get('cache'),
        ctx.connectors.get('kvLocal'),
      )
      if (isInBlockList) {
        throw new PermissionDenied('The provided token has been revoked or is blocklisted.')
      }

      // Assign a session to the context
      defineLocalSession(ctx, { type, payload: jwtPayload })

      // Rate limit validation
      const { response, headers: rateLimitHeaders } = rateLimit ? await rateLimitFn(ctx) : {}

      if (response) {
        const headers = await getDefaultSessionHeaders({
          ...rateLimitHeaders,
          ...defaultSessionOpts,
          sessionStatus: 'blocked',
        })

        addHeadersToResponse(response, headers)

        return { response }
      }

      const status: SessionStatus = 'active'

      // This value is processed in headers interceptor, to add valid session headers.
      // `token` is intentionally NOT included here: it holds the access token from this
      // request's Authorization header, not the refresh token issued at login. Forwarding
      // it would make sessionHeadersInterceptor overwrite the refresh-token cookie with
      // the access token on every authenticated request.
      ctx.locals.session = {
        // deno-lint-ignore no-non-null-assertion
        ...ctx.locals.session!,
        status,
      }

      Object.freeze(ctx.locals.session)

      return { headers: rateLimitHeaders }
    } catch (e) {
      const { 'Set-Cookie': cookies, ...baseHeaders } = await getDefaultSessionHeaders({
        ...defaultSessionOpts,
        sessionStatus: 'failed',
      })
      const response = httpErrorResponse(
        new HttpError('FORBIDDEN', {
          message: 'You do not have access to this resource.',
          cause: e,
          meta: {
            source: 'zanix',
            method: 'verifyJWT',
          },
        }),
        { headers: baseHeaders, contextId: ctx.id },
      )

      addCookiesToResponse(response, cookies)
      return { response }
    }
  }
}
