import { HttpError, PermissionDenied } from '@zanix/errors'

// `HttpErrorCodes` itself isn't part of `@zanix/errors`' public export surface — derived from
// `HttpError`'s own constructor instead of naming it directly, so this stays correct regardless.
type HttpErrorCodes = ConstructorParameters<typeof HttpError>[0]

/**
 * Whether `e` is a failure this package's own JWT primitives (`decodeJWT`, `verifyJWT`,
 * `getSecretByToken`'s own key lookup, `exchangeServiceCredential`, `refreshSessionTokens`, ...)
 * throw for a BAD credential — malformed format, invalid signature, expired, missing `exp`, wrong
 * issuer/audience/subject, blocklisted — as opposed to a genuine, unrelated server-side fault (e.g.
 * `getSecretByToken`'s own `HttpError('INTERNAL_SERVER_ERROR')` for a missing signing key, or a
 * real infra error from something else entirely).
 *
 * Every one of this package's own JWT primitives reports its own checks as a bare
 * `PermissionDenied` — no HTTP status of its own, deliberately: they're transport-agnostic
 * building blocks other Zanix packages also call outside any HTTP context (see that class's own
 * doc), and each stays independently unit-tested against exactly that contract. Converting one to
 * an `HttpError` INSIDE the primitive itself would break that contract for every non-HTTP caller —
 * see {@link toJwtHttpError}'s own doc for where the conversion belongs instead.
 */
export const isJwtVerificationFailure = (e: unknown): boolean => e instanceof PermissionDenied

/**
 * Normalizes a JWT decode/verification failure into an `HttpError` with `status` — call this at
 * the actual HTTP boundary (a route handler/controller building a real `Response`), never inside
 * one of this package's own reusable session/JWT functions (`exchangeServiceCredential`,
 * `refreshSessionTokens`, `verifyJWT`, ...) — those stay transport-agnostic on purpose (see
 * {@link isJwtVerificationFailure}'s own doc) so a non-HTTP caller (a CLI, a background job) can
 * still catch a bare `PermissionDenied` without this package assuming an HTTP response is even
 * being built.
 *
 * Every consumer (a credential-exchange endpoint, a refresh endpoint, a validation guard) reports
 * the SAME underlying failure as whichever status fits ITS OWN context (`'BAD_REQUEST'` for "the
 * credential you just presented is malformed," `'UNAUTHORIZED'` for "you need to re-authenticate,"
 * `'FORBIDDEN'` for "your existing session's credential is bad") — instead of letting it fall
 * through to `@zanix/server`'s own generic default (500, correct for a real server fault, wrong
 * for "this JWT is garbage/expired/wrong audience").
 *
 * Anything that isn't a JWT verification failure (see {@link isJwtVerificationFailure}) is a
 * genuine, already-correctly-statused error or an unrelated bug, and is re-thrown UNCHANGED — this
 * never masks a real server fault as a client error.
 *
 * @example
 * A consumer's own `/admin/service-token` route, calling the primitive directly:
 * ```ts
 * @Post('service-token', { Body: ServiceExchangeRTO })
 * public async exchange(ctx: HandlerContext<{ body: ServiceExchangeRTO }>) {
 *   try {
 *     return await exchangeServiceCredential(ctx.payload.body.assertion)
 *   } catch (e) {
 *     toJwtHttpError(e, 'BAD_REQUEST')
 *   }
 * }
 * ```
 */
export function toJwtHttpError(e: unknown, status: HttpErrorCodes): never {
  if (!isJwtVerificationFailure(e)) throw e

  const known = e as { message: string; code?: string; meta?: Record<string, unknown> }
  throw new HttpError(status, {
    message: known.message,
    code: known.code,
    cause: e,
    meta: known.meta,
    exposeCause: true,
  })
}
