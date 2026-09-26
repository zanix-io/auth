import { getCookies } from '@std/http/cookie'
import { SESSION_HEADERS } from '@zanix/server'
import { getSecretByToken } from 'utils/jwt/secrets.ts'
import { verifyJWT } from 'utils/jwt/verify.ts'

/**
 * Reads a request's own session-cookie permissions in read-only mode, with no guard and no
 * rotation — for a context that has no guard of its own to attach to at all, e.g. a `@zanix/space`
 * root `layout.tsx`. A `layout.tsx` is a plain function with an optional `loader`, never a
 * `SpacePageController` subclass a page-level `@Guard` decorator can attach to, and its `loader`
 * receives a curated `PageContext` that never carries `session` (neither `ctx.locals.session` nor
 * the top-level, pipe-promoted `ctx.session`) — a deliberate snapshot, not an oversight, confirmed
 * by reading `@zanix/space`'s own `toPageContext`. A page reached from such a layout still enforces
 * its own real `pageSessionGuard`/`iamSessionGuard`-style guard regardless of what this returns —
 * this is for a UI decision only (e.g. which nav links a layout shows), never an authorization
 * check on its own.
 *
 * Re-running `pageSessionGuard`'s own `refreshSessionTokens` here instead was deliberately not
 * done: it single-use-rotates AND blocklists the refresh token it consumes
 * (`refreshSessionTokensBase`) — calling it a second time in the same request, after a page's own
 * guard already rotated (and blocklisted) that exact cookie once, throws "already blocklisted"
 * instead of quietly succeeding. `verifyJWT`/`getSecretByToken` are the same two READ-ONLY
 * primitives `refreshSessionTokensBase` itself calls before ever deciding to rotate — reused here
 * for the identical reason: confirming the token is genuinely valid and reading its embedded
 * permissions, without mutating anything.
 *
 * Scoped to the `'user'` session type — the only one with a cookie token at all
 * ({@linkcode SESSION_HEADERS}`.api.token` is `undefined`; the `'api'` type never has a browser
 * cookie to peek at in the first place).
 *
 * A missing/expired/malformed/tampered cookie resolves to `[]` — the exact same "no session"
 * outcome as a request with no cookie at all, never a thrown error.
 *
 * @param request - The raw incoming request.
 * @returns The session's granted permission strings (`payload.access.permissions`, exactly what
 * `generateSessionTokens` embedded in the refresh token's own payload when this session was
 * minted) — `[]` for no session, or one with no explicit permissions.
 */
export async function peekSessionPermissions(request: Request): Promise<string[]> {
  const token = getCookies(request.headers)[SESSION_HEADERS.user.token as string]
  if (!token) return []

  try {
    const secret = getSecretByToken(token)
    const { access } = await verifyJWT(token, secret)
    const permissions = (access as { permissions?: string[] | string } | undefined)?.permissions

    if (!permissions) return []
    return Array.isArray(permissions) ? permissions : [permissions]
  } catch {
    return []
  }
}
