import type { CaptchaOptions } from 'typings/captcha.ts'
import { httpErrorResponse, type MiddlewareGlobalGuard } from '@zanix/server'
import { HttpError } from '@zanix/errors'

import { resolveCaptchaAdapter } from 'modules/connectors/captcha/defs.ts'

/**
 * Request header carrying the captcha response token produced by the provider's client-side
 * widget/script. Fixed, not configurable — matches the `X-Znx-<Word>-...` namespace every
 * framework-owned Zanix header/cookie uses (see `naming-and-structure-conventions`).
 */
export const CAPTCHA_TOKEN_HEADER = 'X-Znx-Captcha-Token'

/**
 * Creates and returns a middleware guard that verifies a captcha response token against a
 * third-party anti-bot provider (Google reCAPTCHA, hCaptcha, or Cloudflare Turnstile) before
 * allowing a request through.
 *
 * This guard is defense-in-depth, the same as `ipAllowlistGuard`/`rateLimitGuard` — never a
 * replacement for real authentication/authorization.
 *
 * ## Token
 * The request must carry the provider's response token in the `X-Znx-Captcha-Token` header (see
 * `CAPTCHA_TOKEN_HEADER`). That token is produced client-side by the provider's own widget/script —
 * loading that widget and forwarding its token as this header is the consumer's own responsibility;
 * this guard only validates a token that already arrives, the same way `OAuth2Connector` never
 * renders anything of its own.
 *
 * ## Provider Configuration
 * A provider adapter can be supplied directly (`options.adapter`), or resolved automatically:
 * - `options.provider` (with `options.secretKey`/`options.apiBase`, each falling back to that
 *   provider's own env var) selects and configures it explicitly.
 * - Otherwise, the `CAPTCHA_PROVIDER` environment variable selects it (`'recaptcha'`, `'hcaptcha'`,
 *   or `'turnstile'`), configured from that provider's own env vars
 *   (`RECAPTCHA_SECRET_KEY`/`HCAPTCHA_SECRET_KEY`/`TURNSTILE_SECRET_KEY`, each with an optional
 *   `*_API_BASE` override).
 * - Otherwise, exactly one provider's own secret-key env var being set auto-selects it —
 *   zero-config, the same shape `@zanix/notifications`'s SMS/WhatsApp provider selection uses. If
 *   more than one is set at once with no `CAPTCHA_PROVIDER` selected, this throws rather than
 *   silently picking one — see `resolveCaptchaProvider()`.
 *
 * If no provider resolves at all (nothing configured), this guard is a pass-through — it does not
 * restrict requests, matching `ipAllowlistGuard`'s own unconfigured behavior.
 *
 * @param options - The captcha configuration options.
 * @param options.provider - Explicit provider selection.
 * @param options.adapter - A custom adapter, bypassing provider resolution/env entirely.
 * @param options.secretKey - The resolved provider's secret key, overriding its own env var.
 * @param options.apiBase - Overrides the resolved provider's verification API base URL.
 * @param options.minScore - Minimum confidence score required to pass, for providers/keys that
 *                            return one (see `CaptchaVerifyResult.score`). Defaults to `0.5`.
 * @function captchaGuard
 * @returns {MiddlewareGlobalGuard} A middleware guard instance that verifies the captcha token on
 *          incoming requests.
 *
 * @throws {InternalError} If `CAPTCHA_PROVIDER` is set to an unsupported value, if more than one
 * provider's env vars are set with no `CAPTCHA_PROVIDER` selected, or if a resolved provider is
 * missing its own secret key.
 */
export const captchaGuard = (
  options: CaptchaOptions = {},
): MiddlewareGlobalGuard => {
  const { minScore = 0.5 } = options
  const adapter = resolveCaptchaAdapter(options)

  return async (ctx) => {
    if (!adapter) return {}

    const { req: { headers } } = ctx
    const token = headers.get(CAPTCHA_TOKEN_HEADER)

    if (!token) {
      const response = httpErrorResponse(
        new HttpError('BAD_REQUEST', {
          message: 'Bad Request',
          meta: {
            source: 'zanix',
            method: 'captchaGuard',
            requestId: ctx.id,
            reason: `Missing "${CAPTCHA_TOKEN_HEADER}" header.`,
          },
        }),
        { contextId: ctx.id },
      )
      return { response }
    }

    const result = await adapter.verify(token)
    const passed = result.success && (result.score === undefined || result.score >= minScore)

    if (!passed) {
      const response = httpErrorResponse(
        new HttpError('FORBIDDEN', {
          message: 'Forbidden',
          meta: {
            source: 'zanix',
            method: 'captchaGuard',
            requestId: ctx.id,
            reason: result.success
              ? `Captcha score below the required minimum (${minScore}).`
              : 'Captcha verification failed.',
          },
        }),
        { contextId: ctx.id },
      )
      return { response }
    }

    return {}
  }
}
