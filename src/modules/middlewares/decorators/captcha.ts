import { defineMiddlewareDecorator, type ZanixGenericDecorator } from '@zanix/server'
import type { CaptchaOptions } from 'typings/captcha.ts'
import { captchaGuard } from '../captcha.guard.ts'

/**
 * A class-level decorator that verifies a captcha response token (Google reCAPTCHA, hCaptcha, or
 * Cloudflare Turnstile) before allowing access to a controller.
 *
 * This decorator applies captcha verification as an extra layer of defense — typically on
 * sign-up/login/contact-form endpoints prone to bot abuse — never as a replacement for real
 * authentication/authorization.
 *
 * @see {@link captchaGuard} for the full provider-resolution/token-header contract.
 *
 * @param options - Configuration object for captcha verification, including:
 *                  - `provider`: Explicit provider selection (`'recaptcha'`/`'hcaptcha'`/
 *                    `'turnstile'`).
 *                  - `minScore`: Minimum confidence score required to pass, for providers that
 *                    return one.
 *
 *                  These options are defined in the `CaptchaOptions` type.
 *
 * @returns A class decorator (`ZanixGenericDecorator`) that applies captcha verification to the
 *          decorated controller.
 *
 * @example
 * ```ts
 * @Controller()
 * @CaptchaGuard()
 * export class SignupController extends ZanixController {
 *   // ...
 * }
 * ```
 */
export function CaptchaGuard(
  options?: CaptchaOptions,
): ZanixGenericDecorator {
  return defineMiddlewareDecorator('guard', captchaGuard(options))
}
