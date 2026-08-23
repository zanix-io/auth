import type { CaptchaOptions, CaptchaProvider, CaptchaProviderAdapter } from 'typings/captcha.ts'

import { InternalError } from '@zanix/errors'
import { RecaptchaAdapter } from './recaptcha.ts'
import { HCaptchaAdapter } from './hcaptcha.ts'
import { TurnstileAdapter } from './turnstile.ts'

/** Env var naming Google reCAPTCHA's secret key — the one required var for the `'recaptcha'`
 * `CaptchaProvider` (see `resolveCaptchaProvider()`). Works for both v2 and v3 site keys. */
export const RECAPTCHA_SECRET_KEY_ENV = 'RECAPTCHA_SECRET_KEY'
/** Env var optionally overriding reCAPTCHA's verification API base URL (proxy, mock server). */
export const RECAPTCHA_API_BASE_ENV = 'RECAPTCHA_API_BASE'

/** Env var naming hCaptcha's secret key — the one required var for the `'hcaptcha'`
 * `CaptchaProvider`. */
export const HCAPTCHA_SECRET_KEY_ENV = 'HCAPTCHA_SECRET_KEY'
/** Env var optionally overriding hCaptcha's verification API base URL (proxy, mock server). */
export const HCAPTCHA_API_BASE_ENV = 'HCAPTCHA_API_BASE'

/** Env var naming Cloudflare Turnstile's secret key — the one required var for the `'turnstile'`
 * `CaptchaProvider`. */
export const TURNSTILE_SECRET_KEY_ENV = 'TURNSTILE_SECRET_KEY'
/** Env var optionally overriding Turnstile's verification API base URL (proxy, mock server). */
export const TURNSTILE_API_BASE_ENV = 'TURNSTILE_API_BASE'

/**
 * Env var explicitly selecting which built-in captcha provider `captchaGuard()` resolves when more
 * than one provider's own secret-key env var is set at once — mirrors
 * `@zanix/notifications`'s `SMS_PROVIDER`/`WHATSAPP_PROVIDER`: only required to disambiguate that
 * conflict. With exactly one provider's own secret-key env var set (the common case),
 * `resolveCaptchaProvider()` still auto-detects it with zero extra config. Also honored as an
 * explicit override even without a conflict (e.g. forcing `'turnstile'` while another provider's
 * secret key happens to also be set, without unsetting it).
 *
 * @throws (via `resolveCaptchaProvider()`) if set to anything other than `'recaptcha'`,
 * `'hcaptcha'`, or `'turnstile'`.
 */
export const CAPTCHA_PROVIDER_ENV = 'CAPTCHA_PROVIDER'

const SECRET_KEY_ENV: Record<CaptchaProvider, string> = {
  recaptcha: RECAPTCHA_SECRET_KEY_ENV,
  hcaptcha: HCAPTCHA_SECRET_KEY_ENV,
  turnstile: TURNSTILE_SECRET_KEY_ENV,
}

const API_BASE_ENV: Record<CaptchaProvider, string> = {
  recaptcha: RECAPTCHA_API_BASE_ENV,
  hcaptcha: HCAPTCHA_API_BASE_ENV,
  turnstile: TURNSTILE_API_BASE_ENV,
}

const PROVIDERS: readonly CaptchaProvider[] = ['recaptcha', 'hcaptcha', 'turnstile']

const hasProviderEnv = (provider: CaptchaProvider) => Deno.env.has(SECRET_KEY_ENV[provider])

/**
 * Resolves which `CaptchaProvider` `captchaGuard()` should use when no explicit `options.provider`
 * is given, re-read on every call (not cached) — mirrors `@zanix/notifications`'
 * `resolveSmsProvider()`/`resolveWhatsappProvider()`.
 *
 * - `CAPTCHA_PROVIDER_ENV` set: that value wins outright, `'recaptcha'`/`'hcaptcha'`/`'turnstile'`
 *   only.
 * - `CAPTCHA_PROVIDER_ENV` unset, exactly one provider's own secret-key env var set: that one,
 *   auto-detected — zero-config.
 * - `CAPTCHA_PROVIDER_ENV` unset, more than one provider's secret-key env var set at once: throws
 *   rather than silently picking one.
 * - Nothing set: `undefined` — `captchaGuard()` becomes a pass-through (see its own doc).
 *
 * @returns `'recaptcha'`, `'hcaptcha'`, `'turnstile'`, or `undefined` when nothing is configured.
 * @throws {InternalError} If `CAPTCHA_PROVIDER_ENV` is set to an unsupported value, or if it's
 * unset while more than one provider's own secret-key env var is set at once.
 */
export function resolveCaptchaProvider(): CaptchaProvider | undefined {
  const raw = Deno.env.get(CAPTCHA_PROVIDER_ENV)
  if (raw) {
    if (!PROVIDERS.includes(raw as CaptchaProvider)) {
      throw new InternalError(
        `[captchaGuard] "${CAPTCHA_PROVIDER_ENV}" must be one of ${
          PROVIDERS.join(', ')
        } — got "${raw}".`,
      )
    }
    return raw as CaptchaProvider
  }

  const configured = PROVIDERS.filter(hasProviderEnv)

  if (configured.length > 1) {
    throw new InternalError(
      `[captchaGuard] More than one captcha provider's env vars are set (${
        configured.join(', ')
      }) with no "${CAPTCHA_PROVIDER_ENV}" selected — set "${CAPTCHA_PROVIDER_ENV}=<provider>" ` +
        'to disambiguate.',
    )
  }

  return configured[0]
}

const buildAdapter = (
  provider: CaptchaProvider,
  secretKey: string,
  apiBase?: string,
): CaptchaProviderAdapter => {
  switch (provider) {
    case 'recaptcha':
      return new RecaptchaAdapter({ secretKey, apiBase })
    case 'hcaptcha':
      return new HCaptchaAdapter({ secretKey, apiBase })
    case 'turnstile':
      return new TurnstileAdapter({ secretKey, apiBase })
  }
}

/**
 * Resolves `options` into a ready-to-use `CaptchaProviderAdapter`, or `undefined` when nothing is
 * configured (see `captchaGuard`'s own doc on the resulting pass-through behavior).
 *
 * - `options.adapter`, if given, wins outright — no provider/env resolution at all.
 * - Otherwise `options.provider` (falling back to `resolveCaptchaProvider()`) selects the
 *   provider, and `options.secretKey`/`options.apiBase` (each falling back to that provider's own
 *   env var) configure it.
 *
 * @throws (via `resolveCaptchaProvider()`) if provider resolution is ambiguous/invalid, or if the
 * resolved provider has no secret key (`options.secretKey` nor its own env var).
 */
export function resolveCaptchaAdapter(options: CaptchaOptions): CaptchaProviderAdapter | undefined {
  if (options.adapter) return options.adapter

  const provider = options.provider ?? resolveCaptchaProvider()
  if (!provider) return undefined

  const secretKey = options.secretKey ?? Deno.env.get(SECRET_KEY_ENV[provider])
  if (!secretKey) {
    throw new InternalError(
      `[captchaGuard] Provider "${provider}" requires a secret key — set "options.secretKey" or ` +
        `"${SECRET_KEY_ENV[provider]}".`,
    )
  }

  const apiBase = options.apiBase ?? Deno.env.get(API_BASE_ENV[provider])

  return buildAdapter(provider, secretKey, apiBase)
}
