/**
 * Outcome of verifying a captcha response token against a provider's `siteverify`-style
 * endpoint.
 */
export interface CaptchaVerifyResult {
  /** Whether the token is valid and the challenge was solved. */
  success: boolean
  /**
   * Confidence score (`0.0`-`1.0`, higher = more likely human), only returned by score-based
   * providers/keys (e.g. Google reCAPTCHA v3). `undefined` for pass/fail-only responses
   * (reCAPTCHA v2, hCaptcha, Turnstile) — `captchaGuard` only applies its `minScore` threshold
   * when this is set.
   */
  score?: number
  /** Raw error codes from the provider's response, present when `success` is `false`. */
  errorCodes?: string[]
}

/**
 * Pluggable captcha verification contract. `captchaGuard` delegates to whichever adapter is
 * configured/resolved (see `CaptchaOptions`), so it isn't coupled to any single vendor.
 */
export interface CaptchaProviderAdapter {
  /**
   * Verifies a captcha response token against the provider's own verification endpoint.
   *
   * @param token - The response token produced by the provider's client-side widget/script,
   *                forwarded as-is — see `captchaGuard`'s own doc for how it arrives on a request.
   * @throws {HttpError} If the transport-level response is a non-2xx status.
   */
  verify(token: string): Promise<CaptchaVerifyResult>
}

/**
 * The three built-in captcha providers `CAPTCHA_PROVIDER_ENV`/`resolveCaptchaProvider()` choose
 * between.
 */
export type CaptchaProvider = 'recaptcha' | 'hcaptcha' | 'turnstile'

/** Shared shape for every built-in provider adapter's own config. */
export interface CaptchaProviderConfig {
  /** The provider's server-side secret key. */
  secretKey: string
  /** Overrides the provider's verification API base URL (proxy, mock server). */
  apiBase?: string
}

/** Google reCAPTCHA (v2 checkbox/invisible, or v3 score-based) credentials. */
export type RecaptchaConfig = CaptchaProviderConfig

/** hCaptcha credentials. */
export type HCaptchaConfig = CaptchaProviderConfig

/** Cloudflare Turnstile credentials. */
export type TurnstileConfig = CaptchaProviderConfig

/**
 * The `captchaGuard` configuration options.
 */
export interface CaptchaOptions {
  /**
   * Explicit provider selection. Falls back to the `CAPTCHA_PROVIDER` environment variable, then
   * to auto-detection (exactly one provider's own secret-key env var set) — see
   * `resolveCaptchaProvider()`.
   */
  provider?: CaptchaProvider
  /**
   * Custom adapter — bypasses provider resolution/env entirely. Use this for a provider with no
   * built-in adapter, or to inject a mock in tests.
   */
  adapter?: CaptchaProviderAdapter
  /**
   * The resolved provider's secret key. Falls back to that provider's own env var
   * (`RECAPTCHA_SECRET_KEY`/`HCAPTCHA_SECRET_KEY`/`TURNSTILE_SECRET_KEY`) when omitted.
   */
  secretKey?: string
  /** Overrides the resolved provider's verification API base URL. Falls back to its own env var. */
  apiBase?: string
  /**
   * Minimum confidence score (`0.0`-`1.0`) required to pass, for providers/keys that return a
   * `score` (see `CaptchaVerifyResult.score`) — ignored when a response carries no score.
   * Defaults to `0.5`.
   */
  minScore?: number
}
