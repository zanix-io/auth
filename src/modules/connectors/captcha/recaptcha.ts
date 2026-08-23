import type {
  CaptchaProviderAdapter,
  CaptchaVerifyResult,
  RecaptchaConfig,
} from 'typings/captcha.ts'

import { RestClient } from '@zanix/server'
import logger from '@zanix/logger'

const RECAPTCHA_API_BASE = 'https://www.google.com/recaptcha/api'

/** Google reCAPTCHA's `POST siteverify` response shape (v2 and v3 share one endpoint/shape; `score`/
 * `action` are only present for a v3 site key). See
 * https://developers.google.com/recaptcha/docs/verify. */
interface RecaptchaSiteverifyResponse {
  success: boolean
  score?: number
  action?: string
  'challenge_ts'?: string
  hostname?: string
  'error-codes'?: string[]
}

/**
 * `CaptchaProviderAdapter` for Google reCAPTCHA's `siteverify` endpoint — works with both v2
 * (checkbox/invisible, pass/fail only) and v3 (score-based) site keys, since both share the same
 * request/response shape; only a v3 key's response carries `score`.
 *
 * Extends `@zanix/server`'s `RestClient` (via `this.http`), same as `@zanix/notifications`'
 * `TwilioSmsAdapter`/`VonageSmsAdapter`, rather than calling `fetch` directly.
 */
export class RecaptchaAdapter extends RestClient implements CaptchaProviderAdapter {
  #secretKey: string

  /**
   * Creates a `RecaptchaAdapter`.
   *
   * @param config reCAPTCHA secret key and optional API base override.
   */
  constructor(config: RecaptchaConfig) {
    super({
      baseUrl: config.apiBase || RECAPTCHA_API_BASE,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    })
    this.#secretKey = config.secretKey
  }

  /**
   * Verifies a response token via reCAPTCHA's `siteverify` endpoint.
   *
   * @param token The client-side widget's response token.
   * @throws {HttpError} If the transport-level response is a non-2xx status (e.g. invalid secret
   * key).
   */
  public async verify(token: string): Promise<CaptchaVerifyResult> {
    const body = new URLSearchParams({ secret: this.#secretKey, response: token })

    let response: RecaptchaSiteverifyResponse
    try {
      response = await this.http.post<RecaptchaSiteverifyResponse>('siteverify', { body })
    } catch (error) {
      // Metadata only, per the verify-path logging policy: provider is safe to log, the response
      // token itself and reCAPTCHA's own response body are not — left unlogged, still available in
      // the caught `error`'s own `cause` for anyone catching it.
      logger.error('[RecaptchaAdapter] Verification request failed (transport-level).', {
        provider: 'recaptcha',
      })
      throw error
    }

    return { success: response.success, score: response.score, errorCodes: response['error-codes'] }
  }
}
