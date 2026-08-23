import type {
  CaptchaProviderAdapter,
  CaptchaVerifyResult,
  HCaptchaConfig,
} from 'typings/captcha.ts'

import { RestClient } from '@zanix/server'
import logger from '@zanix/logger'

const HCAPTCHA_API_BASE = 'https://hcaptcha.com'

/** hCaptcha's `POST siteverify` response shape. `score`/`score_reason` are Enterprise-plan-only
 * fields — absent on the standard free API. See https://docs.hcaptcha.com/#verify-the-user-response-server-side. */
interface HCaptchaSiteverifyResponse {
  success: boolean
  score?: number
  'challenge_ts'?: string
  hostname?: string
  'error-codes'?: string[]
}

/**
 * `CaptchaProviderAdapter` for hCaptcha's `siteverify` endpoint.
 *
 * Extends `@zanix/server`'s `RestClient` (via `this.http`), same as `@zanix/notifications`'
 * `TwilioSmsAdapter`/`VonageSmsAdapter`, rather than calling `fetch` directly.
 */
export class HCaptchaAdapter extends RestClient implements CaptchaProviderAdapter {
  #secretKey: string

  /**
   * Creates an `HCaptchaAdapter`.
   *
   * @param config hCaptcha secret key and optional API base override.
   */
  constructor(config: HCaptchaConfig) {
    super({
      baseUrl: config.apiBase || HCAPTCHA_API_BASE,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    })
    this.#secretKey = config.secretKey
  }

  /**
   * Verifies a response token via hCaptcha's `siteverify` endpoint.
   *
   * @param token The client-side widget's response token.
   * @throws {HttpError} If the transport-level response is a non-2xx status (e.g. invalid secret
   * key).
   */
  public async verify(token: string): Promise<CaptchaVerifyResult> {
    const body = new URLSearchParams({ secret: this.#secretKey, response: token })

    let response: HCaptchaSiteverifyResponse
    try {
      response = await this.http.post<HCaptchaSiteverifyResponse>('siteverify', { body })
    } catch (error) {
      // Metadata only — provider is safe to log, the response token and hCaptcha's own response
      // body are not — left unlogged, still available in the caught `error`'s own `cause`.
      logger.error('[HCaptchaAdapter] Verification request failed (transport-level).', {
        provider: 'hcaptcha',
      })
      throw error
    }

    return { success: response.success, score: response.score, errorCodes: response['error-codes'] }
  }
}
