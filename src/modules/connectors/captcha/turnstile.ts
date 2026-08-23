import type {
  CaptchaProviderAdapter,
  CaptchaVerifyResult,
  TurnstileConfig,
} from 'typings/captcha.ts'

import { RestClient } from '@zanix/server'
import logger from '@zanix/logger'

const TURNSTILE_API_BASE = 'https://challenges.cloudflare.com/turnstile/v0'

/** Cloudflare Turnstile's `POST siteverify` response shape — pass/fail only, no `score` field in
 * the public API. See https://developers.cloudflare.com/turnstile/get-started/server-side-validation/. */
interface TurnstileSiteverifyResponse {
  success: boolean
  'challenge_ts'?: string
  hostname?: string
  action?: string
  'error-codes'?: string[]
}

/**
 * `CaptchaProviderAdapter` for Cloudflare Turnstile's `siteverify` endpoint.
 *
 * Extends `@zanix/server`'s `RestClient` (via `this.http`), same as `@zanix/notifications`'
 * `TwilioSmsAdapter`/`VonageSmsAdapter`, rather than calling `fetch` directly.
 */
export class TurnstileAdapter extends RestClient implements CaptchaProviderAdapter {
  #secretKey: string

  /**
   * Creates a `TurnstileAdapter`.
   *
   * @param config Turnstile secret key and optional API base override.
   */
  constructor(config: TurnstileConfig) {
    super({
      baseUrl: config.apiBase || TURNSTILE_API_BASE,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    })
    this.#secretKey = config.secretKey
  }

  /**
   * Verifies a response token via Turnstile's `siteverify` endpoint.
   *
   * @param token The client-side widget's response token.
   * @throws {HttpError} If the transport-level response is a non-2xx status (e.g. invalid secret
   * key).
   */
  public async verify(token: string): Promise<CaptchaVerifyResult> {
    const body = new URLSearchParams({ secret: this.#secretKey, response: token })

    let response: TurnstileSiteverifyResponse
    try {
      response = await this.http.post<TurnstileSiteverifyResponse>('siteverify', { body })
    } catch (error) {
      // Metadata only — provider is safe to log, the response token and Turnstile's own response
      // body are not — left unlogged, still available in the caught `error`'s own `cause`.
      logger.error('[TurnstileAdapter] Verification request failed (transport-level).', {
        provider: 'turnstile',
      })
      throw error
    }

    // Turnstile never returns `score` in its public API — always `undefined`, so `captchaGuard`'s
    // `minScore` threshold never applies to it.
    return { success: response.success, errorCodes: response['error-codes'] }
  }
}
