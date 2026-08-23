import type { ZanixCacheProvider } from '@zanix/server'
import type { GenerateOTPOptions, VerifyOTPOptions } from 'typings/auth.ts'
import { CACHE_KEYS, REDIS_URI_ENV } from './constants.ts'

/** Default number of wrong guesses a single OTP tolerates before it's burned outright — see
 * {@link verifyOTP}'s own doc. */
export const DEFAULT_OTP_MAX_ATTEMPTS = 5

/**
 * Largest byte value that still divides evenly into 10 outcomes (`250 = 25 * 10`) — a byte above
 * this (`250`-`255`, 6 of the 256 possible values) is discarded and redrawn instead of reduced
 * mod 10, so every digit 0-9 has exactly a 25/250 (not 26/256 vs 25/256) chance. Rejection
 * sampling, not a smaller modulus, is what makes this actually unbiased.
 */
const MAX_UNBIASED_BYTE = 249

/**
 * Fills `digits` with `length` cryptographically secure, unbiased random decimal digit characters.
 *
 * Draws a single batch of `length + 4` random bytes up front rather than one byte at a time — the
 * ~2.34% (6/256) rejection rate at {@link MAX_UNBIASED_BYTE} means a batch this size clears every
 * digit without ever needing a second batch the overwhelming majority of the time (a run needing
 * more than 4 rejections across the whole draw has well under 1% probability even at `length: 6`),
 * so this stays a single `crypto.getRandomValues()` call in the common case while still being
 * exact — a fresh batch is drawn on the rare occasion the first one isn't enough.
 */
function fillUnbiasedDigits(length: number): string[] {
  const digits = new Array<string>(length)
  let filled = 0
  let buffer = crypto.getRandomValues(new Uint8Array(length + 4))
  let cursor = 0

  while (filled < length) {
    if (cursor >= buffer.length) {
      buffer = crypto.getRandomValues(new Uint8Array(length - filled))
      cursor = 0
    }
    const byte = buffer[cursor++]
    if (byte <= MAX_UNBIASED_BYTE) digits[filled++] = (byte % 10).toString()
  }

  return digits
}

/**
 * Generates a cryptographically secure, unbiased numeric code of the given length.
 *
 * Uses `crypto.getRandomValues()` via {@link fillUnbiasedDigits} — rejection sampling, not a bare
 * `byte % 10`, is what keeps every digit equally likely: `256 % 10 !== 0`, so reducing an
 * unfiltered byte mod 10 would give digits 0-5 a 26/256 chance and digits 6-9 only 25/256 — a
 * small but real, measurable skew away from uniform.
 *
 * @param {number} length - Number of digits to generate.
 * @returns {string} A numeric OTP code of the specified length.
 */
export const randomCode = (length: number): string => fillUnbiasedDigits(length).join('')

/**
 * Generates a numeric OTP and stores it in the configured cache provider.
 *
 * The OTP is associated with a unique `target` (such as an email, phone number,
 * or user ID) and saved with an expiration time (TTL). If a Redis URI is detected
 * in the environment, the OTP is stored in Redis; otherwise, it is stored in the
 * local in-memory cache.
 *
 * @param {ZanixCacheProvider} cache - The cache provider instance used to store the OTP.
 * @param {GenerateOTPOptions} options - OTP generation options.
 * @param {string} options.target - Identifier to bind the OTP to.
 * @param {number} [options.exp=300] - Expiration time in seconds (TTL). Defaults to 5 minutes.
 * @param {number} [options.length=6] - Number of digits for the OTP code. Defaults to 6.
 *
 * @returns {Promise<string>} The generated OTP code.
 */
export const generateOTP = async (
  cache: ZanixCacheProvider,
  options: GenerateOTPOptions,
): Promise<string> => {
  const { target, exp = 300, length = 6 } = options
  const code = randomCode(length)

  const key = `${CACHE_KEYS.otp}:${target}`
  if (Deno.env.has(REDIS_URI_ENV)) {
    await cache.saveToCaches({ provider: 'redis', key, value: code, exp })
  } else {
    cache.local.set(key, code, { exp })
  }

  return code
}

/** Cache key tracking how many wrong guesses a given target's current OTP has received — separate
 * from the OTP's own key so burning it on too many attempts never needs to touch (or guess at the
 * remaining TTL of) the OTP entry itself. */
const attemptsKey = (target: string): string => `${CACHE_KEYS.otp}:${target}:attempts`

/**
 * Validates an OTP code previously generated for the given target.
 *
 * The method retrieves the stored OTP from Redis (if available) or from the
 * local in-memory cache. When validation succeeds, the OTP is removed to ensure
 * one-time use.
 *
 * A wrong guess counts against `options.maxAttempts` (default {@link DEFAULT_OTP_MAX_ATTEMPTS}) —
 * once reached, the OTP is burned outright (deleted, `false` returned) even though it hasn't
 * actually expired yet. Without this, a short numeric code behind no other rate limiting could be
 * brute-forced by simply retrying it for as long as its TTL allows — a 6-digit code has only
 * 1,000,000 possibilities, well within reach of a scripted attempt inside a typical multi-minute
 * TTL with no attempt cap at all. The counter itself expires independently (a short, fixed TTL —
 * it only ever needs to outlive the attempts against one still-live OTP, never the OTP's own
 * custom `exp`), so it never lingers as permanent per-target storage.
 *
 * @param {ZanixCacheProvider} cache - The cache provider instance used to retrieve the OTP.
 * @param {string} target - The identifier associated with the stored OTP.
 * @param {string} code - The one-time password (OTP) code that the user provides for verification.
 * @param {VerifyOTPOptions} [options] - Verification options (currently just `maxAttempts`).
 *
 * @returns {Promise<boolean>} `true` if the OTP is valid and matches the stored entry;
 * otherwise, `false`.
 */
export const verifyOTP = async (
  cache: ZanixCacheProvider,
  target: string,
  code: string,
  options: VerifyOTPOptions = {},
): Promise<boolean> => {
  if (!code) return false

  const { maxAttempts = DEFAULT_OTP_MAX_ATTEMPTS } = options
  const key = `${CACHE_KEYS.otp}:${target}`
  const useRedis = Deno.env.has(REDIS_URI_ENV)

  const entry = useRedis ? await cache.getCachedOrFetch<string>('redis', key) : cache.local.get(key)

  if (!entry) return false

  if (entry === code) {
    await burnOtp(cache, target, useRedis)
    return true
  }

  await registerFailedAttempt(cache, target, maxAttempts, useRedis)
  return false
}

/** Deletes both the OTP entry and its attempts counter — a successful verify (one-time use) or a
 * `maxAttempts`-exceeding failure both end the OTP's life the same way. */
async function burnOtp(
  cache: ZanixCacheProvider,
  target: string,
  useRedis: boolean,
): Promise<void> {
  const key = `${CACHE_KEYS.otp}:${target}`
  cache.local.delete(key)
  cache.local.delete(attemptsKey(target))
  if (useRedis) {
    await cache.redis.delete(key)
    await cache.redis.delete(attemptsKey(target))
  }
}

/** Same fixed TTL for every attempts counter, independent of the OTP's own `exp` — see
 * {@link verifyOTP}'s own doc for why that's fine. */
const ATTEMPTS_COUNTER_TTL = 900

async function registerFailedAttempt(
  cache: ZanixCacheProvider,
  target: string,
  maxAttempts: number,
  useRedis: boolean,
): Promise<void> {
  const key = attemptsKey(target)
  const stored = useRedis
    ? await cache.getCachedOrFetch<number>('redis', key)
    : cache.local.get(key)
  const attempts = (Number(stored) || 0) + 1

  if (attempts >= maxAttempts) {
    await burnOtp(cache, target, useRedis)
    return
  }

  if (useRedis) {
    await cache.saveToCaches({
      provider: 'redis',
      key,
      value: attempts,
      exp: ATTEMPTS_COUNTER_TTL,
    })
  } else {
    cache.local.set(key, attempts, { exp: ATTEMPTS_COUNTER_TTL })
  }
}
