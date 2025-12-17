import type { ZanixCacheProvider } from '@zanix/server'
import type { GenerateOTPOptions } from 'typings/auth.ts'
import { CACHE_KEYS } from './constants.ts'

/**
 * Generates a cryptographically secure numeric code of the given length.
 *
 * Uses `crypto.getRandomValues()` to produce a sequence of random bytes,
 * which are then reduced to digits (0–9) to form the OTP code.
 *
 * @param {number} length - Number of digits to generate.
 * @returns {string} A numeric OTP code of the specified length.
 */
const randomCode = (length: number): string => {
  const bytes = new Uint8Array(length)
  crypto.getRandomValues(bytes)

  // Convert each byte into a digit (0–9)
  const digits = Array.from(bytes, (b) => (b % 10).toString())
  return digits.join('')
}

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
  if (Deno.env.has('REDIS_URI')) {
    await cache.saveToCaches({ provider: 'redis', key, value: code, exp })
  } else {
    cache.local.set(key, code, { exp })
  }

  return code
}

/**
 * Validates an OTP code previously generated for the given target.
 *
 * The method retrieves the stored OTP from Redis (if available) or from the
 * local in-memory cache. When validation succeeds, the OTP is removed to ensure
 * one-time use.
 *
 * @param {ZanixCacheProvider} cache - The cache provider instance used to retrieve the OTP.
 * @param {string} target - The identifier associated with the stored OTP.
 * @param {string} code - The one-time password (OTP) code that the user provides for verification.
 *
 * @returns {Promise<boolean>} `true` if the OTP is valid and matches the stored entry;
 * otherwise, `false`.
 */

export const verifyOTP = async (
  cache: ZanixCacheProvider,
  target: string,
  code: string,
): Promise<boolean> => {
  if (!code) return false

  let isValid: boolean = false

  const key = `${CACHE_KEYS.otp}:${target}`

  if (Deno.env.has('REDIS_URI')) {
    const entry = await cache.getCachedOrFetch<string>('redis', key)
    isValid = entry === code
    if (isValid) {
      cache.local.delete(key)
      await cache.redis.delete(key)
    }
  } else {
    const entry = cache.local.get(key)
    isValid = entry === code
    if (isValid) cache.local.delete(key)
  }

  return isValid
}
