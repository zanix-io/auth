import { base32Decode, base32Encode, signHMACBytes } from '@zanix/helpers'
import { DEFAULT_AUTH_ISSUER } from './constants.ts'

const DEFAULT_DIGITS = 6
const DEFAULT_PERIOD = 30
const DEFAULT_WINDOW = 1
const DEFAULT_SECRET_LENGTH = 20

/** Encodes a time-step counter as an 8-byte big-endian buffer, per RFC 4226. */
const counterToBytes = (counter: number): Uint8Array<ArrayBuffer> => {
  const bytes = new Uint8Array(8)
  for (let i = 7; i >= 0; i--) {
    bytes[i] = counter & 0xff
    counter = Math.floor(counter / 256)
  }
  return bytes
}

/** RFC 4226 dynamic truncation: derives a `digits`-long numeric code from an HMAC digest. */
const dynamicTruncate = (hmac: Uint8Array, digits: number): string => {
  const offset = hmac[hmac.length - 1] & 0x0f
  const binCode = ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff)

  const code = binCode % 10 ** digits
  return code.toString().padStart(digits, '0')
}

/**
 * Generates a new random TOTP secret, encoded as an unpadded Base32 string — the format
 * authenticator apps (Google Authenticator, Microsoft Authenticator, etc.) expect for manual
 * entry or QR-code provisioning.
 *
 * @param {number} [length=20] - Number of random bytes to generate (20 bytes = 160 bits, the
 *   standard recommendation for a SHA-1-based secret).
 * @returns {string} The Base32-encoded secret.
 */
export const generateTOTPSecret = (
  length: number = DEFAULT_SECRET_LENGTH,
): string => {
  const bytes = new Uint8Array(length)
  crypto.getRandomValues(bytes)
  return base32Encode(bytes)
}

/**
 * Builds an `otpauth://` provisioning URI for a TOTP secret.
 *
 * The returned URI can be encoded as a QR code and scanned by
 * authenticator apps (such as Google Authenticator or Authy) to
 * register the account and generate TOTP codes.
 *
 * @param {string} secret - The Base32-encoded TOTP secret, as returned by
 *   {@link generateTOTPSecret}.
 * @param {string} accountName - The account identifier shown in the app (e.g. an email address).
 * @param {object} [options] - Provisioning options.
 * @param {string} [options.issuer] - The issuing organization/app name, shown alongside the
 *   account in the authenticator app. Defaults to {@link DEFAULT_AUTH_ISSUER} (`'zanix-auth'`).
 * @param {number} [options.digits=6] - Number of digits in generated codes. Changing this away
 *   from `6` risks breaking compatibility with standard authenticator apps.
 * @param {number} [options.period=30] - Time step in seconds. Changing this away from `30` risks
 *   breaking compatibility with standard authenticator apps.
 * @returns {string} The `otpauth://totp/...` provisioning URI.
 */
export const getTOTPProvisioningUri = (
  secret: string,
  accountName: string,
  options: {
    issuer?: string
    digits?: number
    period?: number
  } = {},
): string => {
  const {
    issuer = DEFAULT_AUTH_ISSUER,
    digits = DEFAULT_DIGITS,
    period = DEFAULT_PERIOD,
  } = options

  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(accountName)}`
  const params = new URLSearchParams({
    secret,
    issuer,
    digits: String(digits),
    period: String(period),
  })

  return `otpauth://totp/${label}?${params.toString()}`
}

/**
 * Computes the TOTP code for a given secret at a point in time (RFC 6238, built on the RFC 4226
 * HOTP dynamic truncation). Always uses HMAC-SHA1 — the algorithm virtually every authenticator
 * app assumes regardless of what a provisioning URI's `algorithm` parameter says, so it's not
 * exposed as an option here.
 *
 * @param {string} secret - The Base32-encoded TOTP secret.
 * @param {object} [options] - Computation options.
 * @param {number} [options.time] - Unix time in seconds. Defaults to the current time.
 * @param {number} [options.digits=6] - Number of digits in the generated code.
 * @param {number} [options.period=30] - Time step in seconds.
 * @returns {Promise<string>} The generated numeric code, zero-padded to `digits` length.
 */
export const generateTOTP = async (
  secret: string,
  options: {
    time?: number
    digits?: number
    period?: number
  } = {},
): Promise<string> => {
  const {
    time = Math.floor(Date.now() / 1000),
    digits = DEFAULT_DIGITS,
    period = DEFAULT_PERIOD,
  } = options

  const counter = Math.floor(time / period)
  const key = new Uint8Array(base32Decode(secret))
  const hmac = await signHMACBytes(key, counterToBytes(counter), 'SHA-1')

  return dynamicTruncate(hmac, digits)
}

/**
 * Verifies a TOTP code against a secret, tolerating clock drift within `window` time steps.
 *
 * @param {string} secret - The Base32-encoded TOTP secret.
 * @param {string} code - The code the user provided for verification.
 * @param {object} [options] - Verification options.
 * @param {number} [options.window=1] - Number of time steps before/after the current one to also
 *   accept (e.g. `1` accepts the previous, current, and next 30s step).
 * @param {number} [options.time] - Unix time in seconds. Defaults to the current time.
 * @param {number} [options.digits=6] - Number of digits in the expected code.
 * @param {number} [options.period=30] - Time step in seconds.
 * @returns {Promise<boolean>} `true` if `code` matches any time step within the window.
 */
export const verifyTOTP = async (
  secret: string,
  code: string,
  options: {
    window?: number
    time?: number
    digits?: number
    period?: number
  } = {},
): Promise<boolean> => {
  if (!code) return false

  const {
    window = DEFAULT_WINDOW,
    time = Math.floor(Date.now() / 1000),
    digits = DEFAULT_DIGITS,
    period = DEFAULT_PERIOD,
  } = options

  const steps = Array.from({ length: window * 2 + 1 }, (_, i) => i - window)
  const candidates = await Promise.all(
    steps.map((step) => generateTOTP(secret, { time: time + step * period, digits, period })),
  )

  return candidates.includes(code)
}
