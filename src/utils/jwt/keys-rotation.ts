import { isNumberString } from '@zanix/validator'
import { parseTTL } from '@zanix/helpers'
import { JWK_PRI_ENV, JWK_ROTATION_CYCLE_ENV, JWT_KEY_ENV } from 'utils/constants.ts'

export const jwtKeys: Record<
  typeof JWT_KEY_ENV | typeof JWK_PRI_ENV,
  Map<number, { value: string; version: `V${number}` }>
> = {
  [JWT_KEY_ENV]: new Map<number, { value: string; version: `V${number}` }>(),
  [JWK_PRI_ENV]: new Map<number, { value: string; version: `V${number}` }>(),
}

/**
 * Returns all versioned keys for a given prefix.
 * Versioned keys follow the pattern `${PREFIX}_V1`, `${PREFIX}_V2`, ...
 *
 * @param {typeof JWT_KEY_ENV | typeof JWK_PRI_ENV} prefix - The environment variable prefix.
 * @returns { Map<number, { value: string; version: `V${number}` }>} Ordered list of versioned key values found in the environment.
 */
function getVersionedKeys(
  prefix: typeof JWT_KEY_ENV | typeof JWK_PRI_ENV,
): Map<number, { value: string; version: `V${number}` }> {
  const jwks = jwtKeys[prefix]
  if (jwks.size) return jwks

  let index = 0
  while (true) {
    const version = `V${index + 1}` as const
    const envKey = `${prefix}_${version}`
    const value = Deno.env.get(envKey)
    if (!value) break
    jwks.set(index, { value, version })
    index++
  }

  return jwks
}

/**
 * Reads the rotation cycle duration from `JWK_ROTATION_CYCLE`.
 * The value is a TTL string such as "30d", "12h" or `0` to disable.
 * A missing value defaults to `30d`; only an explicit `0` disables rotation.
 *
 * @returns {number} The cycle length in seconds. Returns 0 if rotation is disabled.
 */
function getRotationCycle(): number {
  const cycleStr = Deno.env.get(JWK_ROTATION_CYCLE_ENV) || '30d'
  if (cycleStr === '0') return 0
  return parseTTL(isNumberString(cycleStr) ? Number(cycleStr) : cycleStr)
}

/**
 * Computes the index of the active versioned key based on time.
 * It divides the current timestamp by the cycle duration and performs
 * a modulo operation to rotate through available keys.
 *
 * @param {number} cycleSeconds - Rotation cycle duration in seconds.
 * @param {number} total - Number of available versioned keys.
 * @returns {number} Index of the active key (0-based).
 */
function getActiveVersionIndex(cycleSeconds: number, total: number): number {
  if (cycleSeconds <= 0 || total === 0) return 0

  const now = Math.floor(Date.now() / 1000)
  const cycleIndex = Math.floor(now / cycleSeconds)

  return cycleIndex % total
}

/**
 * Returns the currently active key for a given prefix.
 * - If versioned keys exist → picks one according to the rotation cycle.
 * - If NO versioned keys exist → returns the base key `${PREFIX}`.
 * - If nothing is defined → returns `undefined`.
 *
 * Key rotation is controlled by the `JWK_ROTATION_CYCLE` environment variable,
 * and it rotates only among the key versions that actually exist in the environment (e.g. `JWT_KEY_V1`,
 * `JWT_KEY_V2`, `JWT_KEY_V3`, ...). If fewer or more versions are present,
 * the rotation adapts accordingly and cycles through the available keys.
 *
 * @param {typeof JWT_KEY_ENV | typeof JWK_PRI_ENV} prefix - Environment variable prefix to resolve.
 * @returns {{ value?: string; version?: \`V${number}\` }} The selected key value and, when versioned, its version.
 */
export function getRotatingKey(
  prefix: typeof JWT_KEY_ENV | typeof JWK_PRI_ENV,
): { value?: string; version?: `V${number}` } {
  const versions = getVersionedKeys(prefix)

  // No versions → fallback to base key
  if (versions.size === 0) {
    const base = Deno.env.get(prefix)
    return { value: base }
  }

  const cycleSeconds = getRotationCycle()
  const idx = getActiveVersionIndex(cycleSeconds, versions.size)
  // deno-lint-ignore no-non-null-assertion
  return versions.get(idx)!
}
