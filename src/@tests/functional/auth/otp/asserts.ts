// deno-coverage-ignore-file

import { assert, assertFalse } from '@std/assert'
import { ProgramModule, type ZanixCacheProvider } from '@zanix/server'
import { generateOTP, verifyOTP } from 'utils/otp.ts'

console.warn = () => {}
console.info = () => {}

export const shouldGenerateAndExpire = async (provider: 'local' | 'redis') => {
  await import('@zanix/datamaster/core') // load cache core
  const cache = ProgramModule.providers.get<ZanixCacheProvider>('cache')

  const target = 'pepito@email.com'

  const code = await generateOTP(cache, { target, exp: 1 })

  await new Promise((resolve) => setTimeout(resolve, 1000))

  assertFalse(await verifyOTP(cache, target, code)) // expired

  if (provider === 'redis') await cache.redis.clear()
  cache.local.clear()
}

export const shouldGenerateAndVerify = async (provider: 'local' | 'redis') => {
  await import('@zanix/datamaster/core') // load cache core
  const cache = ProgramModule.providers.get<ZanixCacheProvider>('cache')

  const target = 'pepito@email.com'

  const code = await generateOTP(cache, { target })

  await new Promise((resolve) => setTimeout(resolve, 500))

  assertFalse(await verifyOTP(cache, target, 'code'))
  assert(await verifyOTP(cache, target, code))
  assertFalse(await verifyOTP(cache, target, code))

  if (provider === 'redis') await cache.redis.clear()
  cache.local.clear()
}

/**
 * Regression coverage for a confirmed risk: `verifyOTP` used to never track failed attempts at
 * all — a wrong guess was a no-op, so the same still-valid OTP could be retried indefinitely
 * (brute-forced) for as long as its own TTL allowed. `maxAttempts` burns the OTP outright once
 * exceeded, before it would otherwise expire.
 */
export const shouldLockOutAfterMaxAttempts = async (provider: 'local' | 'redis') => {
  await import('@zanix/datamaster/core') // load cache core
  const cache = ProgramModule.providers.get<ZanixCacheProvider>('cache')

  const target = 'pepito@email.com'
  const code = await generateOTP(cache, { target })

  await new Promise((resolve) => setTimeout(resolve, 500))

  // 2 wrong guesses, maxAttempts: 3 — still alive after each.
  assertFalse(await verifyOTP(cache, target, 'wrong-1', { maxAttempts: 3 }))
  assertFalse(await verifyOTP(cache, target, 'wrong-2', { maxAttempts: 3 }))

  // The 3rd wrong guess reaches maxAttempts — burns the OTP outright.
  assertFalse(await verifyOTP(cache, target, 'wrong-3', { maxAttempts: 3 }))

  // Even the real code no longer verifies — the OTP is gone, not merely "still wrong."
  assertFalse(await verifyOTP(cache, target, code, { maxAttempts: 3 }))

  if (provider === 'redis') await cache.redis.clear()
  cache.local.clear()
}

export const shouldAllowDifferentLens = async (provider: 'local' | 'redis') => {
  await import('@zanix/datamaster/core') // load cache core
  const cache = ProgramModule.providers.get<ZanixCacheProvider>('cache')

  const target = 'pepito@email.com'

  let code = await generateOTP(cache, { target })

  assert(code.length === 6)

  code = await generateOTP(cache, { target, length: 3 })

  assert(code.length === 3)

  code = await generateOTP(cache, { target, length: 8 })

  assert(code.length === 8)

  if (provider === 'redis') await cache.redis.clear()
  cache.local.clear()
}
