import { assert, assertFalse } from '@std/assert'
import { ProgramModule, type ZanixCacheProvider } from '@zanix/server'
import { generateOTP, verifyOTP } from 'utils/otp.ts'

console.warn = () => {}
console.info = () => {}

export const shouldGenerateAndExpire = async (provider: 'local' | 'redis') => {
  await import('@zanix/datamaster') // load cache core
  const cache = ProgramModule.getProviders().get<ZanixCacheProvider>('cache')

  const target = 'pepito@email.com'

  const code = await generateOTP(cache, { target, exp: 1 })

  await new Promise((resolve) => setTimeout(resolve, 1000))

  assertFalse(await verifyOTP(cache, target, code)) // expired

  if (provider === 'redis') await cache.redis.clear()
  cache.local.clear()
}

export const shouldGenerateAndVerify = async (provider: 'local' | 'redis') => {
  await import('@zanix/datamaster') // load cache core
  const cache = ProgramModule.getProviders().get<ZanixCacheProvider>('cache')

  const target = 'pepito@email.com'

  const code = await generateOTP(cache, { target })

  await new Promise((resolve) => setTimeout(resolve, 500))

  assertFalse(await verifyOTP(cache, target, 'code'))
  assert(await verifyOTP(cache, target, code))
  assertFalse(await verifyOTP(cache, target, code))

  if (provider === 'redis') await cache.redis.clear()
  cache.local.clear()
}

export const shouldAllowDifferentLens = async (provider: 'local' | 'redis') => {
  await import('@zanix/datamaster') // load cache core
  const cache = ProgramModule.getProviders().get<ZanixCacheProvider>('cache')

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
