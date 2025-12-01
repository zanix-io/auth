import { assert, assertFalse } from '@std/assert'
import { addTokenToBlockList, checkTokenBlockList } from 'utils/sessions/block-list.ts'
import { createJWT } from 'utils/jwt/create.ts'
import { ProgramModule, type ZanixCacheProvider, type ZanixKVConnector } from '@zanix/server'

console.warn = () => {}
console.info = () => {}

export const asserts = async () => {
  await import('@zanix/datamaster') // load cache core
  const localDb = ProgramModule.getConnectors().get<ZanixKVConnector>('kvLocal')
  const cache = ProgramModule.getProviders().get<ZanixCacheProvider>('cache')

  Deno.env.set('JWT_KEY', 'my-secret')
  const token = await createJWT({ exp: Math.floor(Date.now() / 1000) + 1 }, 'my-secret') // Expired in 1 second
  const payload = await addTokenToBlockList(token, cache, localDb)
  const isBlocked = await checkTokenBlockList(payload.jti, cache, localDb)
  assert(isBlocked)

  await new Promise((resolve) => setTimeout(resolve, 900))
  assert(await checkTokenBlockList(payload.jti, cache, localDb)) // still here

  await new Promise((resolve) => setTimeout(resolve, 100))
  assertFalse(await checkTokenBlockList(payload.jti, cache, localDb)) // expired

  Deno.env.delete('JWT_KEY')
  localDb.clear()
  localDb['close']()
}
