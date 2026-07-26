import { assert, assertFalse } from '@std/assert'
import { addTokenToBlockList, checkTokenBlockList } from 'utils/sessions/block-list.ts'
import { createJWT } from 'utils/jwt/create.ts'
import { ProgramModule, type ZanixCacheProvider, type ZanixKVConnector } from '@zanix/server'

console.warn = () => {}
console.info = () => {}

export const asserts = async () => {
  await import('jsr:@zanix/datamaster@0.5.*/core') // load cache core
  const localDb = ProgramModule.connectors.get<ZanixKVConnector>('kvLocal')
  const cache = ProgramModule.providers.get<ZanixCacheProvider>('cache')

  Deno.env.set('JWT_KEY', 'my-secret')
  // exp is computed via two independent Math.floor(Date.now() / 1000) calls (here and inside
  // addTokenToBlockList), so the effective TTL stored in the cache can be up to 1s shorter than
  // the nominal 5s. A wide margin on both sides absorbs that rounding slop plus Redis latency.
  const token = await createJWT({ exp: Math.floor(Date.now() / 1000) + 5 }, 'my-secret')
  const payload = await addTokenToBlockList(token, cache, localDb)
  const isBlocked = await checkTokenBlockList(payload.jti, cache, localDb)
  assert(isBlocked)

  await new Promise((resolve) => setTimeout(resolve, 1000))
  assert(await checkTokenBlockList(payload.jti, cache, localDb)) // still here

  await new Promise((resolve) => setTimeout(resolve, 6000))
  assertFalse(await checkTokenBlockList(payload.jti, cache, localDb)) // expired

  Deno.env.delete('JWT_KEY')
  localDb.clear()
  localDb['close']()
}
