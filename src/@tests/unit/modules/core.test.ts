// deno-lint-ignore-file no-explicit-any
import { assert, assertThrows } from '@std/assert'
import { ProgramModule } from '@zanix/server'
import { GoogleOAuth2Connector } from 'modules/connectors/google/mod.ts'

const googleConnectorRef = GoogleOAuth2Connector as any

console.error = () => {}

Deno.test('providers/core.ts registers the default auth provider under "auth"', async () => {
  await import('modules/providers/core.ts')

  const provider = ProgramModule.providers.get('auth')
  assert(provider)
})

Deno.test('middlewares/core.ts registers the session headers interceptor', async () => {
  await import('modules/middlewares/core.ts')
})

Deno.test('connectors/google/core.ts skips registration without a client ID', async () => {
  Deno.env.delete('GOOGLE_OAUTH2_CLIENT_ID')

  await import('modules/connectors/google/core.ts')

  assertThrows(() => ProgramModule.connectors.get(googleConnectorRef))
})

Deno.test('connectors/google/core.ts registers the connector when envars are set', async () => {
  Deno.env.set('GOOGLE_OAUTH2_CLIENT_ID', 'test-id')
  Deno.env.set('GOOGLE_OAUTH2_CLIENT_SECRET', 'test-secret')
  Deno.env.set('GOOGLE_OAUTH2_REDIRECT_URI', 'https://example.com/cb')

  await import('modules/connectors/google/core.ts?with-env')

  const connector = ProgramModule.connectors.get(googleConnectorRef)
  assert(connector)

  Deno.env.delete('GOOGLE_OAUTH2_CLIENT_ID')
  Deno.env.delete('GOOGLE_OAUTH2_CLIENT_SECRET')
  Deno.env.delete('GOOGLE_OAUTH2_REDIRECT_URI')
})

Deno.test('modules/core.ts aggregates all core registrations', async () => {
  Deno.env.set('GOOGLE_OAUTH2_CLIENT_ID', 'test-id')
  Deno.env.set('GOOGLE_OAUTH2_CLIENT_SECRET', 'test-secret')
  Deno.env.set('GOOGLE_OAUTH2_REDIRECT_URI', 'https://example.com/cb')

  await import('modules/core.ts')

  assert(ProgramModule.providers.get('auth'))
  assert(ProgramModule.connectors.get(googleConnectorRef))

  Deno.env.delete('GOOGLE_OAUTH2_CLIENT_ID')
  Deno.env.delete('GOOGLE_OAUTH2_CLIENT_SECRET')
  Deno.env.delete('GOOGLE_OAUTH2_REDIRECT_URI')
})
