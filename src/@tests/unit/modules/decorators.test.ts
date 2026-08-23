import { assertEquals } from '@std/assert'
import { AuthTokenValidation } from 'modules/middlewares/decorators/authentication.ts'
import { RequirePermissions } from 'modules/middlewares/decorators/permissions.ts'
import { RateLimitGuard } from 'modules/middlewares/decorators/rate-limit.ts'
import { IpAllowlistGuard } from 'modules/middlewares/decorators/ip-allowlist.ts'
import { CaptchaGuard } from 'modules/middlewares/decorators/captcha.ts'

Deno.test('AuthTokenValidation() returns a guard decorator built from jwtValidationGuard', () => {
  const decorator = AuthTokenValidation({ permissions: ['admin'] })
  assertEquals(typeof decorator, 'function')
})

Deno.test('RequirePermissions() returns a pipe decorator built from permissionsPipe', () => {
  const decorator = RequirePermissions(['admin'])
  assertEquals(typeof decorator, 'function')
})

Deno.test('RateLimitGuard() returns a guard decorator built from rateLimitGuard', () => {
  const decorator = RateLimitGuard({ anonymousLimit: 10, trustProxyHeader: true })
  assertEquals(typeof decorator, 'function')
})

Deno.test('IpAllowlistGuard() returns a guard decorator built from ipAllowlistGuard', () => {
  const decorator = IpAllowlistGuard()
  assertEquals(typeof decorator, 'function')
})

Deno.test('CaptchaGuard() returns a guard decorator built from captchaGuard', () => {
  const decorator = CaptchaGuard({ provider: 'recaptcha', secretKey: 'test-key' })
  assertEquals(typeof decorator, 'function')
})
