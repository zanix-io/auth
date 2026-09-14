// deno-lint-ignore-file no-explicit-any
import { assert, assertEquals, assertThrows } from '@std/assert'
import { InternalError } from '@zanix/errors'
import { AuthTokenValidation } from 'modules/middlewares/decorators/authentication.ts'
import { RequirePermissions } from 'modules/middlewares/decorators/permissions.ts'
import { RateLimitGuard, resolveRateLimitApp } from 'modules/middlewares/decorators/rate-limit.ts'
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

// `rateLimitGuard(options)` is now constructed lazily, once decoration `context` (and therefore
// the decorated method's name) is available — instead of eagerly inside `RateLimitGuard`'s own
// factory call, the way it used to be. These two tests pin down that the "throws at construction,
// never on the first request" contract (`assertTrustProxyHeaderDecided`) still holds: the throw
// only moved from "factory call" to "decorator application", both of which happen synchronously
// at class-definition time — never deferred all the way to a real request.

Deno.test(
  'RateLimitGuard() no longer throws at factory-call time when trustProxyHeader is undecided — construction is deferred to decoration time',
  () => {
    // anonymousLimit defaults to 100 (enabled) and trustProxyHeader is left unset: this would have
    // thrown immediately before, since `rateLimitGuard(options)` used to be called right here.
    const decorator = RateLimitGuard({})
    assertEquals(typeof decorator, 'function')
  },
)

Deno.test(
  'RateLimitGuard() throws at class-decoration time (not on first request) when anonymous access is enabled but trustProxyHeader is undecided',
  () => {
    const decorator = RateLimitGuard({})

    const error = assertThrows(
      () =>
        decorator(function login() {}, {
          kind: 'method',
          name: 'login',
        } as ClassMethodDecoratorContext),
      InternalError,
    )
    assertEquals((error as any).meta.method, 'rateLimitGuard')
  },
)

// --- resolveRateLimitApp: the rule `RateLimitGuard` uses to auto-derive `app` -------------------
// This is what actually fixed a real incident: ten sibling anonymous-guarded routes (`login`,
// `login/otp`, `pwd/recovery`, ...) mixing different limits all shared ONE rate-limit counter per
// client identity, because none of them passed `app` — exhausting one route's tight limit silently
// exhausted an unrelated route's separate budget too. See `RateLimitGuard`'s own doc.

Deno.test(
  "resolveRateLimitApp() defaults to the decorated method's own name when app is left unset",
  () => {
    const app = resolveRateLimitApp({}, {
      kind: 'method',
      name: 'login',
    } as ClassMethodDecoratorContext)
    assertEquals(app, 'login')
  },
)

Deno.test(
  'resolveRateLimitApp() isolates two sibling method names into two different defaults',
  () => {
    const criticApp = resolveRateLimitApp({}, {
      kind: 'method',
      name: 'criticRateLimit',
    } as ClassMethodDecoratorContext)
    const freeApp = resolveRateLimitApp({}, {
      kind: 'method',
      name: 'freeRateLimit',
    } as ClassMethodDecoratorContext)

    assertEquals(criticApp, 'criticRateLimit')
    assertEquals(freeApp, 'freeRateLimit')
    assert(criticApp !== freeApp)
  },
)

Deno.test(
  'resolveRateLimitApp() keeps an explicit app instead of overriding it with the method name',
  () => {
    const app = resolveRateLimitApp({ app: 'shared-bucket' }, {
      kind: 'method',
      name: 'login',
    } as ClassMethodDecoratorContext)
    assertEquals(app, 'shared-bucket')
  },
)

Deno.test(
  'resolveRateLimitApp() falls back to the pre-existing global (undefined) behavior with no context',
  () => {
    assertEquals(resolveRateLimitApp({}), undefined)
  },
)

Deno.test('IpAllowlistGuard() returns a guard decorator built from ipAllowlistGuard', () => {
  const decorator = IpAllowlistGuard()
  assertEquals(typeof decorator, 'function')
})

Deno.test('CaptchaGuard() returns a guard decorator built from captchaGuard', () => {
  const decorator = CaptchaGuard({ provider: 'recaptcha', secretKey: 'test-key' })
  assertEquals(typeof decorator, 'function')
})
