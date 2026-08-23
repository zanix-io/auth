// Tests `resolveCaptchaProvider()`/`resolveCaptchaAdapter()` (`modules/connectors/captcha/defs.ts`) —
// grep-discoverable by behavior, not by the (uninformative) `defs.ts` module name, matching the
// naming-and-structure-conventions exemption for a test named after the specific behavior it
// exercises rather than its module's basename.
import { assertEquals, assertInstanceOf, assertThrows } from '@std/assert'
import { InternalError } from '@zanix/errors'
import { resolveCaptchaAdapter, resolveCaptchaProvider } from 'modules/connectors/captcha/defs.ts'
import { RecaptchaAdapter } from 'modules/connectors/captcha/recaptcha.ts'
import { HCaptchaAdapter } from 'modules/connectors/captcha/hcaptcha.ts'
import { TurnstileAdapter } from 'modules/connectors/captcha/turnstile.ts'

console.error = () => {}

const ENV_VARS = [
  'CAPTCHA_PROVIDER',
  'RECAPTCHA_SECRET_KEY',
  'HCAPTCHA_SECRET_KEY',
  'TURNSTILE_SECRET_KEY',
]

function withEnv(vars: Record<string, string>, fn: () => void) {
  for (const key of ENV_VARS) Deno.env.delete(key)
  for (const [key, value] of Object.entries(vars)) Deno.env.set(key, value)
  try {
    fn()
  } finally {
    for (const key of ENV_VARS) Deno.env.delete(key)
  }
}

Deno.test('resolveCaptchaProvider: undefined when nothing is configured', () => {
  withEnv({}, () => {
    assertEquals(resolveCaptchaProvider(), undefined)
  })
})

Deno.test('resolveCaptchaProvider: throws on an unsupported CAPTCHA_PROVIDER value', () => {
  withEnv({ CAPTCHA_PROVIDER: 'not-a-provider' }, () => {
    assertThrows(() => resolveCaptchaProvider(), InternalError)
  })
})

Deno.test('resolveCaptchaProvider: auto-detects the single configured provider', () => {
  withEnv({ HCAPTCHA_SECRET_KEY: 'secret' }, () => {
    assertEquals(resolveCaptchaProvider(), 'hcaptcha')
  })
})

Deno.test('resolveCaptchaProvider: throws when > 1 provider is set with no selector', () => {
  withEnv({ RECAPTCHA_SECRET_KEY: 'a', TURNSTILE_SECRET_KEY: 'b' }, () => {
    assertThrows(() => resolveCaptchaProvider(), InternalError)
  })
})

Deno.test('resolveCaptchaProvider: CAPTCHA_PROVIDER disambiguates when > 1 is set', () => {
  withEnv(
    { RECAPTCHA_SECRET_KEY: 'a', TURNSTILE_SECRET_KEY: 'b', CAPTCHA_PROVIDER: 'turnstile' },
    () => {
      assertEquals(resolveCaptchaProvider(), 'turnstile')
    },
  )
})

Deno.test('resolveCaptchaAdapter: undefined when nothing is configured', () => {
  withEnv({}, () => {
    assertEquals(resolveCaptchaAdapter({}), undefined)
  })
})

Deno.test('resolveCaptchaAdapter: options.adapter wins outright, no env resolution', () => {
  withEnv({}, () => {
    const adapter = { verify: () => Promise.resolve({ success: true }) }
    assertEquals(resolveCaptchaAdapter({ adapter }), adapter)
  })
})

Deno.test('resolveCaptchaAdapter: builds from provider + secretKey options, no env read', () => {
  withEnv({}, () => {
    const adapter = resolveCaptchaAdapter({ provider: 'recaptcha', secretKey: 'test-key' })
    assertInstanceOf(adapter, RecaptchaAdapter)
  })
})

Deno.test('resolveCaptchaAdapter: builds from an env provider + its own secret env var', () => {
  withEnv({ RECAPTCHA_SECRET_KEY: 'from-env' }, () => {
    const adapter = resolveCaptchaAdapter({})
    assertInstanceOf(adapter, RecaptchaAdapter)
  })
})

Deno.test('resolveCaptchaAdapter: throws when the resolved provider has no secret key', () => {
  withEnv({}, () => {
    assertThrows(() => resolveCaptchaAdapter({ provider: 'recaptcha' }), InternalError)
  })
})

Deno.test('resolveCaptchaAdapter: builds an HCaptchaAdapter for the "hcaptcha" provider', () => {
  withEnv({}, () => {
    const adapter = resolveCaptchaAdapter({ provider: 'hcaptcha', secretKey: 'test-key' })
    assertInstanceOf(adapter, HCaptchaAdapter)
  })
})

Deno.test('resolveCaptchaAdapter: builds a TurnstileAdapter for the "turnstile" provider', () => {
  withEnv({}, () => {
    const adapter = resolveCaptchaAdapter({ provider: 'turnstile', secretKey: 'test-key' })
    assertInstanceOf(adapter, TurnstileAdapter)
  })
})
