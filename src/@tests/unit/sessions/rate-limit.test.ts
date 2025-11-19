import { assert } from '@std/assert'
import { getRateLimitForSession } from 'utils/sessions/rate-limit.ts'

// Test when RATE_LIMIT_PLANS is not set
Deno.test(
  'getRateLimitForSession should return sessionRateLimit when RATE_LIMIT_PLANS is not set',
  () => {
    // Simulate a session with a rate limit (200 requests)
    const sessionRateLimit = 200

    // Call the function
    const result = getRateLimitForSession(sessionRateLimit)

    // Check that the function returns the sessionRateLimit directly when no rate limit plans are set
    assert(result === sessionRateLimit)
  },
)

// Test when RATE_LIMIT_PLANS is set
Deno.test(
  'getRateLimitForSession should return mapped rate limit when RATE_LIMIT_PLANS is set',
  () => {
    // Set the RATE_LIMIT_PLANS environment variable
    Deno.env.set('RATE_LIMIT_PLANS', '0:100;1:1000;2:3000')

    // Simulate a session with rateLimit set to 1 (should map to the second plan with 1000 requests)
    const sessionRateLimit = 1

    // Call the function
    const result = getRateLimitForSession(sessionRateLimit)

    // Check that the function correctly maps the sessionRateLimit to the second plan (1000 requests)
    assert(result === 1000)

    // Clean up the environment variable after the test
    Deno.env.delete('RATE_LIMIT_PLANS')
  },
)

// Test when RATE_LIMIT_PLANS is set but no matching index is found
Deno.test(
  'getRateLimitForSession should return default sessionRateLimit if index not found in RATE_LIMIT_PLANS',
  () => {
    // Set the RATE_LIMIT_PLANS environment variable
    Deno.env.set('RATE_LIMIT_PLANS', '0:100;1:1000;2:3000')

    // Simulate a session with rateLimit set to 99 (no plan exists for this index)
    const sessionRateLimit = 99

    // Call the function
    const result = getRateLimitForSession(sessionRateLimit)

    // Verify that the function returns the sessionRateLimit value as fallback when no matching plan is found
    assert(result === sessionRateLimit)

    // Clean up the environment variable after the test
    Deno.env.delete('RATE_LIMIT_PLANS')
  },
)

// Test when sessionRateLimit is 0 (first index in RATE_LIMIT_PLANS)
Deno.test('getRateLimitForSession should work when sessionRateLimit is 0 (index)', () => {
  // Set the RATE_LIMIT_PLANS environment variable
  Deno.env.set('RATE_LIMIT_PLANS', '0:100;1:1000;2:3000')

  // Simulate a session with rateLimit set to 0 (should map to the first plan with 100 requests)
  const sessionRateLimit = 0

  // Call the function
  const result = getRateLimitForSession(sessionRateLimit)

  // Check that the function correctly maps sessionRateLimit 0 to the first plan (100 requests)
  assert(result === 100)
  // Clean up the environment variable after the test
  Deno.env.delete('RATE_LIMIT_PLANS')
})

// Test when RATE_LIMIT_PLANS is an empty string (no rate limit plans are set)
Deno.test(
  'getRateLimitForSession should return sessionRateLimit when RATE_LIMIT_PLANS is an empty string',
  () => {
    // Simulate an empty RATE_LIMIT_PLANS (i.e., no plans are defined)
    Deno.env.set('RATE_LIMIT_PLANS', '')

    // Simulate a session with rateLimit set to 200
    const sessionRateLimit = 200

    // Call the function
    const result = getRateLimitForSession(sessionRateLimit)

    // Check that the function returns the sessionRateLimit directly when no rate limit plans are set (empty string)
    assert(result === sessionRateLimit)

    // Clean up the environment variable after the test
    Deno.env.delete('RATE_LIMIT_PLANS')
  },
)
