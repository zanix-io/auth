import { defineMiddlewareDecorator, type ZanixGenericDecorator } from '@zanix/server'
import { ipAllowlistGuard, type IpAllowlistOptions } from '../ip-allowlist.guard.ts'

/**
 * A class-level decorator that restricts access to a set of allowed IPs/CIDR ranges.
 *
 * This decorator applies an IP allowlist to a controller, typically used to add an extra layer of
 * defense on admin-only routes on top of an existing `@AuthTokenValidation`.
 *
 * @see {@link ipAllowlistGuard} for additional context on IP allowlisting.
 *
 * @param options - Configuration object for the allowlist, including:
 *                  - `allow`: Exact IPs or CIDR ranges allowed to access the resource.
 *                  - `trustProxyHeader`: Must be `true` whenever an allowlist is configured.
 *
 *                  These options are defined in the `IpAllowlistOptions` type.
 *
 * @returns A class decorator (`ZanixGenericDecorator`) that applies the IP allowlist logic to the
 *          decorated controller.
 *
 * @example
 * ```ts
 * @Controller()
 * @IpAllowlistGuard({ allow: ['10.0.0.0/8'], trustProxyHeader: true })
 * export class AdminController extends ZanixController {
 *   // ...
 * }
 * ```
 */
export function IpAllowlistGuard(
  options?: IpAllowlistOptions,
): ZanixGenericDecorator {
  return defineMiddlewareDecorator('guard', ipAllowlistGuard(options))
}
