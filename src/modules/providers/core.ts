/**
 *  ______               _
 * |___  /              (_)
 *    / /   __ _  _ __   _ __  __
 *   / /   / _` || '_ \ | |\ \/ /
 * ./ /___| (_| || | | || | >  <
 * \_____/ \__,_||_| |_||_|/_/\_\
 */

import { Provider, registerCoreProviderSlot } from '@zanix/server'

import { ZanixAuthProvider, ZanixCoreAuthProvider } from './auth.ts'

// `@zanix/auth` owns the `'auth'` core-provider slot: it registers it here, in its own `/core`
// entrypoint, rather than relying on `@zanix/server` to declare it upfront.
registerCoreProviderSlot('auth', ZanixCoreAuthProvider, {
  sourcePackage: '@zanix/auth/core',
})

/**
 * Provider DSL definition — applies the decorator directly to `ZanixAuthProvider` itself (calling
 * it as a plain function, not `@Provider(...)` syntax, since there's no wrapper class declaration
 * to attach `@` to) rather than wrapping it in a throwaway anonymous subclass. This matters beyond
 * style: `this.providers.get(ZanixAuthProvider)` only resolves the exact class that was decorated
 * — an anonymous `class _X extends ZanixAuthProvider {}` wrapper would still work via
 * `get('auth')`, but `get(ZanixAuthProvider)` (the class every consumer actually imports) would
 * silently fail to find it, since `getTargetKey` assigns each class reference — the wrapper and
 * `ZanixAuthProvider` — its own distinct identity.
 */
// Exported (not just auto-run below) — kept consistent with every other `core.ts` loader's own
// callable, re-invokable registration function across the Zanix ecosystem (see
// `@zanix/datamaster`'s `storage/core.ts`'s own `registerSeaweedFSConnector` doc for the full
// reasoning that pattern exists for).
export const registerAuthProvider = (): void => {
  Provider({ slot: 'auth', lifetime: 'SCOPED' })(ZanixAuthProvider)
}

/**
 * Core Auth provider loader for Zanix.
 *
 * This module automatically registers the default auth provider (`ZanixAuthProvider`) under the
 * `'auth'` core-provider key — the same zero-config pattern AsyncMQ already uses for its `'worker'`
 * provider — so it's available via `this.providers.get('auth')` without any app-side setup.
 *
 * `SCOPED` lifetime (one instance per request) is required here since auth handles per-request
 * session/token validation data.
 *
 * @requires ZanixAuthProvider
 * @decorator Provider
 *
 * @module
 */
const zanixAuthProvider: void = registerAuthProvider()

export default zanixAuthProvider
