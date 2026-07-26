/**
 *  ______               _
 * |___  /              (_)
 *    / /   __ _  _ __   _ __  __
 *   / /   / _` || '_ \ | |\ \/ /
 * ./ /___| (_| || | | || | >  <
 * \_____/ \__,_||_| |_||_|/_/\_\
 */

import { Provider } from '@zanix/server'

import { ZanixAuthProvider } from './auth.ts'

/** Provider DSL definition */
const registerProvider = () => {
  @Provider({ type: 'auth', lifetime: 'SCOPED' })
  class _ZanixAuthProvider extends ZanixAuthProvider {}
}

/**
 * Core Auth provider loader for Zanix.
 *
 * This module automatically registers the default auth provider (`_ZanixAuthProvider`) under the
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
const zanixAuthProvider: void = registerProvider()

export default zanixAuthProvider
