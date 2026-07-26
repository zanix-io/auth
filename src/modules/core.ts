/**
 *  ______               _
 * |___  /              (_)
 *    / /   __ _  _ __   _ __  __
 *   / /   / _` || '_ \ | |\ \/ /
 * ./ /___| (_| || | | || | >  <
 * \_____/ \__,_||_| |_||_|/_/\_\
 */

/**
 * @module
 *
 * Zero-config core registration for `@zanix/auth`. Importing this module (as a side effect, e.g.
 * `import '@zanix/auth/core'`) registers the default `ZanixAuthProvider` under the `'auth'`
 * core-provider key, the default session headers interceptor, and — when `GOOGLE_OAUTH2_CLIENT_ID`
 * is set — a default `GoogleOAuth2Connector`.
 */

export * from './connectors/google/core.ts'
export * from './middlewares/core.ts'
export * from './providers/core.ts'
