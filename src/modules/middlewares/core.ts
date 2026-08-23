/**
 *  ______               _
 * |___  /              (_)
 *    / /   __ _  _ __   _ __  __
 *   / /   / _` || '_ \ | |\ \/ /
 * ./ /___| (_| || | | || | >  <
 * \_____/ \__,_||_| |_||_|/_/\_\
 */

import { sessionHeadersInterceptor } from './headers.interceptor.ts'
import { registerGlobalInterceptor } from '@zanix/server'

// Exported (not just auto-run below) — kept consistent with every other `core.ts` loader's own
// callable, re-invokable registration function across the Zanix ecosystem (see
// `@zanix/datamaster`'s `storage/core.ts`'s own `registerSeaweedFSConnector` doc for the full
// reasoning that pattern exists for).
/** Global Middleware DSL definitions */
export const registerMiddlewares = (): void => {
  registerGlobalInterceptor(sessionHeadersInterceptor())
}

/**
 * Auth Core Middlewares loader for Zanix.
 *
 * This module automatically registers the default authentication middlewares
 * It uses the `registerGlobalInterceptor` function to register the middlewares globally with the Zanix framework.
 *
 * This behavior ensures the default authentication middlewares are available without requiring manual setup.
 *
 * @requires registerGlobalInterceptor
 * @requires sessionHeadersInterceptor
 *
 * @module
 */
const authCoreMiddlewares: void = registerMiddlewares()

export default authCoreMiddlewares
