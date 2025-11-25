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

/** Global Middleware DSL definitions */
const registerMiddlewares = () => {
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
 * @requires defineMiddlewareDecorator
 *
 * @module
 */
const authCoreMiddlewares: void = registerMiddlewares()

export default authCoreMiddlewares
