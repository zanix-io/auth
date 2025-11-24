/**
 *  ______               _
 * |___  /              (_)
 *    / /   __ _  _ __   _ __  __
 *   / /   / _` || '_ \ | |\ \/ /
 * ./ /___| (_| || | | || | >  <
 * \_____/ \__,_||_| |_||_|/_/\_\
 */

import { ZanixAuthProvider } from './auth.ts'
import { Provider } from '@zanix/server'

/**
 * DSL function that defines and registers an authentication provider `ZanixAuthProvider` using the Zanix `@Provider` decorator.
 *
 * The returned class is configured with lazy initialization and can be used in Interactor decorators,
 * for example: `@Interactor({ Provider: createAuthProvider() })`, or registered directly in your `base.defs.ts` file.
 *
 * **Usage recommendation:** call `createAuthProvider()` only once. After registration, you can use
 * the `ZanixAuthProvider` class directly throughout the application.
 *
 * @returns A decorated authentication provider class.
 */
export const createAuthProvider = (): typeof ZanixAuthProvider => {
  Provider({ startMode: 'lazy' })(ZanixAuthProvider)
  return ZanixAuthProvider
}
