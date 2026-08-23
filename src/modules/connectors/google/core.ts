/**
 *  ______               _
 * |___  /              (_)
 *    / /   __ _  _ __   _ __  __
 *   / /   / _` || '_ \ | |\ \/ /
 * ./ /___| (_| || | | || | >  <
 * \_____/ \__,_||_| |_||_|/_/\_\
 */

import { GOOGLE_OAUTH2_CLIENT_ID_ENV, GoogleOAuth2Connector } from './mod.ts'
import { Connector } from '@zanix/server'

/**
 * Connector DSL definition — exported (not just auto-run below) so a caller can re-register after
 * clearing the `'type:connector'` registry (`closeAllConnections()`/
 * `ProgramModule.targets.resetContainer(['type:connector'])`, both in `@zanix/server`), without
 * needing a fresh module evaluation of this file. Re-reads `Deno.env` each call, so a config-reload
 * in a long-running process — or a test simulating a different env state between cases — gets a
 * genuinely current registration, not a stale decision baked in at first import. Same pattern
 * `@zanix/datamaster`'s own `storage/core.ts` (`registerS3Connector`) already uses.
 */
export const registerGoogleOAuth2Connector = (): void => {
  if (!Deno.env.has(GOOGLE_OAUTH2_CLIENT_ID_ENV)) return

  Connector({ startMode: 'lazy', autoInitialize: false })(
    GoogleOAuth2Connector,
  )
}

/**
 * Core Google Oauth2 connector loader for Zanix.
 *
 * This module automatically registers the default `GoogleOAuth2Connector`
 * if the environment variable `GOOGLE_OAUTH2_CLIENT_ID` is set.
 * It uses the `@Connector()` decorator to register the connector with the Zanix framework.
 *
 * This behavior ensures that, when a Google OAuth configuration is provided,
 * a default Google OAuth2 connector is available without requiring manual setup.
 *
 * @requires Deno.env
 * @requires GoogleOAuth2Connector
 * @decorator Connector
 *
 * @module
 */
const zanixGOAuth2ConnectorCore: void = registerGoogleOAuth2Connector()

export default zanixGOAuth2ConnectorCore
