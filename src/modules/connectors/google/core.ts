/**
 *  ______               _
 * |___  /              (_)
 *    / /   __ _  _ __   _ __  __
 *   / /   / _` || '_ \ | |\ \/ /
 * ./ /___| (_| || | | || | >  <
 * \_____/ \__,_||_| |_||_|/_/\_\
 */

import { GoogleOAuth2Connector } from './mod.ts'
import { Connector } from '@zanix/server'

/** Connector DSL definition */
const registerConnector = () => {
  if (!Deno.env.get('GOOGLE_OAUTH2_CLIENT_ID')) return

  Connector({ startMode: 'lazy', autoInitialize: false })(GoogleOAuth2Connector)
}

/**
 * Core Google Oauth2 connector loader for Zanix.
 *
 * This module automatically registers the default Google Oauth2 connector
 * (`_ZanixGOAuthCoreConnector`) if the environment variable `GOOGLE_OAUTH2_CLIENT_ID` is set.
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
const zanixGOAuth2ConnectorCore: void = registerConnector()

export default zanixGOAuth2ConnectorCore
