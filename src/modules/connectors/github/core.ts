/**
 *  ______               _
 * |___  /              (_)
 *    / /   __ _  _ __   _ __  __
 *   / /   / _` || '_ \ | |\ \/ /
 * ./ /___| (_| || | | || | >  <
 * \_____/ \__,_||_| |_||_|/_/\_\
 */

import { GITHUB_OAUTH2_CLIENT_ID_ENV, GitHubOAuth2Connector } from './mod.ts'
import { Connector } from '@zanix/server'

/**
 * Connector DSL definition — exported (not just auto-run below) so a caller can re-register after
 * clearing the `'type:connector'` registry (`closeAllConnections()`/
 * `ProgramModule.targets.resetContainer(['type:connector'])`, both in `@zanix/server`), without
 * needing a fresh module evaluation of this file. Re-reads `Deno.env` each call, so a config-reload
 * in a long-running process — or a test simulating a different env state between cases — gets a
 * genuinely current registration, not a stale decision baked in at first import. Same pattern
 * `registerGoogleOAuth2Connector` (`google/core.ts`) and `@zanix/datamaster`'s own `storage/core.ts`
 * (`registerSeaweedFSConnector`) already use.
 */
export const registerGitHubOAuth2Connector = (): void => {
  if (!Deno.env.has(GITHUB_OAUTH2_CLIENT_ID_ENV)) return

  Connector({ startMode: 'lazy', autoInitialize: false })(
    GitHubOAuth2Connector,
  )
}

/**
 * Core GitHub Oauth2 connector loader for Zanix.
 *
 * This module automatically registers the default `GitHubOAuth2Connector`
 * if the environment variable `GITHUB_OAUTH2_CLIENT_ID` is set.
 * It uses the `@Connector()` decorator to register the connector with the Zanix framework.
 *
 * This behavior ensures that, when a GitHub OAuth configuration is provided,
 * a default GitHub OAuth2 connector is available without requiring manual setup.
 *
 * @requires Deno.env
 * @requires GitHubOAuth2Connector
 * @decorator Connector
 *
 * @module
 */
const zanixGitHubOAuth2ConnectorCore: void = registerGitHubOAuth2Connector()

export default zanixGitHubOAuth2ConnectorCore
