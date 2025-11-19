import type { CoreAuthConnectors } from 'typings/connectors.ts'

import { GoogleOAuth2Connector } from './google/mod.ts'

// deno-lint-ignore no-explicit-any
export const authConnectors: Record<CoreAuthConnectors, any> = {
  'google-oauth2': GoogleOAuth2Connector,
}
