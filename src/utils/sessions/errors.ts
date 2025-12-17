import { SESSION_HEADERS } from '../constants.ts'
import { HttpError } from '@zanix/errors'

export const invalidRefreshTokenError = (method: string) => {
  const metaError = {
    source: 'zanix',
    method: method,
    suggestion:
      `Provide a valid refresh token in the request body ('token') or ensure that the authentication cookie ('${
        SESSION_HEADERS['user'].token
      }') is present.`,
  }

  return {
    metaError,
    error: new HttpError('UNAUTHORIZED', {
      code: 'INVALID_TOKEN',
      cause: 'Refresh token is undefined and cannot be used to refresh the session.',
      meta: metaError,
    }),
  }
}
