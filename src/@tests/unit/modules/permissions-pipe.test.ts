// deno-lint-ignore-file no-explicit-any
import { assertThrows } from '@std/assert'
import { HttpError } from '@zanix/errors'
import { permissionsPipe } from 'modules/middlewares/permissions.pipe.ts'

Deno.test('permissionsPipe throws UNAUTHORIZED when there is no active session', () => {
  const pipe = permissionsPipe(['admin'])

  assertThrows(
    () => pipe({ id: 'req-1', locals: {} } as any),
    HttpError,
  )
})

Deno.test('permissionsPipe throws FORBIDDEN when the session is missing the required scope', () => {
  const pipe = permissionsPipe(['admin'])

  assertThrows(
    () =>
      pipe({
        id: 'req-2',
        locals: { session: { id: 's1', type: 'user', scope: ['user'] } },
      } as any),
    HttpError,
  )
})

Deno.test('permissionsPipe does not throw when the session has the required scope', () => {
  const pipe = permissionsPipe(['admin'])

  pipe({
    id: 'req-3',
    locals: { session: { id: 's1', type: 'user', scope: ['admin'] } },
  } as any)
})
