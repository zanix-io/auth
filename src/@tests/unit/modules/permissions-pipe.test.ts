// deno-lint-ignore-file no-explicit-any
import { assertThrows } from '@std/assert'
import { HttpError } from '@zanix/errors'
import { permissionsPipe } from 'modules/middlewares/permissions.pipe.ts'

// The pipe reads `ctx.locals.session` first, falling back to `ctx.session` — under
// `@zanix/auth`'s own guards/handlers, `@zanix/server`'s `contextSettingPipe` already promotes
// `locals.session` there (and deletes `locals.session`) before any app-registered pipe runs, so
// most fixtures below match that same shape, not `ctx.locals.session`. See the dedicated test
// further down for the `locals.session` fallback itself (defensive, for a consuming app's own
// custom pipe composed alongside this one).

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
        locals: {},
        session: { id: 's1', type: 'user', scope: ['user'] },
      } as any),
    HttpError,
  )
})

Deno.test('permissionsPipe does not throw when the session has the required scope', () => {
  const pipe = permissionsPipe(['admin'])

  pipe({
    id: 'req-3',
    locals: {},
    session: { id: 's1', type: 'user', scope: ['admin'] },
  } as any)
})

Deno.test('permissionsPipe falls back to ctx.locals.session when ctx.session is unset', () => {
  const pipe = permissionsPipe(['admin'])

  // Defensive fallback: nothing in `@zanix/auth` itself populates `locals.session` this late, but
  // a consuming app's own custom pipe composed alongside `@RequirePermissions` could.
  pipe({
    id: 'req-4',
    locals: { session: { id: 's1', type: 'user', scope: ['admin'] } },
  } as any)
})

Deno.test('permissionsPipe prefers ctx.locals.session over a stale ctx.session', () => {
  const pipe = permissionsPipe(['admin'])

  assertThrows(
    () =>
      pipe({
        id: 'req-5',
        session: { id: 'stale', type: 'user', scope: ['admin'] },
        locals: { session: { id: 'fresh', type: 'user', scope: ['user'] } },
      } as any),
    HttpError,
  )
})
