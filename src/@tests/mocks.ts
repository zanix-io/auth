// deno-lint-ignore-file no-explicit-any
import { type HandlerContext, ProgramModule } from '@zanix/server'

export const contextMock: () => HandlerContext & {
  interactors: any
  providers: any
  connectors: any
} = () => ({
  req: {
    headers: {
      get: (_: string) => {
        return ''
      },
    },
  },
  url: undefined,
  payload: {
    params: undefined,
    search: undefined,
    body: undefined,
  },
  id: '',
  providers: ProgramModule.getProviders(),
  connectors: ProgramModule.getConnectors(),
  interactors: null as any,
  locals: {},
  cookies: {},
} as unknown as HandlerContext & {
  interactors: any
  providers: any
  connectors: any
})
