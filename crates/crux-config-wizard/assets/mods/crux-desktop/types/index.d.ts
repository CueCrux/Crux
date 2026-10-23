export type CruxHealth = {
  server: string | null
  facts: number | null
  mode: string | null
  checkedAt: number
  error?: string
}

export type CruxCall = { id: string; tool: string; at: number; isOk: boolean }

export type CruxSave = { at: number; reason: string; isOk: boolean; error?: string }

declare module 'claude-code' {
  interface PluginState {
    'crux-desktop': {
      health: CruxHealth | null
      calls: CruxCall[]
      lastSave: CruxSave | null
      hasContinuity: boolean
    }
  }
}
