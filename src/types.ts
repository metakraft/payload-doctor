import type { SourceFile } from 'ts-morph'

export type Severity = 'error' | 'warning' | 'info'
export type Category = 'security' | 'privacy' | 'correctness' | 'config' | 'rendering'

export interface Finding {
  ruleId: string
  category: Category
  severity: Severity
  message: string
  file: string
  line: number
  column: number
  hint?: string
  /** Optional context-specific fix snippet (overrides the generic per-rule one). */
  fix?: string
}

export interface CheckContext {
  /** Absolute project root the scan was started from. */
  root: string
  /** Make an absolute file path relative to the project root for display. */
  rel(absPath: string): string
}

export interface Check {
  id: string
  category: Category
  /** Short human description shown in --list. */
  describe: string
  run(file: SourceFile, ctx: CheckContext): Finding[]
}
