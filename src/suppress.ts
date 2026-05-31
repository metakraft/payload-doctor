import type { Finding } from './types'

/**
 * Inline suppression, ESLint-style. Supported comments:
 *   // payload-doctor-disable-next-line [rule...]   suppress the next line
 *   // payload-doctor-disable-line [rule...]         suppress this line
 *   // payload-doctor-disable [rule...]              suppress the whole file
 * With no rule listed (or the word `all`), every rule is suppressed in scope.
 * Rule names may be written with or without the `payload-doctor/` prefix.
 */

type RuleScope = 'all' | Set<string>

interface FileSuppressions {
  fileScope: RuleScope | null
  lines: Map<number, RuleScope>
}

const DIRECTIVE = /payload-doctor-(disable-next-line|disable-line|disable)\b([^\n\r]*)/

function parseRules(rest: string): RuleScope {
  const tokens = rest
    .split(/[\s,]+/)
    .map((t) => t.trim().replace(/^payload-doctor\//, ''))
    .filter((t) => t.length > 0 && t !== '--')
  if (tokens.length === 0 || tokens.includes('all')) return 'all'
  return new Set(tokens)
}

function mergeScope(existing: RuleScope | undefined, next: RuleScope): RuleScope {
  if (!existing) return next
  if (existing === 'all' || next === 'all') return 'all'
  for (const r of next) existing.add(r)
  return existing
}

function parseFile(text: string): FileSuppressions {
  const supp: FileSuppressions = { fileScope: null, lines: new Map() }
  const lines = text.split(/\r?\n/)
  lines.forEach((lineText, idx) => {
    const m = lineText.match(DIRECTIVE)
    if (!m) return
    const kind = m[1]
    const rules = parseRules(m[2] ?? '')
    const lineNo = idx + 1
    if (kind === 'disable') {
      supp.fileScope = mergeScope(supp.fileScope ?? undefined, rules)
    } else if (kind === 'disable-line') {
      supp.lines.set(lineNo, mergeScope(supp.lines.get(lineNo), rules))
    } else {
      supp.lines.set(lineNo + 1, mergeScope(supp.lines.get(lineNo + 1), rules))
    }
  })
  return supp
}

function scopeSuppresses(scope: RuleScope | null | undefined, ruleId: string): boolean {
  if (!scope) return false
  if (scope === 'all') return true
  return scope.has(ruleId)
}

export function applySuppressions(
  findings: Finding[],
  fileTexts: Map<string, string>,
): { kept: Finding[]; suppressed: number } {
  const cache = new Map<string, FileSuppressions>()
  const getSupp = (file: string): FileSuppressions | undefined => {
    if (cache.has(file)) return cache.get(file)
    const text = fileTexts.get(file)
    if (text === undefined) return undefined
    const parsed = parseFile(text)
    cache.set(file, parsed)
    return parsed
  }

  let suppressed = 0
  const kept = findings.filter((f) => {
    const supp = getSupp(f.file)
    if (!supp) return true
    if (scopeSuppresses(supp.fileScope, f.ruleId) || scopeSuppresses(supp.lines.get(f.line), f.ruleId)) {
      suppressed++
      return false
    }
    return true
  })
  return { kept, suppressed }
}
