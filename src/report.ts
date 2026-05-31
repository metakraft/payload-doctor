import type { Finding, Severity } from './types'
import type { ScoreResult } from './score'

const COLOR = {
  reset: '\x1b[0m',
  dim: '\x1b[2m',
  bold: '\x1b[1m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  green: '\x1b[32m',
}

let useColor = true
export function setColor(on: boolean) {
  useColor = on
}
function c(code: string, s: string): string {
  return useColor ? `${code}${s}${COLOR.reset}` : s
}

const SEV_MARK: Record<Severity, string> = {
  error: '✗',
  warning: '!',
  info: 'i',
}
function sevColor(sev: Severity): string {
  return sev === 'error' ? COLOR.red : sev === 'warning' ? COLOR.yellow : COLOR.blue
}

export function renderText(
  findings: Finding[],
  score: ScoreResult,
  opts: { verbose: boolean },
): string {
  const lines: string[] = []

  // group by file
  const byFile = new Map<string, Finding[]>()
  for (const f of findings) {
    const arr = byFile.get(f.file) ?? []
    arr.push(f)
    byFile.set(f.file, arr)
  }

  for (const [file, fs] of [...byFile.entries()].sort()) {
    lines.push(c(COLOR.bold, file))
    fs.sort((a, b) => a.line - b.line)
    for (const f of fs) {
      const loc = c(COLOR.dim, `${f.line}:${f.column}`)
      const mark = c(sevColor(f.severity), `${SEV_MARK[f.severity]} ${f.severity}`)
      lines.push(`  ${loc}  ${mark}  ${f.message}  ${c(COLOR.dim, f.ruleId)}`)
      if (opts.verbose && f.hint) {
        lines.push(`        ${c(COLOR.dim, '↳ ' + f.hint)}`)
      }
    }
    lines.push('')
  }

  const bandLabel =
    score.band === 'great'
      ? c(COLOR.green, 'Great')
      : score.band === 'needs-work'
        ? c(COLOR.yellow, 'Needs work')
        : c(COLOR.red, 'Critical')

  lines.push(
    c(COLOR.bold, `Score: ${score.score}/100`) +
      `  ${bandLabel}  ` +
      c(COLOR.dim, `(${score.counts.error} errors, ${score.counts.warning} warnings, ${score.counts.info} info)`),
  )
  return lines.join('\n')
}

export function renderJson(
  findings: Finding[],
  score: ScoreResult,
  meta: { root: string; filesScanned: number },
): string {
  return JSON.stringify(
    {
      tool: 'payload-doctor',
      version: 1,
      root: meta.root,
      filesScanned: meta.filesScanned,
      score: score.score,
      band: score.band,
      counts: score.counts,
      findings,
    },
    null,
    2,
  )
}
