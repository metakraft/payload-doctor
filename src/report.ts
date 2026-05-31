import type { Finding, Severity } from './types'
import type { ScoreResult } from './score'
import { VERSION } from './version'
import { fixFor } from './fix'

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

const SEV_RANK: Record<Severity, number> = { error: 0, warning: 1, info: 2 }

export interface RuleSummaryRow {
  ruleId: string
  severity: Severity
  count: number
  files: number
  errors: number
  warnings: number
  infos: number
}

/** Aggregate findings per rule, sorted by severity then count. Shared by text + JSON. */
export function rollupData(findings: Finding[]): RuleSummaryRow[] {
  type Agg = { count: number; files: Set<string>; sev: Severity; e: number; w: number; i: number }
  const byRule = new Map<string, Agg>()
  for (const f of findings) {
    const a = byRule.get(f.ruleId) ?? { count: 0, files: new Set<string>(), sev: f.severity, e: 0, w: 0, i: 0 }
    a.count++
    a.files.add(f.file)
    if (f.severity === 'error') a.e++
    else if (f.severity === 'warning') a.w++
    else a.i++
    if (SEV_RANK[f.severity] < SEV_RANK[a.sev]) a.sev = f.severity
    byRule.set(f.ruleId, a)
  }
  return [...byRule.entries()]
    .map(([ruleId, a]) => ({
      ruleId,
      severity: a.sev,
      count: a.count,
      files: a.files.size,
      errors: a.e,
      warnings: a.w,
      infos: a.i,
    }))
    .sort((x, y) => SEV_RANK[x.severity] - SEV_RANK[y.severity] || y.count - x.count)
}

/** Compact per-rule summary lines with e/w/i breakdown. */
function ruleRollup(findings: Finding[]): string[] {
  if (findings.length === 0) return []
  const lines = [c(COLOR.bold, 'Summary by rule:')]
  for (const r of rollupData(findings)) {
    const mark = c(sevColor(r.severity), SEV_MARK[r.severity])
    const count = String(r.count).padStart(3)
    const breakdown = c(COLOR.dim, `(${r.errors}e/${r.warnings}w/${r.infos}i)`)
    lines.push(`  ${mark} ${count}  ${r.ruleId}  ${c(COLOR.dim, `in ${r.files} file(s)`)}  ${breakdown}`)
  }
  return lines
}

export function renderText(
  findings: Finding[],
  score: ScoreResult,
  opts: { verbose: boolean; suppressed?: number; summaryOnly?: boolean },
): string {
  const lines: string[] = []

  // Summary by rule first, so the overview is visible without scrolling.
  for (const l of ruleRollup(findings)) lines.push(l)
  if (findings.length > 0) lines.push('')

  if (!opts.summaryOnly) {
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
  } // end !summaryOnly

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
  if (opts.suppressed && opts.suppressed > 0) {
    lines.push(c(COLOR.dim, `${opts.suppressed} finding(s) suppressed by inline comments.`))
  }
  return lines.join('\n')
}

/** A "Suggested fixes" section: one snippet per distinct rule present. */
export function renderFixes(findings: Finding[]): string {
  const order: string[] = []
  for (const f of findings) if (!order.includes(f.ruleId)) order.push(f.ruleId)
  const lines: string[] = [c(COLOR.bold, 'Suggested fixes (starting points — files are never modified):')]
  let any = false
  for (const r of order) {
    const group = findings.filter((f) => f.ruleId === r)
    // Prefer a context-specific fix supplied by the check; else the generic template.
    const fx = group.find((f) => f.fix)?.fix ?? fixFor(r)
    if (!fx) continue
    any = true
    const first = group[0]
    let where: string
    if (group.length === 1) {
      where = `${first.file}:${first.line}`
    } else {
      const byFile = new Map<string, number>()
      for (const g of group) byFile.set(g.file, (byFile.get(g.file) ?? 0) + 1)
      const top = [...byFile.entries()].sort((a, b) => b[1] - a[1])
      const shown = top.slice(0, 4).map(([f, n]) => `${f} (${n})`)
      const more = top.length > 4 ? `, +${top.length - 4} more` : ''
      where = `${group.length}× in ${top.length} file${top.length === 1 ? '' : 's'} — ${shown.join(', ')}${more}`
    }
    lines.push('')
    lines.push(c(COLOR.dim, `# ${r}  (${where})`))
    for (const l of fx.split('\n')) lines.push('  ' + l)
  }
  if (!any) return ''
  return lines.join('\n')
}

export function renderJson(
  findings: Finding[],
  score: ScoreResult,
  meta: { root: string; filesScanned: number; suppressed?: number },
): string {
  return JSON.stringify(
    {
      tool: 'payload-doctor',
      toolVersion: VERSION,
      schema: 2,
      root: meta.root,
      filesScanned: meta.filesScanned,
      suppressed: meta.suppressed ?? 0,
      score: score.score,
      band: score.band,
      counts: score.counts,
      summary: rollupData(findings),
      findings,
    },
    null,
    2,
  )
}
