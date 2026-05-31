import type { Finding, Severity } from './types'

const WEIGHT: Record<Severity, number> = {
  error: 10,
  warning: 3,
  info: 0,
}

export interface ScoreResult {
  score: number
  band: 'great' | 'needs-work' | 'critical'
  counts: Record<Severity, number>
}

export function scoreFindings(findings: Finding[]): ScoreResult {
  const counts: Record<Severity, number> = { error: 0, warning: 0, info: 0 }
  let penalty = 0
  for (const f of findings) {
    counts[f.severity]++
    penalty += WEIGHT[f.severity]
  }
  const score = Math.max(0, 100 - penalty)
  const band: ScoreResult['band'] =
    score >= 75 ? 'great' : score >= 50 ? 'needs-work' : 'critical'
  return { score, band, counts }
}
