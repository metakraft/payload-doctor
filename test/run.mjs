#!/usr/bin/env node
// Minimal assertion runner for payload-doctor self-tests.
// Runs the built CLI against each fixture and checks the outcome.
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

const here = path.dirname(fileURLToPath(import.meta.url))
const cli = path.join(here, '..', 'dist', 'cli.js')
const fixtures = path.join(here, 'fixtures')

function scan(dir) {
  const out = execFileSync('node', [cli, path.join(fixtures, dir), '--json', '--no-exit-code'], {
    encoding: 'utf8',
  })
  return JSON.parse(out)
}

const cases = [
  {
    name: 'vulnerable project is flagged',
    dir: 'vulnerable',
    check: (r) => r.counts.error > 0 && r.score < 50,
  },
  {
    name: 'clean project is silent',
    dir: 'clean',
    check: (r) => r.findings.length === 0 && r.score === 100,
  },
  {
    name: 'tricky legit patterns produce no false positives',
    dir: 'tricky',
    check: (r) => r.findings.length === 0,
  },
  {
    name: 'explicit system write (overrideAccess:true, no user) is info, not error',
    dir: 'system',
    check: (r) => r.counts.error === 0 && r.counts.info >= 1,
  },
]

let failed = 0
for (const c of cases) {
  const r = scan(c.dir)
  const ok = c.check(r)
  if (!ok) failed++
  const tag = ok ? 'PASS' : 'FAIL'
  console.log(
    `${tag}  ${c.name}  (score ${r.score}, ${r.counts.error}e/${r.counts.warning}w/${r.counts.info}i)`,
  )
}

if (failed > 0) {
  console.error(`\n${failed} test(s) failed.`)
  process.exit(1)
}
console.log('\nAll tests passed.')
