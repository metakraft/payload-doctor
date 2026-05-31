#!/usr/bin/env node
import * as path from 'path'
import { Project } from 'ts-morph'
import type { Finding, CheckContext } from './types'
import { ALL_CHECKS } from './checks'
import { scoreFindings } from './score'
import { renderText, renderJson, setColor } from './report'

interface Options {
  target: string
  verbose: boolean
  json: boolean
  list: boolean
  color: boolean
  exitCode: boolean
  minScore: number | null
  help: boolean
}

function parseArgs(argv: string[]): Options {
  const o: Options = {
    target: '.',
    verbose: false,
    json: false,
    list: false,
    color: process.stdout.isTTY ?? false,
    exitCode: true,
    minScore: null,
    help: false,
  }
  const positional: string[] = []
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    switch (a) {
      case '--verbose':
      case '-v':
        o.verbose = true
        break
      case '--json':
        o.json = true
        break
      case '--list':
        o.list = true
        break
      case '--no-color':
        o.color = false
        break
      case '--color':
        o.color = true
        break
      case '--no-exit-code':
        o.exitCode = false
        break
      case '--min-score':
        o.minScore = Number(argv[++i])
        break
      case '--help':
      case '-h':
        o.help = true
        break
      default:
        if (!a.startsWith('-')) positional.push(a)
    }
  }
  if (positional[0]) o.target = positional[0]
  return o
}

const HELP = `payload-doctor — static security & correctness auditor for Payload CMS

Usage:
  npx -y payload-doctor@latest [path] [options]

Options:
  -v, --verbose     show fix hints under each finding
      --json        machine-readable JSON output
      --list        list all checks and exit
      --min-score N exit non-zero if the score is below N
      --no-exit-code always exit 0 (useful in pre-commit while adopting)
      --no-color    disable ANSI colors
  -h, --help        show this help

Workflow: run it, fix errors first, re-run to watch the score climb.
Score bands: 75-100 great · 50-74 needs work · 0-49 critical.
`

function listChecks(): void {
  for (const ch of ALL_CHECKS) {
    console.log(`${ch.category.padEnd(12)} payload-doctor/${ch.id}\n             ${ch.describe}`)
  }
}

function main(): void {
  const opts = parseArgs(process.argv.slice(2))
  setColor(opts.color)

  if (opts.help) {
    console.log(HELP)
    process.exit(0)
  }
  if (opts.list) {
    listChecks()
    process.exit(0)
  }

  const root = path.resolve(opts.target)
  const project = new Project({
    skipAddingFilesFromTsConfig: true,
    compilerOptions: { allowJs: true, checkJs: false },
  })

  project.addSourceFilesAtPaths([
    `${root}/**/*.ts`,
    `${root}/**/*.tsx`,
    `${root}/**/*.js`,
    `${root}/**/*.jsx`,
    `!${root}/**/node_modules/**`,
    `!${root}/**/dist/**`,
    `!${root}/**/.next/**`,
    `!${root}/**/build/**`,
    `!${root}/**/*.d.ts`,
  ])

  const files = project.getSourceFiles()
  const ctx: CheckContext = {
    root,
    rel: (abs) => path.relative(root, abs) || path.basename(abs),
  }

  const findings: Finding[] = []
  for (const file of files) {
    for (const check of ALL_CHECKS) {
      try {
        findings.push(...check.run(file, ctx))
      } catch {
        // a single check throwing must not abort the whole scan
      }
    }
  }

  const score = scoreFindings(findings)

  if (opts.json) {
    console.log(renderJson(findings, score, { root, filesScanned: files.length }))
  } else {
    if (files.length === 0) {
      console.log('No source files found. Point payload-doctor at your Payload project root.')
    } else if (findings.length === 0) {
      console.log(`Scanned ${files.length} files. No issues found. Score: 100/100`)
    } else {
      console.log(renderText(findings, score, { verbose: opts.verbose }))
    }
  }

  if (!opts.exitCode) process.exit(0)
  if (opts.minScore !== null && score.score < opts.minScore) process.exit(1)
  process.exit(score.counts.error > 0 ? 1 : 0)
}

main()
