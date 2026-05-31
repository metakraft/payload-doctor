#!/usr/bin/env node
import * as path from 'path'
import * as fs from 'fs'
import { Project } from 'ts-morph'
import type { Finding, CheckContext } from './types'
import { ALL_CHECKS } from './checks'
import { projectChecks } from './checks/project'
import { scoreFindings } from './score'
import { renderText, renderJson, renderFixes, setColor } from './report'
import { applySuppressions } from './suppress'
import { VERSION } from './version'

interface Options {
  target: string
  verbose: boolean
  json: boolean
  list: boolean
  color: boolean
  exitCode: boolean
  minScore: number | null
  help: boolean
  version: boolean
  summary: boolean
  fix: boolean
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
    version: false,
    summary: false,
    fix: false,
  }
  const positional: string[] = []
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    switch (a) {
      case '--version':
      case '-V':
        o.version = true
        break
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
      case '--summary':
        o.summary = true
        break
      case '--fix':
        o.fix = true
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
      case '--min-score': {
        const raw = argv[++i]
        const n = Number(raw)
        if (raw === undefined || raw === '' || !Number.isFinite(n) || n < 0 || n > 100) {
          console.error(
            `Invalid --min-score value: ${raw ?? '(missing)'}. Expected a number between 0 and 100.`,
          )
          process.exit(2)
        }
        o.minScore = n
        break
      }
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

const HELP = `payload-doctor v${VERSION} — static security & correctness auditor for Payload CMS

Usage:
  npx -y payload-doctor@latest [path] [options]

Options:
  -v, --verbose     show fix hints under each finding
      --json        machine-readable JSON output
      --list        list all checks and exit
      --summary     show only the per-rule rollup, not every finding
      --fix         print a suggested fix per rule (does not modify files)
      --min-score N exit non-zero if the score is below N
      --no-exit-code always exit 0 (useful in pre-commit while adopting)
      --no-color    disable ANSI colors
  -V, --version     print version and exit
  -h, --help        show this help

Suppress intentional cases with a comment on or above the line:
  // payload-doctor-disable-next-line local-api-override-access
  // payload-doctor-disable side-effect-in-get   (whole file; omit rule for all)

Workflow: run it, fix errors first, re-run to watch the score climb.
Score = max(0, 100 − 10·errors − 3·warnings); info findings don't affect it.
Score bands: 75-100 great · 50-74 needs work · 0-49 critical.
(10+ errors floor the score at 0 by design — watch the error/warning counts drop to gauge progress.)`

function listChecks(): void {
  for (const ch of ALL_CHECKS) {
    console.log(`${ch.category.padEnd(12)} payload-doctor/${ch.id}\n             ${ch.describe}`)
  }
}

function main(): void {
  const opts = parseArgs(process.argv.slice(2))
  setColor(opts.color)

  if (opts.version) {
    console.log(`payload-doctor v${VERSION}`)
    process.exit(0)
  }
  if (opts.help) {
    console.log(HELP)
    process.exit(0)
  }
  if (opts.list) {
    listChecks()
    process.exit(0)
  }

  const root = path.resolve(opts.target)

  if (!fs.existsSync(root)) {
    console.error(
      `Path not found: ${opts.target}\n` +
        'Point payload-doctor at an existing Payload project. From the project root, run it with ".".',
    )
    process.exit(2)
  }

  let project: Project
  try {
    project = new Project({
      skipAddingFilesFromTsConfig: true,
      compilerOptions: { allowJs: true, checkJs: false },
    })

    if (fs.statSync(root).isFile()) {
      project.addSourceFileAtPath(root)
    } else {
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
    }
  } catch (err) {
    console.error(
      `Failed to read the project at ${root}:\n  ${err instanceof Error ? err.message : String(err)}\n` +
        'Make sure the path is a readable Payload project directory (or a single .ts/.tsx file).',
    )
    process.exit(2)
  }

  const files = project.getSourceFiles()
  if (files.length === 0) {
    console.error(
      `No .ts/.tsx/.js/.jsx files found under ${root}.\n` +
        'Point payload-doctor at a Payload project root (where your collections/ and payload config live).',
    )
    process.exit(2)
  }

  const ctx: CheckContext = {
    root,
    rel: (abs) => path.relative(root, abs) || path.basename(abs),
  }

  const rawFindings: Finding[] = []
  for (const file of files) {
    for (const check of ALL_CHECKS) {
      try {
        rawFindings.push(...check.run(file, ctx))
      } catch {
        // a single check throwing must not abort the whole scan
      }
    }
  }
  // cross-file checks (e.g. duplicate slugs across collections)
  try {
    rawFindings.push(...projectChecks(files, ctx))
  } catch {
    // never let an aggregate check abort the scan
  }

  // inline suppression (// payload-doctor-disable...)
  const fileTexts = new Map<string, string>()
  for (const file of files) fileTexts.set(ctx.rel(file.getFilePath()), file.getFullText())
  const { kept: findings, suppressed } = applySuppressions(rawFindings, fileTexts)

  const score = scoreFindings(findings)

  if (opts.json) {
    console.log(renderJson(findings, score, { root, filesScanned: files.length, suppressed }))
  } else {
    console.log(`payload-doctor v${VERSION}\n`)
    if (files.length === 0) {
      console.log('No source files found. Point payload-doctor at your Payload project root.')
    } else if (findings.length === 0) {
      const tail = suppressed > 0 ? ` (${suppressed} suppressed)` : ''
      console.log(`Scanned ${files.length} files. No issues found. Score: 100/100${tail}`)
    } else {
      console.log(renderText(findings, score, { verbose: opts.verbose, suppressed, summaryOnly: opts.summary }))
    }
    if (opts.fix && findings.length > 0) {
      const fixes = renderFixes(findings)
      if (fixes) console.log('\n' + fixes)
    }
  }

  if (!opts.exitCode) process.exit(0)
  if (opts.minScore !== null && score.score < opts.minScore) process.exit(1)
  process.exit(score.counts.error > 0 ? 1 : 0)
}

main()
