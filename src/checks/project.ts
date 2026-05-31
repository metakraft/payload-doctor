import { Node, SyntaxKind, type SourceFile } from 'ts-morph'
import * as fs from 'fs'
import * as path from 'path'
import type { Finding, CheckContext } from '../types'
import { getConfigKind, propInit, makeFinding } from '../util'

/** Line number (1-based) of the first occurrence of `needle` in `text`, else 1. */
function lineOf(text: string, needle: string): number {
  const idx = text.indexOf(needle)
  if (idx < 0) return 1
  return text.slice(0, idx).split('\n').length
}

/**
 * All `payload` and `@payloadcms/*` packages must be on the exact same version;
 * a mismatch is one of the most common causes of mysterious build/runtime breaks.
 * Reads the root package.json (skips ranges/tags/workspace specs we can't compare).
 */
function dependencyVersionMismatch(ctx: CheckContext): Finding[] {
  const pkgPath = path.join(ctx.root, 'package.json')
  let text: string
  try {
    text = fs.readFileSync(pkgPath, 'utf8')
  } catch {
    return []
  }
  let pkg: any
  try {
    pkg = JSON.parse(text)
  } catch {
    return []
  }
  // Defensive schema guard: a malformed package.json (non-object root, or
  // dependencies that aren't objects) must not throw — just skip the check.
  if (typeof pkg !== 'object' || pkg === null || Array.isArray(pkg)) return []
  const asObj = (v: unknown): Record<string, unknown> =>
    v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {}
  const deps = { ...asObj(pkg.dependencies), ...asObj(pkg.devDependencies) }
  const byVersion = new Map<string, string[]>()
  for (const [name, spec] of Object.entries(deps)) {
    if (name !== 'payload' && !name.startsWith('@payloadcms/')) continue
    if (typeof spec !== 'string') continue
    const v = spec.replace(/^[\^~>=<\s]+/, '')
    if (!/^\d+\.\d+\.\d+/.test(v)) continue // skip ranges/tags/workspace:* etc.
    const arr = byVersion.get(v) ?? []
    arr.push(name)
    byVersion.set(v, arr)
  }
  if (byVersion.size < 2) return []
  const summary = [...byVersion.entries()].map(([v, names]) => `${names.length}×${v}`).join(', ')
  const line = lineOf(text, '@payloadcms/') || lineOf(text, '"payload"')
  return [
    {
      ruleId: 'dependency-version-mismatch',
      category: 'config',
      severity: 'error',
      message: `Mismatched payload / @payloadcms/* versions in package.json (${summary}) — keep all Payload packages on one version`,
      file: ctx.rel(pkgPath),
      line,
      column: 1,
      hint: 'Pin every payload and @payloadcms/* dependency to the exact same version.',
    },
  ]
}

/**
 * Cross-file: relationship/upload fields that form a cycle (A → B → A or a
 * self-reference). Cycles are often legitimate (category trees, related posts),
 * so this is `info` — a reminder that maxDepth must bound population to avoid
 * runaway queries.
 */
function circularRelationships(files: SourceFile[], ctx: CheckContext): Finding[] {
  const adj = new Map<string, Set<string>>()
  const nodeBySlug = new Map<string, Node>()

  for (const file of files) {
    for (const obj of file.getDescendantsOfKind(SyntaxKind.ObjectLiteralExpression)) {
      if (getConfigKind(obj) !== 'collection') continue
      const slugInit = propInit(obj, 'slug')
      if (!slugInit || !Node.isStringLiteral(slugInit)) continue
      const slug = slugInit.getLiteralValue()
      nodeBySlug.set(slug, slugInit)
      const targets = adj.get(slug) ?? new Set<string>()
      for (const field of obj.getDescendantsOfKind(SyntaxKind.ObjectLiteralExpression)) {
        const t = propInit(field, 'type')
        if (!t || !Node.isStringLiteral(t)) continue
        const tv = t.getLiteralValue()
        if (tv !== 'relationship' && tv !== 'upload') continue
        const rel = propInit(field, 'relationTo')
        if (!rel) continue
        if (Node.isStringLiteral(rel)) targets.add(rel.getLiteralValue())
        else if (Node.isArrayLiteralExpression(rel)) {
          for (const el of rel.getElements()) if (Node.isStringLiteral(el)) targets.add(el.getLiteralValue())
        }
      }
      adj.set(slug, targets)
    }
  }

  const known = new Set(adj.keys())

  // Tarjan's SCC: O(V+E). A collection is in a cycle if its strongly-connected
  // component has >1 member, or it references itself (self-loop).
  let index = 0
  const idx = new Map<string, number>()
  const low = new Map<string, number>()
  const onStack = new Set<string>()
  const stack: string[] = []
  const sccOf = new Map<string, string[]>()
  const strongconnect = (v: string): void => {
    idx.set(v, index)
    low.set(v, index)
    index++
    stack.push(v)
    onStack.add(v)
    for (const w of adj.get(v) ?? []) {
      if (!known.has(w)) continue
      if (!idx.has(w)) {
        strongconnect(w)
        low.set(v, Math.min(low.get(v)!, low.get(w)!))
      } else if (onStack.has(w)) {
        low.set(v, Math.min(low.get(v)!, idx.get(w)!))
      }
    }
    if (low.get(v) === idx.get(v)) {
      const comp: string[] = []
      let w: string
      do {
        w = stack.pop()!
        onStack.delete(w)
        comp.push(w)
      } while (w !== v)
      for (const m of comp) sccOf.set(m, comp)
    }
  }
  for (const v of known) if (!idx.has(v)) strongconnect(v)

  const findings: Finding[] = []
  for (const slug of known) {
    const comp = sccOf.get(slug) ?? [slug]
    // NOTE: the selfLoop check is NOT redundant — Tarjan puts a self-referencing
    // node in a size-1 SCC, indistinguishable from an acyclic node, so a plain
    // SCC-size>1 test would miss real self-loops (e.g. articles -> articles).
    const selfLoop = adj.get(slug)?.has(slug) ?? false
    if (comp.length < 2 && !selfLoop) continue
    const node = nodeBySlug.get(slug)
    if (!node) continue
    const pathStr = comp.length >= 2 ? `${comp.join(' → ')} → ${comp[0]}` : `${slug} → ${slug}`
    findings.push(
      makeFinding(node, ctx, 'circular-relationship', 'correctness', 'info',
        `Circular relationship: ${pathStr} — ensure maxDepth bounds population so queries don't recurse endlessly`,
        'Cycles are fine (e.g. category trees); just keep query depth small and avoid populating the loop fully.'),
    )
  }
  return findings
}

/**
 * Cross-file check: the same slug defined on more than one collection/global.
 * Slugs must be unique — Payload derives DB collections and admin/API routes
 * from them, so a duplicate silently shadows one definition.
 */
export function projectChecks(files: SourceFile[], ctx: CheckContext): Finding[] {
  const bySlug = new Map<string, Node[]>()

  for (const file of files) {
    for (const obj of file.getDescendantsOfKind(SyntaxKind.ObjectLiteralExpression)) {
      const kind = getConfigKind(obj)
      if (kind !== 'collection' && kind !== 'global') continue
      const slugInit = propInit(obj, 'slug')
      if (!slugInit || !Node.isStringLiteral(slugInit)) continue
      const val = slugInit.getLiteralValue()
      const arr = bySlug.get(val) ?? []
      arr.push(slugInit)
      bySlug.set(val, arr)
    }
  }

  const findings: Finding[] = []
  for (const [val, nodes] of bySlug) {
    if (nodes.length < 2) continue
    for (const n of nodes) {
      findings.push(
        makeFinding(n, ctx, 'duplicate-slug', 'config', 'error',
          `Duplicate slug "${val}" — defined ${nodes.length} times across collections/globals`,
          'Slugs must be unique; Payload builds DB collections and routes from them.'),
      )
    }
  }

  findings.push(...dependencyVersionMismatch(ctx))
  findings.push(...circularRelationships(files, ctx))
  return findings
}
