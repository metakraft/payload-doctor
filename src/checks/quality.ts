import { Node, SyntaxKind } from 'ts-morph'
import type { Check, Finding, Severity } from '../types'
import { isLocalApiCall, READ_METHODS, makeFinding, nameSegments, propInit } from '../util'

const LOOP_KINDS = new Set<SyntaxKind>([
  SyntaxKind.ForStatement,
  SyntaxKind.ForOfStatement,
  SyntaxKind.ForInStatement,
  SyntaxKind.WhileStatement,
  SyntaxKind.DoStatement,
])
const ITER_METHODS = new Set(['map', 'forEach', 'filter', 'reduce', 'flatMap', 'some', 'every'])

/** Is this node lexically inside a loop or an array-iteration callback? */
function insideIteration(node: Node): boolean {
  let cur: Node | undefined = node.getParent()
  while (cur) {
    if (LOOP_KINDS.has(cur.getKind())) return true
    if (Node.isCallExpression(cur)) {
      const expr = cur.getExpression()
      if (Node.isPropertyAccessExpression(expr) && ITER_METHODS.has(expr.getName())) {
        // only count it if our node is in an argument (the callback), not the array
        if (cur.getArguments().some((a) => a === node || a.getDescendants().includes(node))) return true
      }
    }
    cur = cur.getParent()
  }
  return false
}

/**
 * A Local API read (`payload.find`/`findByID`/`findGlobal`) inside a loop or
 * map/forEach callback is the classic N+1: one query per iteration. Batch it
 * (a single `find` with an `in` filter) instead.
 */
const hookNPlusOne: Check = {
  id: 'hook-n-plus-one',
  category: 'correctness',
  describe: 'Local API read inside a loop / map (N+1 query)',
  run(file, ctx) {
    const findings: Finding[] = []
    for (const call of file.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      const local = isLocalApiCall(call)
      if (!local || !READ_METHODS.has(local.method)) continue
      if (!insideIteration(call)) continue
      // If the queried collection/global is a string literal, every iteration hits
      // the SAME collection -> a real, batchable N+1 (warning). If it's dynamic
      // (a variable/expression), the loop likely spans different collections per
      // item and can't be trivially batched -> info.
      const target = propInit(local.arg, 'collection') ?? propInit(local.arg, 'global')
      const literalTarget = !!target && Node.isStringLiteral(target)
      const severity: Severity = literalTarget ? 'warning' : 'info'
      findings.push(
        makeFinding(call, ctx, 'hook-n-plus-one', 'correctness', severity,
          literalTarget
            ? `payload.${local.method} runs inside a loop/iteration on a fixed collection — one query per item (N+1)`
            : `payload.${local.method} runs inside a loop on a dynamic collection — batch where possible (likely heterogeneous, so info)`,
          'If the collection is fixed, fetch once with { where: { id: { in: ids } } } and map over the result.'),
      )
    }
    return findings
  },
}

const SENSITIVE_LOG_WORDS = new Set([
  'password',
  'token',
  'secret',
  'apikey',
  'privatekey',
  'creditcard',
  'ssn',
  'cvv',
])
const CONSOLE_METHODS = new Set(['log', 'error', 'warn', 'info', 'debug', 'trace'])

/**
 * Logging a sensitive value (password/token/secret/…) leaks it into stdout and
 * log aggregators. We match explicit sensitive property accesses in console.* args.
 */
const sensitiveDataLogged: Check = {
  id: 'sensitive-data-logged',
  category: 'security',
  describe: 'console.* logs a sensitive value (password/token/secret/…)',
  run(file, ctx) {
    const findings: Finding[] = []
    for (const call of file.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      const expr = call.getExpression()
      if (!Node.isPropertyAccessExpression(expr)) continue
      if (expr.getExpression().getText() !== 'console') continue
      if (!CONSOLE_METHODS.has(expr.getName())) continue
      for (const arg of call.getArguments()) {
        // property accesses like data.password, req.user.token
        const accesses = arg.getDescendantsOfKind(SyntaxKind.PropertyAccessExpression)
        const targets = accesses.length ? accesses : (Node.isPropertyAccessExpression(arg) ? [arg] : [])
        const hit = targets.some((a) => nameSegments(a.getName()).some((s) => SENSITIVE_LOG_WORDS.has(s)))
        if (hit) {
          findings.push(
            makeFinding(call, ctx, 'sensitive-data-logged', 'security', 'warning',
              'A sensitive value (password/token/secret/…) is written to the console',
              'Remove the log or redact the field; logs end up in stdout and aggregators.'),
          )
          break
        }
      }
    }
    return findings
  },
}

export const qualityChecks: Check[] = [hookNPlusOne, sensitiveDataLogged]
