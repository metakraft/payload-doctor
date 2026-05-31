import { Node, SyntaxKind } from 'ts-morph'
import type { Check, Finding } from '../types'
import { isLocalApiCall, makeFinding, MUTATION_METHODS } from '../util'

/**
 * Fail-open secret check: `if (secret && header !== ...) return 401` means that
 * when the secret is unset the guard is skipped and the endpoint is public.
 */
const cronNotFailClosed: Check = {
  id: 'cron-not-fail-closed',
  category: 'security',
  describe: 'Secret/cron auth check is fail-open (missing secret leaves endpoint public)',
  run(file, ctx) {
    const findings: Finding[] = []
    for (const ifStmt of file.getDescendantsOfKind(SyntaxKind.IfStatement)) {
      const cond = ifStmt.getExpression()
      if (!Node.isBinaryExpression(cond)) continue
      if (cond.getOperatorToken().getKind() !== SyntaxKind.AmpersandAmpersandToken) continue
      const leftText = cond.getLeft().getText()
      // Left operand is a bare secret-ish truthiness guard.
      if (!/secret|token|apikey|api_key/i.test(leftText)) continue
      if (/[=!<>]/.test(leftText)) continue // left already a comparison, not a bare guard
      const thenText = ifStmt.getThenStatement().getText()
      if (!/(401|403|unauthorized|forbidden|return|throw)/i.test(thenText)) continue
      findings.push(
        makeFinding(
          ifStmt,
          ctx,
          'cron-not-fail-closed',
          'security',
          'error',
          'Auth guard is fail-open: if the secret is unset the check is skipped and the endpoint stays public',
          'Fail closed: if (!secret) return 500/false BEFORE comparing the header.',
        ),
      )
    }
    return findings
  },
}

function bodyHasMutation(node: Node): Node | undefined {
  for (const call of node.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const local = isLocalApiCall(call)
    if (local && MUTATION_METHODS.has(local.method)) return call
  }
  return undefined
}

/**
 * GET handlers that write are triggered by prefetch / link scanners / double
 * renders. Detects Next.js `export function GET` and Payload endpoints with
 * method:'get' whose body performs a Local API mutation.
 */
const sideEffectInGet: Check = {
  id: 'side-effect-in-get',
  category: 'correctness',
  describe: 'GET handler performs a write (prefetch/scanner can trigger it)',
  run(file, ctx) {
    const findings: Finding[] = []
    const path = file.getFilePath()
    const isCron = /\/cron\//i.test(path)
    const isUnsub = !isCron && /unsubscribe|opt-?out/i.test(path)
    const sev = isCron ? 'info' : isUnsub ? 'warning' : 'error'
    const note = isCron
      ? ' (Vercel cron requires GET — ensure the write is idempotent)'
      : isUnsub
        ? ' (email one-click unsubscribe — but mail-client prefetch can auto-trigger it; prefer RFC 8058 List-Unsubscribe-Post or a confirm step)'
        : ''

    // Next.js route handlers: export async function GET(...) {}
    for (const fn of file.getFunctions()) {
      if (fn.getName() !== 'GET') continue
      const body = fn.getBody()
      if (!body) continue
      const mutation = bodyHasMutation(body)
      if (mutation) {
        findings.push(
          makeFinding(
            fn.getNameNode() ?? fn,
            ctx,
            'side-effect-in-get',
            'correctness',
            sev,
            `GET route handler performs a write — link prefetch or email scanners can trigger it unintentionally${note}`,
            'Move the side effect to POST, or add an idempotency guard.',
          ),
        )
      }
    }

    // Payload custom endpoints: { method: 'get', handler: ... }
    for (const obj of file.getDescendantsOfKind(SyntaxKind.ObjectLiteralExpression)) {
      const methodProp = obj.getProperty('method')
      if (!methodProp || !Node.isPropertyAssignment(methodProp)) continue
      const m = methodProp.getInitializer()?.getText().replace(/['"`]/g, '').toLowerCase()
      if (m !== 'get') continue
      const handlerProp = obj.getProperty('handler')
      if (!handlerProp) continue
      const mutation = bodyHasMutation(obj)
      if (mutation) {
        findings.push(
          makeFinding(
            methodProp,
            ctx,
            'side-effect-in-get',
            'correctness',
            sev,
            `Payload endpoint with method:'get' performs a write${note}`,
            'Use method:\'post\' for mutating endpoints, or guard against repeated calls.',
          ),
        )
      }
    }

    return findings
  },
}

/** Returning error.message / error.stack to the client leaks internals. */
const leaksErrorMessage: Check = {
  id: 'leaks-error-message',
  category: 'security',
  describe: 'Internal error message/stack returned to the client',
  run(file, ctx) {
    const findings: Finding[] = []
    for (const pa of file.getDescendantsOfKind(SyntaxKind.PropertyAssignment)) {
      const name = pa.getName().replace(/['"`]/g, '')
      if (name !== 'error' && name !== 'message') continue
      const initText = pa.getInitializer()?.getText() ?? ''
      if (/(^|[^\w.])(err|error|e|ex|exception)\s*\.\s*(message|stack)\b/.test(initText)) {
        findings.push(
          makeFinding(
            pa,
            ctx,
            'leaks-error-message',
            'security',
            'warning',
            'Response leaks an internal error message/stack to the client',
            'Log the error server-side; return a generic message like "Internal server error".',
          ),
        )
      }
    }
    return findings
  },
}

export const routeChecks: Check[] = [cronNotFailClosed, sideEffectInGet, leaksErrorMessage]
