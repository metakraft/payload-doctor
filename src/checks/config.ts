import { Node, SyntaxKind, type ObjectLiteralExpression } from 'ts-morph'
import type { Check, Finding } from '../types'
import {
  isCollectionConfig,
  getFieldObjects,
  propInit,
  propText,
  hasProp,
  makeFinding,
  unquote,
} from '../util'

const CONNECTION_STRING = /(mongodb(\+srv)?|postgres(ql)?|mysql|redis):\/\/[^/\s:]+:[^@/\s]+@/
const KEY_PREFIX = /^(sk-[a-z]|sk_live_|sk_test_|rk_live_|AKIA[0-9A-Z]{16}|ghp_|xox[bp]-|AIza)/

/** Hardcoded secrets / credentials in source instead of env vars. */
const hardcodedSecret: Check = {
  id: 'hardcoded-secret',
  category: 'security',
  describe: 'Secret, key or credential hardcoded as a string literal',
  run(file, ctx) {
    const findings: Finding[] = []

    // secret: '...'  (e.g. PAYLOAD_SECRET) assigned a literal, not process.env
    for (const pa of file.getDescendantsOfKind(SyntaxKind.PropertyAssignment)) {
      const name = pa.getName().replace(/['"`]/g, '').toLowerCase()
      if (!/^(secret|payload_secret|apikey|api_key|password|privatekey)$/.test(name)) continue
      const init = pa.getInitializer()
      if (!init || !Node.isStringLiteral(init)) continue
      const val = init.getLiteralValue()
      if (val.length < 6) continue
      findings.push(
        makeFinding(
          pa,
          ctx,
          'hardcoded-secret',
          'security',
          'error',
          `"${name}" is assigned a hardcoded literal instead of an environment variable`,
          'Read it from process.env and fail closed when it is missing.',
        ),
      )
    }

    // connection strings with embedded credentials, and known key prefixes
    for (const lit of file.getDescendantsOfKind(SyntaxKind.StringLiteral)) {
      const val = lit.getLiteralValue()
      if (CONNECTION_STRING.test(val)) {
        findings.push(
          makeFinding(lit, ctx, 'hardcoded-secret', 'security', 'error',
            'Connection string with embedded credentials found in source',
            'Move it to an environment variable.'),
        )
      } else if (KEY_PREFIX.test(val)) {
        findings.push(
          makeFinding(lit, ctx, 'hardcoded-secret', 'security', 'error',
            'Value looks like a live API key committed to source',
            'Rotate the key and load it from the environment.'),
        )
      }
    }
    return findings
  },
}

/** Wide-open CORS (`'*'`) accepts requests from any origin. */
const wideOpenCors: Check = {
  id: 'wide-open-cors',
  category: 'config',
  describe: "CORS configured as '*' (any origin)",
  run(file, ctx) {
    const findings: Finding[] = []
    for (const pa of file.getDescendantsOfKind(SyntaxKind.PropertyAssignment)) {
      if (pa.getName().replace(/['"`]/g, '') !== 'cors') continue
      const init = pa.getInitializer()
      if (!init) continue
      const text = init.getText().replace(/\s+/g, '')
      if (text === "'*'" || text === '"*"' || text === "['*']" || text === '["*"]') {
        findings.push(
          makeFinding(pa, ctx, 'wide-open-cors', 'config', 'warning',
            'CORS allows any origin (*)',
            'List the exact origins you trust instead of "*".'),
        )
      }
    }
    return findings
  },
}

const SENSITIVE_FIELD = /(token|hash|secret|apikey|resetkey)/i

/**
 * Token/hash/secret fields are exposed through the REST/GraphQL API unless
 * field-level read access denies it. admin.hidden only hides the admin UI.
 */
const tokenFieldReadable: Check = {
  id: 'token-field-readable',
  category: 'privacy',
  describe: 'Sensitive field readable via API (no field-level read:false)',
  run(file, ctx) {
    const findings: Finding[] = []
    for (const obj of file.getDescendantsOfKind(SyntaxKind.ObjectLiteralExpression)) {
      if (!isCollectionConfig(obj)) continue
      const slug = unquote(propText(obj, 'slug')) ?? 'unknown'
      for (const f of getFieldObjects(obj)) {
        const name = unquote(propText(f, 'name'))
        if (!name || !SENSITIVE_FIELD.test(name)) continue
        const accessInit = propInit(f, 'access')
        const guarded =
          accessInit &&
          Node.isObjectLiteralExpression(accessInit) &&
          hasProp(accessInit as ObjectLiteralExpression, 'read')
        if (guarded) continue
        findings.push(
          makeFinding(f, ctx, 'token-field-readable', 'privacy', 'warning',
            `Sensitive field "${name}" on "${slug}" can be read through the API`,
            'Add field access: { read: () => false }. admin.hidden only hides the UI, not the API.'),
        )
      }
    }
    return findings
  },
}

export const configChecks: Check[] = [hardcodedSecret, wideOpenCors, tokenFieldReadable]
