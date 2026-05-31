import { Node, SyntaxKind, type ObjectLiteralExpression } from 'ts-morph'
import type { Check, Finding } from '../types'
import {
  isCollectionConfig,
  getFieldObjects,
  propInit,
  propText,
  hasProp,
  hasSpread,
  hasSegment,
  makeFinding,
  unquote,
  enclosingArrayProp,
  isSystemPath,
  directTypeHint,
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
    // In trusted system code (seed/migrations/scripts) a literal is usually a
    // dev/seed default, not a leaked production secret -> info, don't tank the score.
    const sev: 'error' | 'info' = isSystemPath(file.getFilePath()) ? 'info' : 'error'

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
          sev,
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
          makeFinding(lit, ctx, 'hardcoded-secret', 'security', sev,
            'Connection string with embedded credentials found in source',
            'Move it to an environment variable.'),
        )
      } else if (KEY_PREFIX.test(val)) {
        findings.push(
          makeFinding(lit, ctx, 'hardcoded-secret', 'security', sev,
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

const SENSITIVE_WORDS = new Set([
  'token',
  'hash',
  'secret',
  'apikey',
  'apisecret',
  'resetkey',
  'accesskey',
])

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
        if (!name || !hasSegment(name, SENSITIVE_WORDS)) continue
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

/**
 * A collection/global config without a slug. Payload requires a unique slug per
 * collection (it drives the DB collection and admin/API routes). We only flag
 * high-confidence configs — inline elements of a `collections:`/`globals:` array,
 * or objects explicitly typed `CollectionConfig`/`GlobalConfig` — so nested field
 * groups and tabs (which also carry `fields` but no slug) are never mistaken.
 */
const collectionMissingSlug: Check = {
  id: 'collection-missing-slug',
  category: 'config',
  describe: 'Collection/global config without a slug',
  run(file, ctx) {
    const findings: Finding[] = []
    for (const obj of file.getDescendantsOfKind(SyntaxKind.ObjectLiteralExpression)) {
      if (!hasProp(obj, 'fields') || hasProp(obj, 'slug')) continue
      if (hasProp(obj, 'type') || hasProp(obj, 'name')) continue // it's a field, not a config
      if (hasSpread(obj)) continue // a spread may supply the slug
      const arrProp = enclosingArrayProp(obj)
      const inConfigArray = arrProp === 'collections' || arrProp === 'globals'
      const typed = /CollectionConfig|GlobalConfig/.test(directTypeHint(obj))
      if (!inConfigArray && !typed) continue
      findings.push(
        makeFinding(obj, ctx, 'collection-missing-slug', 'config', 'error',
          'Collection/global config has no slug — Payload requires a unique slug',
          'Add a slug, e.g. slug: "posts".'),
      )
    }
    return findings
  },
}

// Hooks whose return value is consumed by Payload (the transformed data/doc).
const TRANSFORMING_HOOKS = new Set([
  'beforeChange',
  'beforeValidate',
  'beforeRead',
  'afterRead',
  'beforeDuplicate',
])

/** Does a function node return a value at its own scope (not a nested callback)? */
function functionReturnsValue(fn: Node): boolean {
  if (Node.isArrowFunction(fn)) {
    const body = fn.getBody()
    if (body && !Node.isBlock(body)) return true // implicit expression-body return
  }
  const body = (fn as any).getBody?.() as Node | undefined
  if (!body || !Node.isBlock(body)) return false
  let found = false
  body.forEachDescendant((node, traversal) => {
    if (
      Node.isFunctionDeclaration(node) ||
      Node.isFunctionExpression(node) ||
      Node.isArrowFunction(node) ||
      Node.isMethodDeclaration(node)
    ) {
      traversal.skip()
      return
    }
    if (Node.isReturnStatement(node) && node.getExpression()) {
      found = true
      traversal.stop()
    }
  })
  return found
}

/**
 * A transforming hook (beforeChange/beforeValidate/afterRead…) that never returns
 * a value silently drops the change — Payload uses the return value as the new
 * data/doc. Side-effect-only hooks (afterChange, afterDelete…) are not flagged.
 */
const hookMissingReturn: Check = {
  id: 'hook-missing-return',
  category: 'correctness',
  describe: 'Transforming hook (beforeChange/afterRead…) returns nothing',
  run(file, ctx) {
    const findings: Finding[] = []
    for (const pa of file.getDescendantsOfKind(SyntaxKind.PropertyAssignment)) {
      const name = pa.getName().replace(/['"`]/g, '')
      if (!TRANSFORMING_HOOKS.has(name)) continue
      const init = pa.getInitializer()
      if (!init || !Node.isArrayLiteralExpression(init)) continue
      for (const el of init.getElements()) {
        if (!Node.isArrowFunction(el) && !Node.isFunctionExpression(el)) continue
        if (functionReturnsValue(el)) continue
        findings.push(
          makeFinding(el, ctx, 'hook-missing-return', 'correctness', 'warning',
            `${name} hook returns nothing — Payload uses the return value, so the change is discarded`,
            'Return data (before* hooks) or doc (afterRead) at the end of the hook.'),
        )
      }
    }
    return findings
  },
}

/**
 * admin.hidden only hides a field in the Admin UI — it is still returned by the
 * REST/GraphQL API. Without field-level read access that is a false sense of
 * security. We flag fields with admin.hidden:true and no field `access`.
 */
const adminHiddenNotAccess: Check = {
  id: 'admin-hidden-not-access',
  category: 'security',
  describe: 'Field hidden in admin UI but still readable via API (no field access)',
  run(file, ctx) {
    const findings: Finding[] = []
    for (const obj of file.getDescendantsOfKind(SyntaxKind.ObjectLiteralExpression)) {
      if (!hasProp(obj, 'name') || !hasProp(obj, 'type')) continue // must be a field
      if (hasProp(obj, 'access')) continue // dev set field access -> assume intentional
      const adminInit = propInit(obj, 'admin')
      if (!adminInit || !Node.isObjectLiteralExpression(adminInit)) continue
      if (propText(adminInit as ObjectLiteralExpression, 'hidden') !== 'true') continue
      const name = unquote(propText(obj, 'name')) ?? 'field'
      findings.push(
        makeFinding(obj, ctx, 'admin-hidden-not-access', 'security', 'warning',
          `Field "${name}" uses admin.hidden but has no field access — it is still returned by the API`,
          'admin.hidden hides only the Admin UI. Add access: { read: () => false } (or top-level hidden: true) to keep it out of API responses.'),
      )
    }
    return findings
  },
}

const RELATION_TYPES = new Set(['relationship', 'upload'])

/** relationship/upload field without relationTo — Payload cannot resolve the relation. */
const relationshipMissingRelationTo: Check = {
  id: 'relationship-missing-relationTo',
  category: 'correctness',
  describe: 'relationship/upload field without relationTo',
  run(file, ctx) {
    const findings: Finding[] = []
    for (const obj of file.getDescendantsOfKind(SyntaxKind.ObjectLiteralExpression)) {
      const type = unquote(propText(obj, 'type'))
      if (!type || !RELATION_TYPES.has(type)) continue
      if (hasProp(obj, 'relationTo') || hasSpread(obj)) continue
      const name = unquote(propText(obj, 'name')) ?? 'field'
      findings.push(
        makeFinding(obj, ctx, 'relationship-missing-relationTo', 'correctness', 'error',
          `${type} field "${name}" has no relationTo — Payload cannot resolve the relation`,
          'Add relationTo: "collection-slug" (or an array of slugs for polymorphic relations).'),
      )
    }
    return findings
  },
}

const OPTION_TYPES = new Set(['select', 'radio'])

/** select/radio field without options — required by Payload. */
const selectWithoutOptions: Check = {
  id: 'select-without-options',
  category: 'correctness',
  describe: 'select/radio field without options',
  run(file, ctx) {
    const findings: Finding[] = []
    for (const obj of file.getDescendantsOfKind(SyntaxKind.ObjectLiteralExpression)) {
      const type = unquote(propText(obj, 'type'))
      if (!type || !OPTION_TYPES.has(type)) continue
      if (hasProp(obj, 'options') || hasSpread(obj)) continue
      const name = unquote(propText(obj, 'name')) ?? 'field'
      findings.push(
        makeFinding(obj, ctx, 'select-without-options', 'correctness', 'error',
          `${type} field "${name}" has no options`,
          'Add options: [{ label, value }, …].'),
      )
    }
    return findings
  },
}

/**
 * Two fields with the same name in the same fields array collide. We check each
 * literal `fields:` array independently (its own namespace), so nested groups
 * are handled correctly and there are no cross-namespace false positives.
 */
const duplicateFieldName: Check = {
  id: 'duplicate-field-name',
  category: 'correctness',
  describe: 'Duplicate field name within the same fields array',
  run(file, ctx) {
    const findings: Finding[] = []
    for (const pa of file.getDescendantsOfKind(SyntaxKind.PropertyAssignment)) {
      if (pa.getName().replace(/['"`]/g, '') !== 'fields') continue
      const init = pa.getInitializer()
      if (!init || !Node.isArrayLiteralExpression(init)) continue
      const seen = new Set<string>()
      for (const el of init.getElements()) {
        if (!Node.isObjectLiteralExpression(el)) continue
        const name = unquote(propText(el, 'name'))
        if (!name) continue
        if (seen.has(name)) {
          findings.push(
            makeFinding(el, ctx, 'duplicate-field-name', 'correctness', 'error',
              `Duplicate field name "${name}" in the same fields array — the fields collide`,
              'Field names must be unique within their level; rename one.'),
          )
        }
        seen.add(name)
      }
    }
    return findings
  },
}

// Field names Payload reserves / auto-manages; redefining them collides.
const RESERVED_FIELD_NAMES = new Set(['id', '_id', 'createdAt', 'updatedAt', '_status', 'blockType', 'blockName'])
// Payload's internal collection slugs.
const RESERVED_SLUGS = new Set([
  'payload-preferences',
  'payload-migrations',
  'payload-locked-documents',
  'payload-jobs',
])
// Field names that are very commonly used as query filters.
const FILTER_FIELD_NAMES = new Set(['email', 'slug', 'username', 'externalid', 'sku'])

/**
 * Weak auth config: lockout disabled (`maxLoginAttempts: 0`) or a very long
 * `tokenExpiration`. Payload's defaults are safe, so we only flag explicit
 * weakenings — not a missing option (the default still applies).
 */
const authWeakConfig: Check = {
  id: 'auth-weak-config',
  category: 'security',
  describe: 'Auth config weakens brute-force lockout or uses a very long token lifetime',
  run(file, ctx) {
    const findings: Finding[] = []
    for (const pa of file.getDescendantsOfKind(SyntaxKind.PropertyAssignment)) {
      if (pa.getName().replace(/['"`]/g, '') !== 'auth') continue
      const auth = pa.getInitializer()
      if (!auth || !Node.isObjectLiteralExpression(auth)) continue
      const maxAttempts = propText(auth, 'maxLoginAttempts')
      if (maxAttempts === '0') {
        findings.push(
          makeFinding(auth, ctx, 'auth-weak-config', 'security', 'warning',
            'maxLoginAttempts: 0 disables brute-force lockout entirely',
            'Use a small positive number (Payload defaults to 5) to lock accounts after failed logins.'),
        )
      }
      const exp = propText(auth, 'tokenExpiration')
      if (exp && /^\d+$/.test(exp) && Number(exp) > 2_592_000) {
        findings.push(
          makeFinding(auth, ctx, 'auth-weak-config', 'security', 'warning',
            `tokenExpiration is ${exp}s (> 30 days) — a long-lived token widens the window if it leaks`,
            'Prefer a short tokenExpiration and refresh, unless this collection truly needs long sessions.'),
        )
      }
    }
    return findings
  },
}

/**
 * Field name or collection slug that collides with Payload-reserved identifiers
 * or is illegal in MongoDB (contains "." or starts with "$"). Generic SQL keywords
 * are intentionally NOT flagged — the SQL adapter quotes identifiers, so they work.
 */
const reservedFieldName: Check = {
  id: 'reserved-field-name',
  category: 'config',
  describe: 'Field name / slug collides with a Payload-reserved or Mongo-illegal identifier',
  run(file, ctx) {
    const findings: Finding[] = []
    // Reserved names (id/createdAt/…) only collide at the collection document top
    // level. Inside array/blocks rows `id` is normal, and group/tab fields are
    // namespaced — so skip the reserved-name check there (Mongo-illegal still applies).
    const inSubFieldScope = (obj: Node): boolean => {
      let cur: Node | undefined = obj.getParent()
      while (cur) {
        if (Node.isObjectLiteralExpression(cur)) {
          const t = propText(cur, 'type')?.replace(/['"`]/g, '')
          if (t === 'array' || t === 'blocks' || t === 'group') return true
        }
        cur = cur.getParent()
      }
      return false
    }
    for (const obj of file.getDescendantsOfKind(SyntaxKind.ObjectLiteralExpression)) {
      // field name — only objects that are actually fields in a `fields: [...]`
      // array. This excludes query/select/alias objects elsewhere (e.g. a
      // `{ name: 'm.name' }` projection in a raw query) that merely look field-ish.
      if (hasProp(obj, 'name') && hasProp(obj, 'type') && enclosingArrayProp(obj) === 'fields') {
        const name = unquote(propText(obj, 'name'))
        if (name) {
          const illegal = name.includes('.') || name.startsWith('$')
          const reserved = RESERVED_FIELD_NAMES.has(name) && !inSubFieldScope(obj)
          if (reserved || illegal) {
            findings.push(
              makeFinding(obj, ctx, 'reserved-field-name', 'config', 'warning',
                `Field name "${name}" is reserved by Payload or illegal in MongoDB`,
                'Rename the field (Payload manages id/_id/createdAt/updatedAt/_status itself; "." and "$" are invalid in Mongo keys).',
                `// rename "${name}" — Payload manages id/_id/createdAt/updatedAt/_status itself,\n// and "."/"$" are invalid in MongoDB keys`),
            )
          }
        }
      }
      // collection slug
      if (isCollectionConfig(obj)) {
        const slug = unquote(propText(obj, 'slug'))
        if (slug && RESERVED_SLUGS.has(slug)) {
          findings.push(
            makeFinding(obj, ctx, 'reserved-field-name', 'config', 'warning',
              `Collection slug "${slug}" collides with a Payload-internal collection`,
              'Choose a different slug; payload-* slugs are reserved for Payload internals.'),
          )
        }
      }
    }
    return findings
  },
}

/** maxDepth/defaultDepth set very high can make populated queries blow up. */
const excessiveMaxDepth: Check = {
  id: 'excessive-max-depth',
  category: 'config',
  describe: 'maxDepth / defaultDepth set above 10',
  run(file, ctx) {
    const findings: Finding[] = []
    for (const pa of file.getDescendantsOfKind(SyntaxKind.PropertyAssignment)) {
      const name = pa.getName().replace(/['"`]/g, '')
      if (name !== 'maxDepth' && name !== 'defaultDepth') continue
      const init = pa.getInitializer()
      if (!init || !Node.isNumericLiteral(init)) continue
      const val = Number(init.getText())
      if (val > 10) {
        findings.push(
          makeFinding(pa, ctx, 'excessive-max-depth', 'config', 'warning',
            `${name} is ${val} — deep relationship population can balloon query cost and response size`,
            'Keep depth small (often 1–2) and request more only where needed.'),
        )
      }
    }
    return findings
  },
}

/** Commonly-filtered fields without an index pay a scan cost on every lookup. */
const missingIndexOnFilterField: Check = {
  id: 'missing-index-on-filter-field',
  category: 'config',
  describe: 'Commonly-filtered field (email/slug/…) without index: true',
  run(file, ctx) {
    const findings: Finding[] = []
    for (const obj of file.getDescendantsOfKind(SyntaxKind.ObjectLiteralExpression)) {
      if (!hasProp(obj, 'name') || !hasProp(obj, 'type')) continue
      const name = unquote(propText(obj, 'name'))
      if (!name || !FILTER_FIELD_NAMES.has(name.toLowerCase())) continue
      if (propText(obj, 'index') === 'true' || propText(obj, 'unique') === 'true') continue
      findings.push(
        makeFinding(obj, ctx, 'missing-index-on-filter-field', 'config', 'info',
          `Field "${name}" is commonly filtered but has no index — add index: true if you query by it`,
          'Set index: true (or unique: true) to avoid full collection scans.'),
      )
    }
    return findings
  },
}

export const configChecks: Check[] = [
  hardcodedSecret,
  wideOpenCors,
  tokenFieldReadable,
  collectionMissingSlug,
  hookMissingReturn,
  adminHiddenNotAccess,
  relationshipMissingRelationTo,
  selectWithoutOptions,
  duplicateFieldName,
  authWeakConfig,
  reservedFieldName,
  excessiveMaxDepth,
  missingIndexOnFilterField,
]
