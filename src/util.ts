import {
  Node,
  SyntaxKind,
  CallExpression,
  ObjectLiteralExpression,
  type SourceFile,
} from 'ts-morph'
import type { Finding, Severity, Category, CheckContext } from './types'

/** Payload Local API mutation methods (write operations). */
export const MUTATION_METHODS = new Set(['create', 'update', 'delete'])
/** Payload Local API read methods. */
export const READ_METHODS = new Set(['find', 'findByID', 'findGlobal'])
export const LOCAL_API_METHODS = new Set([...MUTATION_METHODS, ...READ_METHODS])

export function lineCol(node: Node): { line: number; column: number } {
  const sf = node.getSourceFile()
  const { line, column } = sf.getLineAndColumnAtPos(node.getStart())
  return { line, column }
}

export function makeFinding(
  node: Node,
  ctx: CheckContext,
  ruleId: string,
  category: Category,
  severity: Severity,
  message: string,
  hint?: string,
  fix?: string,
): Finding {
  const { line, column } = lineCol(node)
  return {
    ruleId,
    category,
    severity,
    message,
    file: ctx.rel(node.getSourceFile().getFilePath()),
    line,
    column,
    hint,
    fix,
  }
}

/** First object-literal argument of a call, if any. */
export function firstObjectArg(call: CallExpression): ObjectLiteralExpression | undefined {
  const arg = call.getArguments()[0]
  if (arg && Node.isObjectLiteralExpression(arg)) return arg
  return undefined
}

/** Get a string-ish value of an object property (initializer text without quotes). */
export function propText(
  obj: ObjectLiteralExpression,
  name: string,
): string | undefined {
  const prop = obj.getProperty(name)
  if (!prop || !Node.isPropertyAssignment(prop)) return undefined
  const init = prop.getInitializer()
  return init?.getText()
}

/** Raw initializer node of an object property. */
export function propInit(obj: ObjectLiteralExpression, name: string): Node | undefined {
  const prop = obj.getProperty(name)
  if (!prop || !Node.isPropertyAssignment(prop)) return undefined
  return prop.getInitializer()
}

export function hasProp(obj: ObjectLiteralExpression, name: string): boolean {
  return obj.getProperty(name) !== undefined
}

/** True if the object literal contains a spread (...x) we cannot statically see into. */
export function hasSpread(obj: ObjectLiteralExpression): boolean {
  return obj.getProperties().some((p) => Node.isSpreadAssignment(p))
}

function unquote(s: string | undefined): string | undefined {
  if (s === undefined) return undefined
  return s.replace(/^['"`]|['"`]$/g, '')
}

export { unquote }

/**
 * Split a field/identifier name into lowercase word segments, handling
 * camelCase and separators. "resetToken" -> ["reset","token"],
 * "hashtags" -> ["hashtags"]. Lets checks match whole words instead of
 * fragile substrings (so "hashtag" never matches "hash").
 */
export function nameSegments(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(/[^a-zA-Z0-9]+/)
    .filter(Boolean)
    .map((s) => s.toLowerCase())
}

/** True if any word segment of `name` is in the given set. */
export function hasSegment(name: string, words: Set<string>): boolean {
  return nameSegments(name).some((seg) => words.has(seg))
}

/**
 * A Payload Local API call looks like `x.<method>({ collection: '...', ... })`.
 * We discriminate from generic Array#find etc. by requiring the first argument
 * to be an object literal carrying a `collection` (or `global`) property.
 */
export function isLocalApiCall(
  call: CallExpression,
): { method: string; arg: ObjectLiteralExpression } | undefined {
  const expr = call.getExpression()
  if (!Node.isPropertyAccessExpression(expr)) return undefined
  const method = expr.getName()
  if (!LOCAL_API_METHODS.has(method)) return undefined
  const arg = firstObjectArg(call)
  if (!arg) return undefined
  if (!hasProp(arg, 'collection') && !hasProp(arg, 'global')) return undefined
  return { method, arg }
}

export type ConfigKind = 'collection' | 'global' | 'block' | 'unknown'

/** Name of the array property an object literal is an element of, if any. */
export function enclosingArrayProp(obj: ObjectLiteralExpression): string | undefined {
  const arr = obj.getParentIfKind(SyntaxKind.ArrayLiteralExpression)
  if (!arr) return undefined
  const pa = arr.getParentIfKind(SyntaxKind.PropertyAssignment)
  if (!pa) return undefined
  return pa.getName().replace(/['"`]/g, '')
}

/** Type annotation directly attached to this object (const x: T =, as T, satisfies T). */
export function directTypeHint(obj: ObjectLiteralExpression): string {
  let target: Node = obj
  let p = obj.getParent()
  while (p && (Node.isAsExpression(p) || Node.isSatisfiesExpression(p) || Node.isParenthesizedExpression(p))) {
    const tn = (p as any).getTypeNode?.()
    if (tn) return tn.getText()
    target = p
    p = p.getParent()
  }
  if (p && Node.isVariableDeclaration(p) && p.getInitializer() === target) {
    return p.getTypeNode()?.getText() ?? ''
  }
  return ''
}

/**
 * Classify a `{ slug, fields }` object. Payload blocks and globals share that
 * shape with collections, so we use position, type annotation and path to avoid
 * flagging blocks/globals as collections (the #1 false-positive source).
 */
export function getConfigKind(obj: ObjectLiteralExpression): ConfigKind {
  if (!hasProp(obj, 'slug') || !hasProp(obj, 'fields')) return 'unknown'

  const prop = enclosingArrayProp(obj)
  if (prop === 'blocks') return 'block'
  if (prop === 'globals') return 'global'
  if (prop === 'collections') return 'collection'
  if (prop === 'fields') return 'block' // a sub-config inside fields, not a collection

  // Nested inside any enclosing config that has `fields` -> it's a block/sub-config.
  let cur: Node | undefined = obj.getParent()
  while (cur) {
    if (Node.isObjectLiteralExpression(cur) && hasProp(cur, 'fields')) return 'block'
    cur = cur.getParent()
  }

  const hint = directTypeHint(obj)
  if (/\bBlock\b/.test(hint)) return 'block'
  if (/GlobalConfig/.test(hint)) return 'global'
  if (/CollectionConfig/.test(hint)) return 'collection'

  const path = obj.getSourceFile().getFilePath()
  if (/\/blocks?\//i.test(path)) return 'block'
  if (/\/globals?\//i.test(path)) return 'global'
  if (/\/collections?\//i.test(path)) return 'collection'

  return 'unknown'
}

/**
 * True only for confirmed collection configs. Blocks, globals and nested field
 * configs are excluded so collection-level checks don't misfire on them.
 */
export function isCollectionConfig(obj: ObjectLiteralExpression): boolean {
  return getConfigKind(obj) === 'collection'
}

/** Does the collection look like an auth collection (public registration is normal)? */
export function isAuthCollection(obj: ObjectLiteralExpression): boolean {
  return hasProp(obj, 'auth')
}

/** Return the `fields` array element object-literals of a collection config. */
export function getFieldObjects(collection: ObjectLiteralExpression): ObjectLiteralExpression[] {
  const fieldsInit = propInit(collection, 'fields')
  if (!fieldsInit || !Node.isArrayLiteralExpression(fieldsInit)) return []
  return fieldsInit
    .getElements()
    .filter(Node.isObjectLiteralExpression) as ObjectLiteralExpression[]
}

/** Does an arrow/function initializer effectively `return true`? */
/**
 * True only if the function *unconditionally* returns boolean `true`:
 *   () => true              (arrow expression body)
 *   () => { return true }   (block whose first statement returns true)
 *   function () { return true }
 * Conditional returns (a guard before `return true`), expressions like
 * `() => true && x`, and unresolvable identifiers (`read: publicRead`) all
 * return false. AST-based, so it doesn't false-match on substrings.
 * Non-goal (scope demarcation, not risk-avoidance): this is a focused heuristic for the
 * literal-`true` case. Folding always-truthy expressions like `() => (!false)` or
 * `() => 1 === 1` is a separate concern with a different scope — it would belong in a
 * dedicated `always-truthy-expression` check, not in this predicate.
 */
export function returnsTrue(init: Node | undefined): boolean {
  if (!init) return false

  const firstStatementReturnsTrue = (body: Node): boolean => {
    if (!Node.isBlock(body)) return false
    const first = body.getStatements()[0]
    if (!first || !Node.isReturnStatement(first)) return false
    const expr = first.getExpression()
    return !!expr && expr.getKind() === SyntaxKind.TrueKeyword
  }

  if (Node.isArrowFunction(init)) {
    const body = init.getBody()
    if (Node.isBlock(body)) return firstStatementReturnsTrue(body)
    let e: Node = body
    while (Node.isParenthesizedExpression(e)) e = e.getExpression()
    return e.getKind() === SyntaxKind.TrueKeyword
  }
  if (Node.isFunctionExpression(init) || Node.isFunctionDeclaration(init)) {
    const body = init.getBody()
    return !!body && firstStatementReturnsTrue(body)
  }
  return false
}

/** Find every CallExpression in a node subtree. */
export function callsIn(node: Node): CallExpression[] {
  return node.getDescendantsOfKind(SyntaxKind.CallExpression)
}

/** True if the file path looks like a migration/seed/script (system writes allowed). */
export function isSystemPath(path: string): boolean {
  return /(migrations?|seeds?|scripts?|\.test\.|\.spec\.)/i.test(path)
}

/**
 * Broader "runs as the system, not on behalf of an end-user request" signal:
 * cron jobs, webhook receivers, background sync/worker/job files. In these the
 * Local API's default `overrideAccess: true` is expected, not a bug.
 */
export function isServerJobPath(path: string): boolean {
  if (isSystemPath(path)) return true
  if (/\/(cron|webhooks?|workers?|jobs|tasks|queue)\//i.test(path)) return true
  if (/(^|\/|[-.])sync(\.|-|$)/i.test(path) || /-(sync|worker|job|cron)\.(ts|js|tsx|jsx)$/i.test(path)) return true
  return false
}

/** True if the file path looks like a request handler (Next route / server action). */
export function looksLikeRequestFile(file: SourceFile): boolean {
  const p = file.getFilePath()
  if (/\/(app|pages)\/.*\/route\.(ts|js|tsx|jsx)$/.test(p)) return true
  if (/\/api\//.test(p)) return true
  const text = file.getFullText()
  if (/['"]use server['"]/.test(text)) return true
  return false
}
