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

function unquote(s: string | undefined): string | undefined {
  if (s === undefined) return undefined
  return s.replace(/^['"`]|['"`]$/g, '')
}

export { unquote }

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

/**
 * Heuristic: is this object literal a Payload collection config?
 * Collection configs always carry both `slug` and `fields`.
 */
export function isCollectionConfig(obj: ObjectLiteralExpression): boolean {
  return hasProp(obj, 'slug') && hasProp(obj, 'fields')
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
export function returnsTrue(init: Node | undefined): boolean {
  if (!init) return false
  const text = init.getText().replace(/\s+/g, ' ')
  if (/=>\s*true\b/.test(text)) return true
  if (/return\s+true\b/.test(text)) return true
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

/** True if the file path looks like a request handler (Next route / server action). */
export function looksLikeRequestFile(file: SourceFile): boolean {
  const p = file.getFilePath()
  if (/\/(app|pages)\/.*\/route\.(ts|js|tsx|jsx)$/.test(p)) return true
  if (/\/api\//.test(p)) return true
  const text = file.getFullText()
  if (/['"]use server['"]/.test(text)) return true
  return false
}
