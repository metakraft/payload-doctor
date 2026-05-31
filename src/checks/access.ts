import { Node, SyntaxKind, type ObjectLiteralExpression } from 'ts-morph'
import type { Check, Finding } from '../types'
import {
  isLocalApiCall,
  isCollectionConfig,
  isSystemPath,
  looksLikeRequestFile,
  getFieldObjects,
  propInit,
  propText,
  hasProp,
  returnsTrue,
  makeFinding,
  unquote,
  MUTATION_METHODS,
} from '../util'

const PRIVILEGED_FIELD = /^(roles?|isadmin|isstaff|ispremium|permissions?|capabilities|plan|tier)$/i

/**
 * The headline rule: Payload's Local API defaults to overrideAccess: true,
 * which BYPASSES collection access control. Any request-context call must set
 * overrideAccess: false (and pass `user`) or it silently runs as admin.
 */
const localApiOverride: Check = {
  id: 'local-api-override-access',
  category: 'security',
  describe: 'Local API call without overrideAccess:false bypasses access control',
  run(file, ctx) {
    const findings: Finding[] = []
    if (isSystemPath(file.getFilePath())) return findings
    const requestCtx = looksLikeRequestFile(file)
    for (const call of file.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      const local = isLocalApiCall(call)
      if (!local) continue
      const overrideText = propText(local.arg, 'overrideAccess')
      if (overrideText === 'false') continue // explicitly safe
      const isMutation = MUTATION_METHODS.has(local.method)
      // Mutations are always serious; reads only flagged in request files.
      if (!isMutation && !requestCtx) continue
      const severity = isMutation ? 'error' : 'warning'
      findings.push(
        makeFinding(
          call,
          ctx,
          'local-api-override-access',
          'security',
          severity,
          `payload.${local.method}() runs with overrideAccess:true by default, bypassing collection access control`,
          'Pass overrideAccess:false and user, or verify ownership manually (defense in depth).',
        ),
      )
    }
    return findings
  },
}

/** overrideAccess:true while a user is also passed is contradictory and dangerous. */
const overrideTrueWithUser: Check = {
  id: 'override-access-true-with-user',
  category: 'security',
  describe: 'overrideAccess:true alongside a user defeats access control on purpose',
  run(file, ctx) {
    const findings: Finding[] = []
    if (isSystemPath(file.getFilePath())) return findings
    for (const call of file.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      const local = isLocalApiCall(call)
      if (!local) continue
      if (propText(local.arg, 'overrideAccess') !== 'true') continue
      if (!hasProp(local.arg, 'user')) continue
      findings.push(
        makeFinding(
          call,
          ctx,
          'override-access-true-with-user',
          'security',
          'error',
          `payload.${local.method}() sets overrideAccess:true while passing a user — access control is skipped`,
          'Use overrideAccess:false in request context; reserve overrideAccess:true for system writes with no user.',
        ),
      )
    }
    return findings
  },
}

/** A collection with no explicit access control relies on framework defaults. */
const collectionMissingAccess: Check = {
  id: 'collection-missing-access',
  category: 'security',
  describe: 'Collection has no explicit access control block',
  run(file, ctx) {
    const findings: Finding[] = []
    for (const obj of file.getDescendantsOfKind(SyntaxKind.ObjectLiteralExpression)) {
      if (!isCollectionConfig(obj)) continue
      if (hasProp(obj, 'access')) continue
      const slug = unquote(propText(obj, 'slug')) ?? 'unknown'
      findings.push(
        makeFinding(
          obj,
          ctx,
          'collection-missing-access',
          'security',
          'warning',
          `Collection "${slug}" defines no access control — operations fall back to defaults`,
          'Define access.read / create / update / delete explicitly (owner-or-admin where-constraint for user data).',
        ),
      )
    }
    return findings
  },
}

/** read/create/update/delete access function that returns true grants the world. */
const openAccessFunction: Check = {
  id: 'open-access-function',
  category: 'security',
  describe: 'Access function returns true (open to everyone)',
  run(file, ctx) {
    const findings: Finding[] = []
    for (const obj of file.getDescendantsOfKind(SyntaxKind.ObjectLiteralExpression)) {
      if (!isCollectionConfig(obj)) continue
      const accessInit = propInit(obj, 'access')
      if (!accessInit || !Node.isObjectLiteralExpression(accessInit)) continue
      const slug = unquote(propText(obj, 'slug')) ?? 'unknown'
      for (const op of ['create', 'update', 'delete', 'read'] as const) {
        const init = propInit(accessInit as ObjectLiteralExpression, op)
        if (!returnsTrue(init)) continue
        const isWrite = op !== 'read'
        findings.push(
          makeFinding(
            init!,
            ctx,
            'open-access-function',
            'security',
            isWrite ? 'error' : 'info',
            `Collection "${slug}" has access.${op} returning true — ${isWrite ? 'anyone can write' : 'fully public read'}`,
            isWrite
              ? 'Restrict to owner-or-admin (return a where-constraint for non-admins).'
              : 'Confirm this collection is intended to be public.',
          ),
        )
      }
    }
    return findings
  },
}

/**
 * If a collection links to users and allows create, a client could supply an
 * arbitrary owner. Ownership must be forced in a beforeValidate hook.
 */
const missingOwnerEnforcement: Check = {
  id: 'missing-owner-enforcement',
  category: 'security',
  describe: 'User-owned collection does not force ownership on create',
  run(file, ctx) {
    const findings: Finding[] = []
    for (const obj of file.getDescendantsOfKind(SyntaxKind.ObjectLiteralExpression)) {
      if (!isCollectionConfig(obj)) continue
      const slug = unquote(propText(obj, 'slug')) ?? 'unknown'
      if (slug === 'users') continue // identity is `id`, handled elsewhere
      const fields = getFieldObjects(obj)
      const ownerField = fields.find((f) => {
        const rel = unquote(propText(f, 'relationTo'))
        const name = unquote(propText(f, 'name'))
        return rel === 'users' || (name ? /^(user|owner|author|createdby)$/i.test(name) : false)
      })
      if (!ownerField) continue
      // Look for any beforeValidate/beforeChange hook that assigns the owner.
      const hooksInit = propInit(obj, 'hooks')
      let enforced = false
      if (hooksInit && Node.isObjectLiteralExpression(hooksInit)) {
        const hooksText = hooksInit.getText()
        if (/beforeValidate|beforeChange/.test(hooksText) && /\bdata\.(user|owner|author)\b/.test(hooksText)) {
          enforced = true
        }
      }
      if (enforced) continue
      findings.push(
        makeFinding(
          ownerField,
          ctx,
          'missing-owner-enforcement',
          'security',
          'warning',
          `Collection "${slug}" links to a user but does not force ownership on create`,
          'Add a beforeValidate hook that sets data.user = req.user.id on create; never trust a client-supplied owner.',
        ),
      )
    }
    return findings
  },
}

/** A privileged field (roles, isAdmin, ...) without field-level update access escalates. */
const userWritablePrivilegedField: Check = {
  id: 'user-writable-privileged-field',
  category: 'security',
  describe: 'Privileged field lacks field-level update access (privilege escalation)',
  run(file, ctx) {
    const findings: Finding[] = []
    for (const obj of file.getDescendantsOfKind(SyntaxKind.ObjectLiteralExpression)) {
      if (!isCollectionConfig(obj)) continue
      const slug = unquote(propText(obj, 'slug')) ?? 'unknown'
      for (const f of getFieldObjects(obj)) {
        const name = unquote(propText(f, 'name'))
        if (!name || !PRIVILEGED_FIELD.test(name)) continue
        const accessInit = propInit(f, 'access')
        const hasUpdateGate =
          accessInit &&
          Node.isObjectLiteralExpression(accessInit) &&
          hasProp(accessInit as ObjectLiteralExpression, 'update')
        if (hasUpdateGate) continue
        findings.push(
          makeFinding(
            f,
            ctx,
            'user-writable-privileged-field',
            'security',
            'error',
            `Field "${name}" on "${slug}" has no field-level access.update — a user could escalate their own privileges`,
            'Add field access: { update: ({ req }) => isAdmin(req.user) } to lock the field to admins.',
          ),
        )
      }
    }
    return findings
  },
}

export const accessChecks: Check[] = [
  localApiOverride,
  overrideTrueWithUser,
  collectionMissingAccess,
  openAccessFunction,
  missingOwnerEnforcement,
  userWritablePrivilegedField,
]
