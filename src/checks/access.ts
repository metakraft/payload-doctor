import { Node, SyntaxKind, type ObjectLiteralExpression } from 'ts-morph'
import type { Check, Finding, Severity } from '../types'
import {
  isLocalApiCall,
  isCollectionConfig,
  isAuthCollection,
  isSystemPath,
  isServerJobPath,
  looksLikeRequestFile,
  getFieldObjects,
  propInit,
  propText,
  hasProp,
  hasSpread,
  hasSegment,
  returnsTrue,
  makeFinding,
  unquote,
  MUTATION_METHODS,
} from '../util'

const PRIVILEGED_WORDS = new Set([
  'role',
  'roles',
  'admin',
  'isadmin',
  'staff',
  'isstaff',
  'permission',
  'permissions',
  'capability',
  'capabilities',
])

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
      // Can't see into a spread; assume it may carry overrideAccess:false.
      if (hasSpread(local.arg)) continue
      const overrideText = propText(local.arg, 'overrideAccess')
      if (overrideText === 'false') continue // explicitly safe
      const isMutation = MUTATION_METHODS.has(local.method)
      const hasUser = hasProp(local.arg, 'user')

      if (overrideText === 'true') {
        // overrideAccess:true + user is contradictory -> reported by override-access-true-with-user
        if (hasUser) continue
        // explicit system write with no user -> intentional; surface as info only
        findings.push(
          makeFinding(
            call,
            ctx,
            'local-api-override-access',
            'security',
            'info',
            `payload.${local.method}() uses explicit overrideAccess:true with no user (system write)`,
            'Fine for cron/migrations/webhooks. If this ever runs for a user, pass overrideAccess:false and user.',
          ),
        )
        continue
      }

      // overrideAccess not set -> defaults to true (the real footgun)
      // In server/job context (cron, webhooks, sync, migrations) this is expected -> info.
      // Otherwise mutations are serious; reads only flagged in request files.
      const serverJob = isServerJobPath(file.getFilePath())
      if (!isMutation && !requestCtx && !serverJob) continue
      const severity: Severity = serverJob ? 'info' : isMutation ? 'error' : 'warning'
      findings.push(
        makeFinding(
          call,
          ctx,
          'local-api-override-access',
          'security',
          severity,
          `payload.${local.method}() runs with overrideAccess:true by default, bypassing collection access control`,
          serverJob
            ? 'System/job context — overrideAccess defaulting to true is expected here. Only pass overrideAccess:false + user if this can ever run on behalf of an end user.'
            : 'Pass overrideAccess:false and user, or verify ownership manually (defense in depth).',
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
          `"${slug}" has no explicit access control — operations fall back to framework defaults`,
          'Define access.read / create / update / delete explicitly (owner-or-admin where-constraint for user data).',
          `// collection "${slug}": define access explicitly\naccess: {\n  read: ownerOrAdmin,\n  create: authenticated,\n  update: ownerOrAdmin,\n  delete: ({ req }) => isAdmin(req.user),\n}`,
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
      const auth = isAuthCollection(obj)
      for (const op of ['create', 'update', 'delete', 'read'] as const) {
        const init = propInit(accessInit as ObjectLiteralExpression, op)
        if (!returnsTrue(init)) continue
        const isWrite = op !== 'read'
        // public registration (create on an auth collection) is a normal pattern
        const publicRegistration = op === 'create' && auth
        const severity = !isWrite || publicRegistration ? 'info' : 'error'
        const message = publicRegistration
          ? `Auth collection "${slug}" allows public create (registration)`
          : isWrite
            ? `Collection "${slug}" has access.${op} returning true — anyone can write`
            : `Collection "${slug}" has access.${op} returning true — fully public read`
        const hint = publicRegistration
          ? 'Confirm public registration is intended; otherwise restrict create.'
          : isWrite
            ? 'Restrict to owner-or-admin (return a where-constraint for non-admins).'
            : 'Confirm this collection is intended to be public.'
        findings.push(
          makeFinding(init!, ctx, 'open-access-function', 'security', severity, message, hint),
        )
      }
    }
    return findings
  },
}

type CreateAccess = 'public' | 'authenticated' | 'restricted' | 'unknown'

/**
 * Classify a collection's `access.create`. "owner" patterns (ownerOrAdmin) count
 * as user-facing, not admin-restricted — only admin/role-gated or `false` create
 * is "restricted" (the system controls creation).
 */
function classifyCreateAccess(obj: ObjectLiteralExpression): CreateAccess {
  const access = propInit(obj, 'access')
  if (!access || !Node.isObjectLiteralExpression(access)) return 'unknown'
  const create = propInit(access, 'create')
  if (!create) return 'unknown'
  if (returnsTrue(create)) return 'public'
  const text = create.getText().replace(/\s+/g, ' ')
  const lc = text.toLowerCase()
  const hasOwner = /owner|isowner|ownuser/.test(lc)
  if (!hasOwner && /=>\s*false|return\s+false/.test(text)) return 'restricted'
  if (!hasOwner && /(admin|\brole|staff|superuser|permission)/.test(lc)) return 'restricted'
  if (hasOwner) return 'authenticated'
  if (/authenticated/.test(lc) || /req\.user|\buser\b/.test(lc)) return 'authenticated'
  return 'unknown'
}

/** Does the collection have a beforeChange/beforeValidate hook (may sanitize input)? */
function hasMutatingHook(obj: ObjectLiteralExpression): boolean {
  const hooksInit = propInit(obj, 'hooks')
  return (
    !!hooksInit &&
    Node.isObjectLiteralExpression(hooksInit) &&
    /beforeValidate|beforeChange/.test(hooksInit.getText())
  )
}

/**
 * If a collection links to users and allows create, a client could supply an
 * arbitrary owner. Ownership must be forced in a beforeValidate hook. If create
 * is admin/system-restricted, the system controls the owner, so this is info.
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
      // Suppress if ownership could plausibly be enforced:
      //  - a beforeValidate/beforeChange hook exists (may live in an imported fn), or
      //  - the owner field has a defaultValue (often req.user.id).
      let enforced = hasMutatingHook(obj)
      if (hasProp(ownerField, 'defaultValue')) enforced = true
      if (enforced) continue
      // If creation is admin/system-restricted, the system stamps the owner -> info, not warning.
      const restricted = classifyCreateAccess(obj) === 'restricted'
      const ownerName = unquote(propText(ownerField, 'name')) ?? 'user'
      findings.push(
        makeFinding(
          ownerField,
          ctx,
          'missing-owner-enforcement',
          'security',
          restricted ? 'info' : 'warning',
          restricted
            ? `Collection "${slug}" links to a user; creation is admin/system-restricted, so the owner is system-set (verify it really is)`
            : `Collection "${slug}" links to a user but does not force ownership on create`,
          'Add a beforeValidate hook that sets data.user = req.user.id on create; never trust a client-supplied owner.',
          `// collection "${slug}": stamp the owner on create, ignore client input\nhooks: { beforeChange: [({ req, data, operation }) => {\n  if (operation === 'create' && req.user) data.${ownerName} = req.user.id\n  return data\n}] }`,
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
        if (!name || !hasSegment(name, PRIVILEGED_WORDS)) continue
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

/**
 * Mass assignment / privilege escalation on create: an AUTH collection whose
 * `create` access is open (public or any authenticated user) has a privileged
 * field (roles/isAdmin/…) with no field-level `access.create` and no sanitizing
 * hook — so a registrant could set `roles: ['admin']` in the create payload.
 * Scoped to auth collections because a `roles` field on a content collection is
 * not a privilege vector. Complements user-writable-privileged-field (update path).
 */
const massAssignment: Check = {
  id: 'mass-assignment',
  category: 'security',
  describe: 'Privileged field settable on create (open create, no field access.create)',
  run(file, ctx) {
    const findings: Finding[] = []
    for (const obj of file.getDescendantsOfKind(SyntaxKind.ObjectLiteralExpression)) {
      if (!isCollectionConfig(obj)) continue
      const slug = unquote(propText(obj, 'slug')) ?? 'unknown'
      if (!isAuthCollection(obj) && slug !== 'users') continue
      const createClass = classifyCreateAccess(obj)
      if (createClass !== 'public' && createClass !== 'authenticated') continue
      if (hasMutatingHook(obj)) continue // a beforeChange hook may strip the field on create
      for (const f of getFieldObjects(obj)) {
        const name = unquote(propText(f, 'name'))
        if (!name || !hasSegment(name, PRIVILEGED_WORDS)) continue
        const accessInit = propInit(f, 'access')
        let createGated = false
        if (accessInit && Node.isObjectLiteralExpression(accessInit)) {
          const fCreate = propInit(accessInit, 'create')
          if (fCreate && !returnsTrue(fCreate)) createGated = true
        }
        if (createGated) continue
        const severity: Severity = createClass === 'public' ? 'error' : 'warning'
        const who = createClass === 'public' ? 'Anyone (create is public)' : 'Any authenticated user'
        findings.push(
          makeFinding(
            f,
            ctx,
            'mass-assignment',
            'security',
            severity,
            `Privileged field "${name}" on "${slug}" can be set on create — ${who}, and it has no field-level access.create (mass-assignment privilege escalation)`,
            'Add field access: { create: ({ req }) => isAdmin(req.user) } so only admins can set it, even on create. The defaultValue still applies for normal sign-ups.',
            `// field "${name}" on "${slug}": add a field-level create gate\naccess: { create: ({ req }) => req.user?.roles?.includes('admin') ?? false }`,
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
  massAssignment,
]
