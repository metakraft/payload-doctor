// Generic, copy-pasteable fix suggestions per rule. These are starting points,
// not file-specific rewrites — payload-doctor never modifies your files.
const FIXES: Record<string, string> = {
  'local-api-override-access':
    "await payload.find({ collection, overrideAccess: false, user: req.user })",
  'override-access-true-with-user':
    "// drop overrideAccess and pass the real user so access control runs",
  'collection-missing-access':
    "access: {\n  read: () => true,\n  create: ({ req }) => Boolean(req.user),\n  update: ({ req }) => Boolean(req.user),\n  delete: ({ req }) => req.user?.role === 'admin',\n}",
  'open-access-function':
    "read: ({ req }) => Boolean(req.user)  // not () => true",
  'missing-owner-enforcement':
    "// beforeChange: data.owner = req.user.id\n// access.read:  ({ req }) => ({ owner: { equals: req.user?.id } })",
  'user-writable-privileged-field':
    "access: { update: ({ req }) => req.user?.role === 'admin' }",
  'cron-not-fail-closed':
    "if (req.headers.get('authorization') !== `Bearer ${process.env.CRON_SECRET}`)\n  return new Response('Unauthorized', { status: 401 })",
  'side-effect-in-get':
    "export async function POST() { /* move the write here, or add an idempotency guard */ }",
  'leaks-error-message':
    "console.error(err)  // log server-side\nreturn Response.json({ error: 'Internal error' }, { status: 500 })",
  'hardcoded-secret':
    "secret: process.env.PAYLOAD_SECRET!  // and throw at startup if missing",
  'wide-open-cors':
    "cors: ['https://yourdomain.com']",
  'token-field-readable':
    "access: { read: () => false }",
  'unsafe-richtext-render':
    "dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }}",
  'collection-missing-slug':
    "slug: 'posts',",
  'hook-missing-return':
    "return data  // afterRead: return doc",
  'admin-hidden-not-access':
    "access: { read: () => false },  // admin.hidden alone leaves it in the API",
  'duplicate-slug':
    "// rename one collection to a unique slug",
  'dependency-version-mismatch':
    "// pin all payload + @payloadcms/* deps to the same exact version",
  'relationship-missing-relationTo':
    "{ name: 'author', type: 'relationship', relationTo: 'users' }",
  'select-without-options':
    "{ name: 'status', type: 'select', options: [{ label: 'Draft', value: 'draft' }] }",
  'duplicate-field-name':
    "// rename one of the two fields so names are unique within the level",
  'auth-weak-config':
    "auth: { maxLoginAttempts: 5, lockTime: 600000, tokenExpiration: 7200 }",
  'sensitive-data-logged':
    "// remove the log, or redact: console.log({ id: doc.id }) — never the secret itself",
  'reserved-field-name':
    "// rename the field (Payload owns id/_id/createdAt/updatedAt/_status); no '.' or '$' in Mongo keys",
  'excessive-max-depth':
    "maxDepth: 2,  // request deeper only where you actually need it",
  'missing-index-on-filter-field':
    "{ name: 'email', type: 'email', index: true }",
  'hook-n-plus-one':
    "const docs = await payload.find({ collection, where: { id: { in: ids } } })\n// then map over docs.docs instead of querying per item",
  'circular-relationship':
    "// fine if intentional — just keep query depth small (depth: 1) to avoid populating the loop",
}

export function fixFor(ruleId: string): string | undefined {
  return FIXES[ruleId]
}
