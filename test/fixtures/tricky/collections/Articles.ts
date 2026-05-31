// Legitimate patterns that previously risked false positives.
// payload-doctor should report ZERO findings here.
import type { CollectionConfig, Access } from 'payload'
import { forceOwner } from '../hooks/forceOwner' // hook lives in another file

const ownerOrAdmin: Access = ({ req: { user } }) => {
  if (!user) return false
  if (((user as any).roles || []).includes('admin')) return true
  return { user: { equals: user.id } }
}

export const Articles: CollectionConfig = {
  slug: 'articles',
  access: {
    read: ownerOrAdmin,
    create: ({ req: { user } }) => !!user,
    update: ownerOrAdmin,
    delete: ownerOrAdmin,
  },
  // ownership enforced by an imported hook — name not visible to the linter
  hooks: { beforeValidate: [forceOwner] },
  fields: [
    { name: 'title', type: 'text' },
    { name: 'user', type: 'relationship', relationTo: 'users' },
    // "hashtags" must NOT match the "hash" sensitive-word check
    { name: 'hashtags', type: 'text', hasMany: true },
    // "tokenizer" must NOT match the "token" sensitive-word check
    { name: 'tokenizer', type: 'text' },
    // privileged field, but properly locked at field level
    {
      name: 'roles',
      type: 'select',
      hasMany: true,
      options: ['user', 'admin'],
      access: { update: ({ req }) => ((req.user as any)?.roles || []).includes('admin') },
    },
    // array rows legitimately carry their own `id`/`createdAt` — must NOT trip reserved-field-name
    {
      name: 'authorsPopulated',
      type: 'array',
      access: { update: () => false },
      fields: [
        { name: 'id', type: 'text' },
        { name: 'createdAt', type: 'text' },
      ],
    },
  ],
}

// A public global with imported access fn (identifier, not literal `true`)
const publicRead: Access = () => true
export const Header = {
  slug: 'header',
  access: { read: publicRead },
  fields: [{ name: 'logo', type: 'upload', relationTo: 'media' }],
}

// A raw-query projection: dotted keys are SQL aliases, NOT collection fields.
// reserved-field-name must NOT flag these (they aren't in a `fields:` array).
const projection = {
  columns: [
    { name: 'm.name', type: 'text' },
    { name: 's.clusterName', type: 'text' },
  ],
}
export const _projection = projection
