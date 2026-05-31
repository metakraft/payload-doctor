// Secure reference fixture for payload-doctor self-tests.
import type { CollectionConfig, Access } from 'payload'

const isAdmin = (user: any): boolean => !!user?.roles?.includes('admin')

const ownerOrAdmin: Access = ({ req: { user } }) => {
  if (!user) return false
  if (isAdmin(user)) return true
  return { user: { equals: user.id } }
}

const authenticated: Access = ({ req: { user } }) => !!user

export const Posts: CollectionConfig = {
  slug: 'posts',
  access: {
    read: ownerOrAdmin,
    create: authenticated,
    update: ownerOrAdmin,
    delete: ownerOrAdmin,
  },
  hooks: {
    beforeValidate: [
      ({ data, req, operation }) => {
        if (operation === 'create' && req.user && !isAdmin(req.user)) {
          data.user = req.user.id
        }
        return data
      },
    ],
  },
  fields: [
    { name: 'title', type: 'text' },
    { name: 'user', type: 'relationship', relationTo: 'users' },
    {
      name: 'roles',
      type: 'select',
      hasMany: true,
      options: ['user', 'admin'],
      access: { update: ({ req }) => isAdmin(req.user) },
    },
    {
      name: 'resetToken',
      type: 'text',
      access: { read: () => false },
    },
  ],
}
