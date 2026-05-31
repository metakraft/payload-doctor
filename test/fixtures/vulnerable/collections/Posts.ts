// Intentionally insecure fixture for payload-doctor self-tests.
import type { CollectionConfig } from 'payload'

export const Posts: CollectionConfig = {
  slug: 'posts',
  // no `access` block at all -> collection-missing-access
  fields: [
    { name: 'title', type: 'text' },
    // relationTo users but no beforeValidate hook -> missing-owner-enforcement
    { name: 'user', type: 'relationship', relationTo: 'users' },
    // privileged field with no field-level update access -> user-writable-privileged-field
    { name: 'roles', type: 'select', hasMany: true, options: ['user', 'admin'] },
    // sensitive field readable via API -> token-field-readable
    { name: 'resetToken', type: 'text' },
  ],
}

export const Comments: CollectionConfig = {
  slug: 'comments',
  access: {
    read: () => true, // info: fully public read
    create: () => true, // error: anyone can write
    update: () => true, // error: anyone can write
    delete: () => true, // error: anyone can write
  },
  fields: [{ name: 'body', type: 'textarea' }],
}
