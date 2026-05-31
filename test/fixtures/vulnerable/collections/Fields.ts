// Intentionally broken fixture for payload-doctor self-tests.
import type { CollectionConfig } from 'payload'

export const Gadgets: CollectionConfig = {
  slug: 'gadgets',
  access: { read: ({ req }) => Boolean(req.user) },
  fields: [
    // relationship-missing-relationTo
    { name: 'owner', type: 'relationship' },
    // select-without-options
    { name: 'status', type: 'select' },
    { name: 'title', type: 'text' },
    // duplicate-field-name (collides with 'title' above)
    { name: 'title', type: 'textarea' },
  ],
}
