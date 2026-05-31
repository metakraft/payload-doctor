// A real collection (in /collections/) with inline blocks. The collection is
// properly access-controlled; the inline cta/media blocks must NOT be treated
// as collections. Expect zero findings.
import type { CollectionConfig, Access } from 'payload'

const publicRead: Access = () => true // referenced as an identifier, not inlined

export const Page: CollectionConfig = {
  slug: 'pages',
  access: { read: publicRead, create: ({ req }) => !!req.user, update: ({ req }) => !!req.user, delete: ({ req }) => !!req.user },
  fields: [
    {
      name: 'layout',
      type: 'blocks',
      blocks: [
        { slug: 'cta', fields: [{ name: 'label', type: 'text' }] },
        { slug: 'media', fields: [{ name: 'token', type: 'text' }] }, // 'token' on a block: not a secret field
      ],
    },
  ],
}
