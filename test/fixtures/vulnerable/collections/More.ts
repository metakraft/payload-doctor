// Intentionally broken fixture for payload-doctor self-tests.
import type { CollectionConfig } from 'payload'

// collection-missing-slug: typed as CollectionConfig but no slug
export const NoSlug: CollectionConfig = {
  fields: [{ name: 'title', type: 'text' }],
}

export const Widgets: CollectionConfig = {
  slug: 'widgets',
  hooks: {
    beforeChange: [
      ({ data, req }) => {
        // hook-missing-return: forgot to return data -> the change is dropped
        data.updatedBy = req.user?.id
      },
    ],
  },
  fields: [
    { name: 'title', type: 'text' },
    // admin-hidden-not-access: hidden in UI only, still returned by the API
    { name: 'internalNote', type: 'text', admin: { hidden: true } },
  ],
}

// duplicate-slug: 'tags' defined twice
export const Tags: CollectionConfig = {
  slug: 'tags',
  fields: [{ name: 'name', type: 'text' }],
}
export const TagsAgain: CollectionConfig = {
  slug: 'tags',
  fields: [{ name: 'label', type: 'text' }],
}
