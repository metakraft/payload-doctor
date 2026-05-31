// Intentionally broken fixture for payload-doctor self-tests.
import type { CollectionConfig } from 'payload'

export const Accounts: CollectionConfig = {
  slug: 'accounts',
  // auth-weak-config: lockout disabled + 30+ day token
  auth: { maxLoginAttempts: 0, tokenExpiration: 99999999 },
  // open registration -> mass-assignment risk on privileged fields below
  access: { create: () => true },
  fields: [
    // missing-index-on-filter-field (info)
    { name: 'email', type: 'email' },
    // reserved-field-name: Payload owns createdAt
    { name: 'createdAt', type: 'date' },
    // mass-assignment: privileged field, update-gated but settable on create
    {
      name: 'roles',
      type: 'select',
      hasMany: true,
      defaultValue: ['member'],
      options: [
        { label: 'Member', value: 'member' },
        { label: 'Admin', value: 'admin' },
      ],
      access: { update: ({ req }: any) => req.user?.roles?.includes('admin') },
    },
    // excessive-max-depth + part of a cycle (accounts -> orgs)
    { name: 'org', type: 'relationship', relationTo: 'orgs', maxDepth: 20 },
  ],
}

export const Orgs: CollectionConfig = {
  slug: 'orgs',
  fields: [
    // circular-relationship: orgs -> accounts -> orgs
    { name: 'lead', type: 'relationship', relationTo: 'accounts' },
  ],
}
