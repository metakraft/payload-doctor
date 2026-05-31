// A Payload block shares the { slug, fields } shape with a collection but must
// NOT trigger collection-level checks. payload-doctor should stay silent here.
import type { Block } from 'payload'

export const HeroBlock: Block = {
  slug: 'hero',
  interfaceName: 'HeroBlock',
  fields: [
    { name: 'heading', type: 'text' },
    { name: 'roles', type: 'text' }, // a 'roles' field on a BLOCK is not a privilege
  ],
}
