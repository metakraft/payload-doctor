// Intentionally broken fixture: a public (async) React Server Component reads via the
// Local API WITHOUT overrideAccess:false, so access control is bypassed and unpublished
// / draft posts can leak to anonymous visitors. payload-doctor must flag this.
import { getPayload } from 'payload'
import config from '../payload.config'

export async function ArchiveBlock({ limit = 3 }: { limit?: number }) {
  const payload = await getPayload({ config })
  const { docs } = await payload.find({ collection: 'posts', limit })
  return docs
}
