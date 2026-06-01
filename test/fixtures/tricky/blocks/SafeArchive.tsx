// Legitimate (async) React Server Component: reads published content with
// overrideAccess:false. payload-doctor should report ZERO findings here — this is the
// false-positive guard for the getPayload() request-context detection.
import { getPayload } from 'payload'
import config from '../payload.config'

export async function SafeArchive({ limit = 3 }: { limit?: number }) {
  const payload = await getPayload({ config })
  const { docs } = await payload.find({
    collection: 'articles',
    overrideAccess: false,
    where: { _status: { equals: 'published' } },
    limit,
  })
  return docs
}
