// Intentionally broken fixture for payload-doctor self-tests.
import { getPayload } from 'payload'
import config from '../payload.config'

export async function enrich(ids: string[]) {
  const payload = await getPayload({ config })
  const results = []
  for (const id of ids) {
    // hook-n-plus-one (warning): fixed collection, batchable
    const doc = await payload.findByID({ collection: 'accounts', id })
    // sensitive-data-logged: leaks the password into logs
    console.error('login failed for', doc.password)
    results.push(doc)
  }
  return results
}

export async function enrichDynamic(items: { type: string; id: string }[]) {
  const payload = await getPayload({ config })
  for (const item of items) {
    // hook-n-plus-one (info): dynamic collection per item, not trivially batchable
    await payload.find({ collection: item.type, where: { id: { equals: item.id } } })
  }
}
