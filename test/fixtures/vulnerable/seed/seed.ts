// Intentionally a seed (system path) for payload-doctor self-tests.
import { getPayload } from 'payload'
import config from '../payload.config'

export async function seed() {
  const payload = await getPayload({ config })
  // hardcoded-secret in a seed = trusted system code -> info, not error
  const apiKey = 'sk_live_EXAMPLE_fixture_not_a_real_key'
  await payload.create({ collection: 'accounts', data: { email: 'seed@example.com' } as any, overrideAccess: true })
  return apiKey
}
