// Secure reference fixture for payload-doctor self-tests.
import { NextResponse } from 'next/server'
import { getPayload } from 'payload'
import config from '../../../payload.config'

export async function POST(req: Request) {
  const payload = await getPayload({ config })
  const { user } = await payload.auth({ headers: req.headers })
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

  const { id, data } = await req.json()

  // access control enforced + user passed
  const doc = await payload.findByID({
    collection: 'posts',
    id,
    overrideAccess: false,
    user,
  })

  const ownerId = typeof doc.user === 'object' ? doc.user.id : doc.user
  const roles = (user as any).roles || []
  if (String(ownerId) !== String(user.id) && !roles.includes('admin')) {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  }

  await payload.update({
    collection: 'posts',
    id,
    data,
    overrideAccess: false,
    user,
  })

  try {
    return NextResponse.json({ ok: true })
  } catch (error: any) {
    console.error('update failed', error)
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
}
