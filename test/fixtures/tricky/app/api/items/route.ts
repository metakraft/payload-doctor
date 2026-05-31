// Legitimate patterns that previously risked false positives.
// payload-doctor should report ZERO findings here.
import { NextResponse } from 'next/server'
import { getPayload } from 'payload'
import config from '../../../payload.config'

const baseOpts = { overrideAccess: false as const }

export async function POST(req: Request) {
  const payload = await getPayload({ config })
  const { user } = await payload.auth({ headers: req.headers })
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

  const { id, data } = await req.json()

  // spread carries overrideAccess:false — must NOT be flagged
  await payload.update({ ...baseOpts, collection: 'articles', id, data, user })

  // static error string — must NOT trigger leaks-error-message
  if (!id) return NextResponse.json({ error: 'Missing id' }, { status: 400 })

  return NextResponse.json({ ok: true })
}

// A GET that only reads (no mutation) with access control — must NOT trigger side-effect-in-get
export async function GET(req: Request) {
  const payload = await getPayload({ config })
  const { user } = await payload.auth({ headers: req.headers })
  const result = await payload.find({
    collection: 'articles',
    overrideAccess: false,
    user: user ?? undefined,
  })
  return NextResponse.json(result)
}
