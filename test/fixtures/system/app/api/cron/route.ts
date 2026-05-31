// A correctly secured server-side cron job. The Local API write uses an
// explicit overrideAccess:true with NO user — an intentional system write.
// payload-doctor should report this as INFO, never an error.
import { NextResponse } from 'next/server'
import { getPayload } from 'payload'
import config from '../../../payload.config'

export async function POST(req: Request) {
  const cronSecret = process.env.CRON_SECRET
  if (!cronSecret) {
    return NextResponse.json({ error: 'Server misconfigured' }, { status: 500 })
  }
  if (req.headers.get('authorization') !== `Bearer ${cronSecret}`) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  const payload = await getPayload({ config })
  await payload.update({
    collection: 'jobs',
    id: '1',
    data: { ranAt: new Date().toISOString() },
    overrideAccess: true,
  })

  return NextResponse.json({ ok: true })
}
