// Secure reference fixture for payload-doctor self-tests.
import { NextResponse } from 'next/server'

export async function POST(req: Request) {
  const cronSecret = process.env.CRON_SECRET
  // fail closed: no secret configured -> endpoint is closed
  if (!cronSecret) {
    return NextResponse.json({ error: 'Server misconfigured' }, { status: 500 })
  }
  if (req.headers.get('authorization') !== `Bearer ${cronSecret}`) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }
  return NextResponse.json({ ok: true })
}
