// Intentionally insecure fixture for payload-doctor self-tests.
import { NextResponse } from 'next/server'

export async function POST(req: Request) {
  const cronSecret = process.env.CRON_SECRET
  const authHeader = req.headers.get('authorization')

  // cron-not-fail-closed: if CRON_SECRET is unset, the guard is skipped -> error
  if (cronSecret && authHeader !== `Bearer ${cronSecret}`) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  // ... run the job ...
  return NextResponse.json({ ok: true })
}
