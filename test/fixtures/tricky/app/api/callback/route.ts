// OAuth providers redirect via GET, so this callback legitimately writes on GET.
// We suppress the protocol-mandated finding for the whole file, and the
// system-write override for a single line, demonstrating both directives.
// payload-doctor-disable side-effect-in-get
import { NextResponse } from 'next/server'
import { getPayload } from 'payload'
import config from '../../../payload.config'

export async function GET(req: Request) {
  const payload = await getPayload({ config })
  // payload-doctor-disable-next-line local-api-override-access
  await payload.create({ collection: 'sessions', data: { provider: 'oauth' } })
  return NextResponse.json({ ok: true })
}
