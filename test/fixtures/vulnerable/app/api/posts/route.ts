// Intentionally insecure fixture for payload-doctor self-tests.
import { NextResponse } from 'next/server'
import { getPayload } from 'payload'
import config from '../../../payload.config'

export async function GET(req: Request) {
  const payload = await getPayload({ config })
  const { searchParams } = new URL(req.url)
  const id = searchParams.get('id') as string

  // local-api-override-access (read, in request file) -> warning
  const doc = await payload.findByID({ collection: 'posts', id })

  // side-effect-in-get + local-api-override-access (mutation) -> error x2
  await payload.update({
    collection: 'posts',
    id,
    data: { title: 'touched-by-get' },
  })

  try {
    return NextResponse.json({ doc })
  } catch (error: any) {
    // leaks-error-message -> warning
    return NextResponse.json({ error: error.message }, { status: 500 })
  }
}
