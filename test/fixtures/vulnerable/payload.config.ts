// Intentionally insecure fixture for payload-doctor self-tests.
import { buildConfig } from 'payload'

export default buildConfig({
  // hardcoded-secret -> error
  secret: 'super-secret-value-1234',
  // wide-open-cors -> warning
  cors: '*',
  collections: [],
})
