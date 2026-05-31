// Intentionally unsafe fixture for payload-doctor self-tests.
import RichText from '@payloadcms/richtext-lexical/react'

export function PostBody({ post }: { post: { content: string } }) {
  // unsafe: CMS rich-text rendered without sanitization -> stored XSS risk
  return <div dangerouslySetInnerHTML={{ __html: post.content }} />
}
