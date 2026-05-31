// Legitimate patterns — must produce ZERO findings.
import DOMPurify from 'dompurify'

export function SafeBody({ post }: { post: { content: string } }) {
  // sanitized -> safe, must not be flagged
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(post.content) }} />
}

export function StaticIcon() {
  // not CMS content, no rich-text signal -> not payload-doctor's concern
  const svg = '<svg viewBox="0 0 1 1"></svg>'
  return <span dangerouslySetInnerHTML={{ __html: svg }} />
}
