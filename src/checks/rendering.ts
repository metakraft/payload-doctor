import { Node, SyntaxKind } from 'ts-morph'
import type { Check, Finding } from '../types'
import { makeFinding } from '../util'

// Signals that a file deals with Payload rich text / CMS HTML.
const CMS_IMPORT =
  /(@payloadcms\/richtext|richtext-lexical|\blexical\b|serializeLexical|slate|RichText|from ['"]payload)/i
// Signals that the rendered expression is CMS content.
const CMS_NAME = /(richtext|\bcontent\b|\bbody\b|\bhtml\b|lexical|serialized|\bblocks?\b|\bdescription\b)/i
// Signals the HTML is already sanitized.
const SANITIZED = /sanitize|dompurify|\bpurify\b|clean\s*\(/i

function htmlExpressionText(attr: Node): string {
  if (!Node.isJsxAttribute(attr)) return ''
  const init = attr.getInitializer()
  if (!init || !Node.isJsxExpression(init)) return ''
  const inner = init.getExpression()
  if (!inner) return ''
  if (Node.isObjectLiteralExpression(inner)) {
    const p = inner.getProperty('__html')
    if (p && Node.isPropertyAssignment(p)) return p.getInitializer()?.getText() ?? ''
    return inner.getText()
  }
  return inner.getText()
}

/**
 * The block-render seam: rendering Payload rich text / block HTML into React
 * (often shadcn/ui) via dangerouslySetInnerHTML without sanitization is a stored
 * XSS risk when the source content is user-writable. We only flag cases that
 * look like CMS content (otherwise it's a generic React concern for react-doctor).
 */
const unsafeRichtextRender: Check = {
  id: 'unsafe-richtext-render',
  category: 'rendering',
  describe: 'dangerouslySetInnerHTML renders CMS/rich-text content without sanitization',
  run(file, ctx) {
    const findings: Finding[] = []
    const fileText = file.getFullText()
    const importSignal = CMS_IMPORT.test(fileText)

    for (const attr of file.getDescendantsOfKind(SyntaxKind.JsxAttribute)) {
      if (attr.getNameNode().getText() !== 'dangerouslySetInnerHTML') continue
      const html = htmlExpressionText(attr)
      if (SANITIZED.test(html)) continue // already sanitized
      // only flag when it clearly handles CMS/rich-text content
      if (!importSignal && !CMS_NAME.test(html)) continue
      findings.push(
        makeFinding(
          attr,
          ctx,
          'unsafe-richtext-render',
          'rendering',
          'info',
          'dangerouslySetInnerHTML renders rich-text/CMS HTML — review this sink: a static tool cannot tell whether the source is sanitized',
          'If the HTML can ever come from user input, sanitize it (e.g. DOMPurify) and restrict write access to the source collection.',
        ),
      )
    }
    return findings
  },
}

export const renderingChecks: Check[] = [unsafeRichtextRender]
