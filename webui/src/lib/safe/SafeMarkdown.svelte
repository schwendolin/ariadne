<!--
  Einzige Stelle, an der aus Text HTML wird (Architektur 7.7): Notizen als Markdown.

  1. markdown-it mit html:false: rohes HTML im Text wird escapt, nicht ausgeführt.
  2. Links und Bilder nur mit blob:-URL (validateLink). Ziel-URLs werden nie klickbar.
  3. DOMPurify mit enger Allowlist, ohne style- und Event-Attribute, ohne <a>.
     Bilder ohne blob:-Quelle werden entfernt (img-src der CSP: 'self' blob:).
  4. Ergebnis als DocumentFragment per replaceChildren, kein innerHTML im eigenen Code.
-->
<script module lang="ts">
  import DOMPurify from 'dompurify';
  import MarkdownIt from 'markdown-it';

  const md = new MarkdownIt({ html: false, linkify: false, typographer: false, breaks: false });
  md.validateLink = (url: string) => /^blob:/i.test(url.trim());

  const ALLOWED_TAGS = [
    'p', 'br', 'strong', 'em', 'del', 's', 'code', 'pre', 'ul', 'ol', 'li', 'blockquote',
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'hr', 'table', 'thead', 'tbody', 'tr', 'th', 'td', 'img',
  ];
  const ALLOWED_ATTR = ['src', 'alt', 'title', 'start'];

  let hooked = false;
  function ensureHook(): void {
    if (hooked) return;
    hooked = true;
    DOMPurify.addHook('afterSanitizeAttributes', (node) => {
      if (node.nodeName === 'IMG') {
        const src = node.getAttribute('src') ?? '';
        if (!/^blob:/i.test(src)) node.remove();
      }
    });
  }

  export function renderMarkdown(source: string): DocumentFragment {
    ensureHook();
    const html = md.render(source);
    return DOMPurify.sanitize(html, {
      ALLOWED_TAGS,
      ALLOWED_ATTR,
      ALLOW_DATA_ATTR: false,
      ALLOW_ARIA_ATTR: false,
      FORBID_ATTR: ['style'],
      FORBID_TAGS: ['style', 'script', 'a', 'svg', 'math', 'iframe', 'form'],
      RETURN_DOM_FRAGMENT: true,
    });
  }
</script>

<script lang="ts">
  let { source }: { source: string } = $props();

  function markdown(node: HTMLElement, src: string) {
    node.replaceChildren(renderMarkdown(src));
    return {
      update(next: string) {
        node.replaceChildren(renderMarkdown(next));
      },
    };
  }
</script>

<div class="md" use:markdown={source}></div>

<style>
  .md :global(p) {
    margin: 0 0 8px;
  }
  .md :global(ul),
  .md :global(ol) {
    margin: 0 0 8px;
    padding-left: 20px;
  }
  .md :global(code) {
    background: var(--surface-2);
    padding: 0 3px;
    border-radius: 3px;
  }
  .md :global(pre) {
    background: var(--surface-2);
    padding: 8px;
    border-radius: var(--radius);
    overflow: auto;
  }
  .md :global(img) {
    max-width: 100%;
  }
</style>
