import { render, screen, waitFor } from '@testing-library/svelte';
import { describe, expect, it } from 'vitest';
import { MockBackend } from '../src/lib/mock/backend';
import { HOSTILE_HOSTNAME, MOCK_PROJECT_ID, ip } from '../src/lib/mock/fixture';
import SafeMarkdown from '../src/lib/safe/SafeMarkdown.svelte';
import { ProjectStore } from '../src/lib/stores/project.svelte';
import Txt from '../src/lib/ui/Txt.svelte';
import HostDrawer from '../src/lib/views/HostDrawer.svelte';

function noActiveContent(root: ParentNode) {
  expect(root.querySelector('img[onerror], script, iframe, object, embed')).toBeNull();
  for (const el of Array.from(root.querySelectorAll('*'))) {
    for (const attr of Array.from(el.attributes)) {
      expect(attr.name.startsWith('on'), `${el.tagName} ${attr.name}`).toBe(false);
      expect(attr.name, el.tagName).not.toBe('style');
    }
  }
}

describe('Feindliche Zieldaten in der UI', () => {
  it('rendert einen Hostnamen mit HTML als Text', () => {
    const { container } = render(Txt, { props: { value: HOSTILE_HOSTNAME } });
    expect(container.querySelector('img')).toBeNull();
    expect(container.textContent).toContain(HOSTILE_HOSTNAME);
    noActiveContent(container);
  });

  it('macht Bidi- und Steuerzeichen sichtbar', () => {
    const { container } = render(Txt, { props: { value: 'Apache 2.4.\u202egnp.exe \u001b]0;x\u0007' } });
    expect(container.textContent).toContain('<U+202E>gnp.exe');
    expect(container.textContent).toContain('<ESC>]0;x<BEL>');
    expect(container.textContent).not.toContain('\u202e');
  });

  it('zeigt den feindlichen Host in der Host-Schublade nur als Text', async () => {
    const mock = new MockBackend({ latencyMs: 0, scripted: false });
    const project = new ProjectStore(MOCK_PROJECT_ID, mock);
    const { container } = render(HostDrawer, { props: { project, hostId: ip('10.10.10.9') } });
    await waitFor(() => expect(screen.getAllByText(HOSTILE_HOSTNAME).length).toBeGreaterThan(0));
    expect(container.querySelector('img')).toBeNull();
    noActiveContent(container);
    // Bidi-Zeichen aus der Service-Version erscheinen sichtbar ersetzt
    expect(container.textContent).toContain('<U+202E>gnp.exe');
    project.dispose();
  });

  it('SafeMarkdown führt kein HTML aus und lässt nur blob:-Bilder zu', () => {
    const source = [
      '# Titel',
      '<img src=x onerror=alert(1)>',
      '<script>alert(1)</script>',
      '[klick](javascript:alert(1))',
      '![extern](https://tracker.example/p.png)',
      '![lokal](blob:http://127.0.0.1:7330/abc)',
      '**fett** und `code`',
    ].join('\n\n');
    const { container } = render(SafeMarkdown, { props: { source } });
    const md = container.querySelector('.md')!;
    expect(md.querySelector('h1')?.textContent).toBe('Titel');
    expect(md.querySelector('script, a, iframe')).toBeNull();
    const imgs = Array.from(md.querySelectorAll('img'));
    expect(imgs).toHaveLength(1);
    expect(imgs[0]!.getAttribute('src')).toMatch(/^blob:/);
    expect(md.textContent).toContain('<img src=x onerror=alert(1)>');
    expect(md.textContent).toContain('<script>alert(1)</script>');
    noActiveContent(md);
  });
});
