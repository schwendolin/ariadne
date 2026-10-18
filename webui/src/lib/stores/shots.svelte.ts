/**
 * Screenshots des Projekts (Entwurf api-screenshots). Besitzer: ui.
 *
 * - `/screenshots` beim Öffnen und nach den Ereignissen `screenshot`, `presentation`, `reset`.
 * - Bilder kommen über `GET /blobs/{id}` mit Token im Header und werden als `blob:`-URL gezeigt
 *   (die CSP erlaubt `img-src 'self' blob:`); nur PNG, JPEG und WebP, sonst kein Bild.
 * - Präsentationsmodus: keine Abrufe der Bilder, die Oberfläche zeigt «verdeckt» (der Server
 *   antwortet ohnehin 403). Beim Einschalten werden alle `blob:`-URLs sofort verworfen.
 */
import type { Screenshot, StreamEvent } from '../api/types';
import { isAbort } from '../util/errors';
import type { ProjectCtx, ProjectPart } from './ctx';

const IMAGE_TYPES = new Set(['image/png', 'image/jpeg', 'image/webp']);

/** Magic-Bytes: PNG, JPEG oder WebP (nie SVG oder HTML). */
export async function isImageBlob(b: Blob): Promise<string | null> {
  const head = new Uint8Array(await b.slice(0, 12).arrayBuffer());
  const at = (i: number) => head[i] ?? -1;
  if (at(0) === 0x89 && at(1) === 0x50 && at(2) === 0x4e && at(3) === 0x47) return 'image/png';
  if (at(0) === 0xff && at(1) === 0xd8 && at(2) === 0xff) return 'image/jpeg';
  if (at(0) === 0x52 && at(1) === 0x49 && at(2) === 0x46 && at(3) === 0x46 && at(8) === 0x57 && at(9) === 0x45 && at(10) === 0x42 && at(11) === 0x50) return 'image/webp';
  return null;
}

export class ShotsStore implements ProjectPart {
  items = $state.raw<Screenshot[]>([]);
  loaded = $state(false);
  private urls = new Map<string, Promise<string | null>>();
  private made: string[] = [];
  private timer: ReturnType<typeof setTimeout> | null = null;

  constructor(private readonly ctx: ProjectCtx) {}

  get presentation(): boolean {
    return this.ctx.app.presentation;
  }

  async load(): Promise<void> {
    try {
      const v = await this.ctx.backend.screenshots(this.ctx.pid, this.ctx.signal);
      this.items = v.items;
      if (v.presentation) this.revokeAll();
    } catch (e) {
      if (!isAbort(e)) this.items = this.items ?? [];
    }
    this.loaded = true;
  }

  byId(id: string): Screenshot | null {
    return this.items.find((s) => s.id === id) ?? null;
  }

  /** Screenshots eines Hosts (Adresse der obersten Kontextstufe bei der Aufnahme). */
  forHost(addresses: readonly string[]): Screenshot[] {
    const set = new Set(addresses);
    return this.items.filter((s) => s.host !== null && set.has(s.host));
  }

  /** `blob:`-URL eines Bildes oder `null` (Präsentation, Fehler, kein Bild). */
  image(blobId: string): Promise<string | null> {
    if (this.presentation) return Promise.resolve(null);
    let p = this.urls.get(blobId);
    if (!p) {
      p = this.fetchImage(blobId);
      this.urls.set(blobId, p);
      // Fehlschläge nicht merken: beim nächsten Mal erneut versuchen
      void p.then((u) => {
        if (u === null) this.urls.delete(blobId);
      });
    }
    return p;
  }

  private async fetchImage(blobId: string): Promise<string | null> {
    try {
      const b = await this.ctx.backend.blob(this.ctx.pid, blobId, this.ctx.signal);
      const type = await isImageBlob(b);
      if (!type || (b.type && !IMAGE_TYPES.has(b.type.split(';')[0]?.trim() ?? ''))) return null;
      if (this.presentation || this.ctx.signal.aborted) return null;
      const u = URL.createObjectURL(new Blob([b], { type }));
      this.made.push(u);
      return u;
    } catch {
      return null;
    }
  }

  private revokeAll(): void {
    for (const u of this.made) URL.revokeObjectURL(u);
    this.made = [];
    this.urls.clear();
  }

  onEvent(ev: StreamEvent): void {
    if (ev.name === 'presentation') {
      if (ev.data.on) this.revokeAll();
      this.reloadSoon();
    } else if (ev.name === 'screenshot') {
      if (ev.data.project_id === this.ctx.pid) this.reloadSoon();
    }
  }

  private reloadSoon(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = setTimeout(() => {
      this.timer = null;
      void this.load();
    }, 200);
  }

  dispose(): void {
    if (this.timer) clearTimeout(this.timer);
    this.revokeAll();
  }
}
