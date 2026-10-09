/**
 * Seitenweiser Cache für bereinigte Logzeilen (GET /streams/{tid}/lines).
 * Lange Ausgaben (linpeas) werden nur seitenweise geladen; die virtuelle Liste
 * fragt Zeilen einzeln ab.
 */
import type { LogLine } from '../api/types';
import type { ProjectStore } from './project.svelte';

export const PAGE = 400;

export class LinesCache {
  total = $state<number | null>(null);
  pages = $state.raw<Record<number, LogLine[]>>({});
  error = $state<string | null>(null);
  private loading = new Set<number>();
  private readonly project: ProjectStore;
  readonly terminalId: string;
  readonly unitId: string | null;
  readonly revealHidden: boolean;

  constructor(project: ProjectStore, terminalId: string, unitId: string | null, revealHidden: boolean) {
    this.project = project;
    this.terminalId = terminalId;
    this.unitId = unitId;
    this.revealHidden = revealHidden;
  }

  async ensure(page: number): Promise<void> {
    if (page < 0 || this.pages[page] || this.loading.has(page)) return;
    if (this.total !== null && page * PAGE >= this.total) return;
    this.loading.add(page);
    try {
      const res = await this.project.backend.streamLines(
        this.project.pid,
        this.terminalId,
        { unit: this.unitId ?? undefined, from: page * PAGE, count: PAGE, reveal_hidden: this.revealHidden },
        this.project.signal,
      );
      this.total = res.total;
      this.pages = { ...this.pages, [page]: res.lines };
    } catch {
      this.error = 'load';
    } finally {
      this.loading.delete(page);
    }
  }

  /** Zeile i, oder null (dann wird die Seite nachgeladen). */
  line(i: number): LogLine | null {
    const page = Math.floor(i / PAGE);
    const p = this.pages[page];
    if (!p) {
      queueMicrotask(() => void this.ensure(page));
      return null;
    }
    return p[i - page * PAGE] ?? null;
  }

  /** Alle Zeilen eines Bereichs (lädt nötige Seiten nach). */
  async range(from: number, to: number): Promise<LogLine[]> {
    for (let p = Math.floor(from / PAGE); p <= Math.floor(to / PAGE); p++) await this.ensure(p);
    const out: LogLine[] = [];
    for (let i = from; i <= to; i++) {
      const l = this.pages[Math.floor(i / PAGE)]?.[i % PAGE];
      if (l) out.push(l);
    }
    return out;
  }
}
