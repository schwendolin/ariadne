# Ariadne Web-UI

Das Cockpit von Ariadne: REC-Knopf, Karte, Inbox, Terminals, Zeitachse, Denkanstösse, Findings und Belegansicht. Svelte 5, TypeScript, Vite und Cytoscape.js mit fcose. Der Daemon liefert die gebaute UI aus `src/ariadne/web/static/` aus (Architektur 7.1).

Stand: Gerüst, funktional mit Mock-Daten, optisch schlicht. Das Feindesign folgt nach dem Brainstorming. Die HTTP-Schnittstelle ist ein Entwurf: [docs/web-api.md](../docs/web-api.md).

## Befehle

Node 22.12 oder neuer. Alle Versionen sind exakt gepinnt, `package-lock.json` ist Pflicht.

| Befehl | Zweck |
|---|---|
| `npm ci --ignore-scripts` | Abhängigkeiten aus dem Lockfile, ohne Install-Skripte |
| `npm run dev` | Dev-Server auf `127.0.0.1:5173`. Leitet `/api` an den Daemon (`ARIADNE_DAEMON_URL`, Standard `http://127.0.0.1:7330`). Ist kein Daemon erreichbar, schaltet die UI selbst auf Mock |
| `npm run dev:mock` | Dev-Server immer mit Mock-Daten |
| `npm run build` | Produktions-Build nach `../src/ariadne/web/static/` (gitignored), ohne Mock-Code |
| `npm run build:mock` | Build mit Mock-Daten nach `dist/` (gitignored), für Vorführung und Playwright |
| `npm run preview:mock` | `dist/` auf `127.0.0.1:4173` ausliefern, mit derselben CSP wie der Daemon |
| `npm run check` | `svelte-check`, Warnungen gelten als Fehler |
| `npm run lint` | ESLint mit den Sicherheitsregeln |
| `npm test` | Vitest (jsdom) |

Hinweis zum Lockfile: `npm install` mit npm 10.9 bricht in diesem Abhängigkeitsbaum mit einem Arborist-Fehler ab (`edgesOut`). Das Lockfile wurde deshalb mit `npx npm@11.6.2 install --ignore-scripts` erzeugt. `npm ci` funktioniert mit npm 10 und 11.

## Mock-Modus

Der Mock bildet die API aus `docs/web-api.md` nach (`src/lib/mock/`), die UI merkt keinen Unterschied.

- Aktiv mit `--mode mock` (Datei `.env.mock`), mit `VITE_ARIADNE_MOCK=1` oder automatisch im Dev-Server, wenn `/api/v1/status` nicht mit JSON antwortet.
- Beispielprojekt «lame»: Scope `10.10.10.0/24` und `10.10.20.0/24` hinter einem Pivot, Hosts im Stil von HTB Lame und Metasploitable2, Faden mit vier Schlüsselschritten, Nebel, ein Konflikt, KI-Werte, Out-of-Scope.
- Absichtlich feindliche Werte: Hostname `<img src=x onerror=alert(1)>`, RLO-Zeichen (U+202E) in einer Version, Escape-Sequenzen in einem Banner, ein Banner mit Anweisungen an Sprachmodelle.
- Die Tool-Ausgaben werden erzeugt, und jeder Fakt zeigt auf seine Zeilen. Die Belegansicht funktioniert deshalb auch im Mock, inklusive einer langen linpeas-Ausgabe für die virtuelle Liste.
- Simulierte SSE-Ereignisse nach dem Start: nach 6 s ein neuer Host im Nebel, nach 12 s ein Denkanstoss, nach 20 s ein Befehl. Entscheide (bestätigen, Arbeitsstand, Tags, Notizen ...) ändern den Mock-Zustand und lösen dieselben Ereignisse aus wie der Daemon.
- Kartenpositionen speichert der Mock im `localStorage` dieses Browsers, der Daemon später in `state.db`.

## Sicherheitsregeln

Zieldaten sind feindlich (Architektur 7.7, 9.2). Die Regeln sind technisch erzwungen, nicht nur dokumentiert.

| Regel | Durchsetzung |
|---|---|
| Kein HTML aus Strings | ESLint verbietet `{@html}` (`svelte/no-at-html-tags`), `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `srcdoc`, `setHTMLUnsafe` und Optionen wie `allowHTML: true` oder `html: true` |
| Einzige Ausnahme Markdown | `src/lib/safe/SafeMarkdown.svelte`: markdown-it mit `html: false`, Links und Bilder nur `blob:`, danach DOMPurify mit enger Allowlist, Ergebnis als DocumentFragment. `dompurify` und `markdown-it` dürfen nirgends sonst importiert werden |
| Unsichtbare Zeichen sichtbar | `displaySafe(text, max)` in `src/lib/safe/displaySafe.ts`, gleiche Semantik wie `src/ariadne/termsafe.py`: C0, C1, DEL, Bidi-, Zero-Width- und Tag-Zeichen werden zu `<ESC>`, `<0x01>`, `<U+202E>`, danach Kürzung. Alle Ziel-Strings laufen über die Komponente `Txt.svelte` bzw. `displaySafe` |
| CSP ohne Ausnahmen | Kein Inline-Skript, kein Inline-Style, keine `data:`-URIs (`assetsInlineLimit: 0`). Dynamische Werte nur als CSS-Variablen per CSSOM (Action `styleProps`); `svelte/no-inline-styles` verbietet Style-Attribute. `vite preview` setzt die CSP des Daemons |
| Token nur in sessionStorage | `src/lib/api/auth.ts`. `localStorage` ist nur über `src/lib/util/prefs.ts` erreichbar (Theme, Ebenen, Lernmodus, Mock-Positionen), per ESLint erzwungen |
| Keine fremden Ressourcen | keine CDN, keine Webfonts, nur Systemschriften; `connect-src 'self'` |
| Karte nur Text | Cytoscape zeichnet auf Canvas, Labels sind nie HTML. Status steht nie nur in der Farbe (`#` admin/root, `$` user, Arbeitsstand als Wort) |
| Befehle nur vom Server | Denkanstösse zeigen fertig gerenderte Befehle, Anteile aus Zieldaten markiert, Kopieren ohne Zeilenumbruch, kein Ausführen-Knopf |
| Quelltext ohne Trojan Source | ein Test findet rohe Bidi- und Zero-Width-Zeichen im Quelltext; Testwerte stehen als `\u`-Escape |

**Ausnahme für Cytoscape:** Cytoscape legt beim Start ein `<style>`-Element an, das `style-src 'self'` blockieren würde. `src/lib/map/csp.ts` legt vorher ein Platzhalter-Element mit derselben ID an, die eine Regel (`position: relative`) steht in `src/app.css`. Alle übrigen Styles setzt Cytoscape per CSSOM, das die CSP nicht betrifft. Svelte 5 kommt ohne Inline-Styles aus: Komponenten-CSS landet in einer Datei, und Übergänge laufen über die Web Animations API (das Gerüst nutzt noch keine). Ergebnis im Playwright-Lauf gegen `vite preview`: keine `securitypolicyviolation`, keine `<style>`-Elemente im DOM.

## Struktur

```
webui/
  index.html              # nur ein externes Modul, kein Inline-Skript
  vite.config.ts          # Build, Dev-Proxy, Preview mit CSP, Vitest
  eslint.config.js        # Sicherheitsregeln
  src/
    main.ts  App.svelte  app.css
    theme/tokens.css      # Theme-Tokens hell und dunkel, inkl. Farbgrammatik der Karte (--map-*)
    lib/
      api/                # types.ts (Vertrag), client.ts, sse.ts, auth.ts, backend.ts, select.ts
      mock/               # fixture.ts (Projekt lame), backend.ts, graph.ts
      stores/             # app.svelte.ts, project.svelte.ts (pro Projekt), lines.svelte.ts
      router.svelte.ts    # History-Router: /karte /inbox /terminals /zeitachse /denkanstoesse /findings
      i18n/               # t(), de.ts (Standard)
      safe/               # displaySafe.ts, SafeMarkdown.svelte
      map/                # MapCanvas.svelte, elements.ts, theme.ts, csp.ts
      shell/              # Header, RecButton, Lagebild, Nav, LoginView
      views/              # Karte, Inbox, Terminals, Zeitachse, Denkanstösse, Findings, Host-Detail, Belegansicht
      ui/                 # Txt, Badge, VirtualList, LogLineView, Breadcrumbs, Aktionen
      util/               # prefs, time, theme, errors, labels, evidence
  tests/                  # Vitest: displaySafe, API-Client, SSE, Mock-Daten, Store-Reset, feindliche Werte, Lint-Regeln
```

**Datenfluss.** Die Stores lesen nur über das `Backend`-Interface (`HttpBackend` oder `MockBackend`). SSE meldet nur Invalidierungen; der Projekt-Store lädt danach gezielt per REST (`/changes?since=`). Beim Ereignis `project` verwirft die App den Projekt-Store komplett: Abrufe abgebrochen, Blob-URLs freigegeben, Ansichten per `{#key}` neu aufgebaut. Schreiben geht nur über Entscheide (`POST /decisions`) und Kontext-Änderungen (`POST /terminals/{tid}/context`).

**Texte.** Alle UI-Texte stehen in `src/lib/i18n/de.ts` (Schweizer Rechtschreibung, Fachbegriffe englisch). `t()` ist typisiert, fehlende Schlüssel fallen in `npm run check` auf.
