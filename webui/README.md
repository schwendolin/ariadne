# Ariadne Web-UI

Die Oberfläche v0.1 von Ariadne nach dem Design in `docs/ui/design-v01/` (SCREENS, BEHAVIOR, Tokens): Kopfzeile mit Aufnahme, Karte mit Lagebild und Out of Scope, Spalte «Als Nächstes», Host-Detail, Terminals, Zeitachse mit Warteliste, Belegansicht, Findings, Anmeldung und Zustände. Svelte 5, TypeScript, Vite, Cytoscape.js mit fcose. Der Daemon liefert die gebaute UI aus `src/ariadne/web/static/` aus (Architektur 7.1). Die Schnittstelle steht in [docs/web-api.md](../docs/web-api.md), die Ergänzungen für diese Oberfläche in Abschnitt 18.

Stand: Gerüst aus dem Bau v0.1 (Phase 1). Fundament (Shell, Stores, API-Client, SSE, Tastatur, URL-Zustand, gemeinsame Bausteine, Mock) steht; Karte, Spalte, Terminals, Zeitachse, Belegansicht und Findings sind Gerüste mit Props und Typen, die die Bau-Agenten «ui-karte» und «ui-verlauf» ausbauen.

## Befehle

Node 22.12 oder neuer. Alle Versionen sind exakt gepinnt, `package-lock.json` ist Pflicht.

| Befehl | Zweck |
|---|---|
| `npm ci --ignore-scripts` | Abhängigkeiten aus dem Lockfile, ohne Install-Skripte |
| `npm run dev` | Dev-Server auf `127.0.0.1:5173`. Leitet `/api` an den Daemon (`ARIADNE_DAEMON_URL`, Standard `http://127.0.0.1:7330`). Ist kein Daemon erreichbar, schaltet die UI selbst auf Mock |
| `npm run dev:mock` | Dev-Server immer mit Mock-Daten |
| `npm run build` | Produktions-Build nach `../src/ariadne/web/static/` (gitignored), ohne Mock-Code |
| `npm run build:mock` | Build mit Mock-Daten nach `dist/` (gitignored) |
| `npm run preview:mock` | `dist/` auf `127.0.0.1:4173` ausliefern, mit derselben CSP wie der Daemon |
| `npm run check` | `svelte-check`, Warnungen gelten als Fehler |
| `npm run lint` | ESLint mit den Sicherheitsregeln |
| `npm test` | Vitest (jsdom) |
| `npm run test:e2e` | Playwright gegen den Mock-Build unter der Daemon-CSP (`*.mock.spec.ts`) |
| `npm run test:e2e:daemon` | Playwright gegen einen echten Daemon mit Fixture-Projekt MS2 (`*.daemon.spec.ts`, braucht `../.venv`) |
| `npm run test:e2e:all` | beides |
| `npm run shots` | Screenshots je Screen bei 1440x900, dunkel und hell, nach `.e2e/shots/` (Augenprüfung gegen die Design-Shots) |

Browsertests: Playwright 1.56.1 mit dem vorhandenen Chromium (`/opt/pw-browsers/chromium-1194/chrome-linux/chrome`, überschreibbar mit `ARIADNE_CHROMIUM`). Nie `playwright install`. Freie Ports wählt `playwright.config.ts` selbst. Jeder Browsertest scheitert, sobald die Seite eine CSP-Verletzung, einen Seitenfehler oder ein `<style>`-Element mit Inhalt meldet (`e2e/fixtures.ts`, mit Selbsttest in `e2e/fundament/guard.mock.spec.ts`).

Der Daemon für `test:e2e:daemon` ist `tests/e2e/ui_fixture.py`: eigener Wegwerf-Ordner für HOME und XDG, Projekt `ms2` mit Scope `192.168.56.0/24`, nmap-Golden gegen .101, msf-Sitzung, Listener mit gefälschtem Callback, Eingabe ohne Echo, Entscheide wie im Standbild. Den Anmeldecode holt der Test über `ctl.sock` und öffnet `/#c=<code>` wie die Startdatei.

Hinweis zum Lockfile: `npm install` mit npm 10.9 bricht in diesem Abhängigkeitsbaum mit einem Arborist-Fehler ab (`edgesOut`). Das Lockfile wurde deshalb mit `npx npm@11.6.2 install --ignore-scripts` erzeugt. `npm ci` funktioniert mit npm 10 und 11.

## Mock-Modus

Der Mock bildet die API aus `docs/web-api.md` nach (`src/lib/mock/`), die UI merkt keinen Unterschied. Die Daten folgen dem Standbild 16:54 aus Anhang A des Briefings: Projekt `ms2`, Kali `192.168.56.102`, Hosts .101 (root, 23 Services), .103 (im Nebel), .104 (Sackgasse «nur RDP»), Kontextvorschlag K2, Zusammenführung K3, Denkanstösse D1 (R-ANON-ZUGRIFF) und D2 (R-VERSION-RECHERCHE), Finding F1, vier Einträge Out of Scope.

- Aktiv mit `--mode mock`, mit `VITE_ARIADNE_MOCK=1` oder automatisch im Dev-Server, wenn `/api/v1/status` nicht mit JSON antwortet.
- Szenario per Query-Parameter beim Laden, z. B. `/karte?mock=hostile`: `normal`, `calm`, `empty`, `noproject`, `locked`, `held`, `offline`, `many` (250 Hosts, nur Tabelle), `hostile` (feindliche Werte, Vorlage mit Shell-Sonderzeichen), `login`, `chain` (Hash-Kette verletzt), `noclip` (kein Werkzeug für die Zwischenablage). Für die Kopfzeile: `allon` (alle Terminals nehmen auf), `present` (Präsentationsmodus an), `scope` (Scope-Warnung nicht quittiert), `noconfirm` (Pause wird nie bestätigt, «wartet auf Bestätigung»), `budget` (E117: Server lehnt die Web-Pause ab, Rest 5 min), `local` (Sitzung lokal).
- Anmeldecodes im Szenario `login`: `FALSCH00` ergibt 401, `SPERRE00` ergibt 429, jeder andere Code meldet an.
- Entscheide ändern den Mock-Zustand und lösen dieselben SSE-Ereignisse aus wie der Daemon. Nichts davon landet im Browser-Speicher.
- Besitz: `state.ts`, `backend.ts`, `data/base.ts`, `data/hostile.ts` gehören dem Fundament; `data/map.ts` und `handlers/map.ts` «ui-karte»; `data/history.ts` und `handlers/history.ts` «ui-verlauf».

## Sicherheitsregeln

Zieldaten sind feindlich (Architektur 7.7, 9.2). Die Regeln sind technisch erzwungen, nicht nur dokumentiert.

| Regel | Durchsetzung |
|---|---|
| Kein HTML aus Strings | ESLint verbietet `{@html}`, `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `srcdoc`, `setHTMLUnsafe`; `tests/fundament/source-rules.test.ts` lässt `{@html}` nur in SafeMarkdown zu |
| Einzige Ausnahme Markdown | `src/lib/safe/SafeMarkdown.svelte`: markdown-it mit `html: false`, Links und Bilder nur `blob:`, DOMPurify mit enger Allowlist, Ergebnis als DocumentFragment |
| Unsichtbare Zeichen sichtbar | `displaySafe(text, max)` (gleiche Semantik wie `src/ariadne/termsafe.py`) und die Komponente `Txt.svelte`: `<ESC>`, `<U+202E>`, Kürzung mit «…», voller Wert im title und im Detail |
| CSP ohne Ausnahmen | Kein Inline-Skript, kein Inline-Style, keine `data:`-URIs. Dynamische Werte nur als CSS-Variablen per CSSOM (Action `styleProps`). Keine `style=`- und `style:`-Attribute, keine Svelte-Übergänge per Direktive (sie fügen `<style>` ein); Bewegung über `src/lib/util/motion.ts` (Web Animations API) |
| Kein Browser-Speicher | `localStorage` und IndexedDB sind verboten, `sessionStorage` nur in `src/lib/api/auth.ts` für das Token dieses Tabs (E112). Vorlieben liegen auf dem Server (`/api/v1/ui/prefs`), Ansichtszustand in der URL |
| Zwischenablage mit Ziel | `navigator.clipboard` nur in `src/lib/util/clipboard.ts`. Jeder Kopierknopf nennt sein Ziel (`CopyButton`: «Mac» oder «In die Kali»). Secrets nie in die Zwischenablage des Browsers, nur über den Daemon in die Kali (E111) |
| Keine fremden Ressourcen | keine CDN, keine Webfonts, nur Systemschriften; `connect-src 'self'` |
| Keine Konsolenausgabe | `console.log/info/debug` verboten (kein Token, keine Zieldaten in der Konsole) |
| Befehle nur vom Server | Denkanstösse zeigen fertig gerenderte Vorlagen, Anteile aus Zieldaten markiert, kein Ausführen-Knopf |
| Quelltext ohne Trojan Source | `tests/source-hygiene.test.ts` findet rohe Bidi- und Zero-Width-Zeichen; Testwerte als `\u`-Escape oder `String.fromCodePoint` |

**Ausnahme für Cytoscape:** Cytoscape legt beim Start ein `<style>`-Element an, das `style-src 'self'` blockieren würde. `src/lib/karte/csp.ts` legt vorher ein Platzhalter-Element mit derselben ID an, die eine Regel (`position: relative`) steht in `src/app.css`. Alle übrigen Styles setzt Cytoscape per CSSOM.

## Struktur

Besitzer im Bau v0.1: F = «ui-fundament», K = «ui-karte», V = «ui-verlauf».

```
webui/
  index.html  vite.config.ts  eslint.config.js  playwright.config.ts           F
  src/
    main.ts  App.svelte  app.css                                                F
    theme/tokens.css        Teil 1 wörtlich aus docs/ui/design-v01, Teil 2 abgeleitet   F
    lib/
      api/                  types.ts (Vertrag), client.ts, sse.ts, auth.ts, backend.ts, select.ts   F
      stores/               app, project, prefs, ui, seen, ctx                  F
                            map, next, host                                     K
                            terminals, timeline, evidence, findings             V
      url/state.svelte.ts   Reiter und Parameter in der URL                     F
      keys/                 keymap.ts (ein Listener, Ebenen), focus.ts          F
      i18n/                 index.ts, de.ts (F), de.karte.ts (K), de.verlauf.ts (V)
      safe/                 displaySafe.ts, SafeMarkdown.svelte                 F
      ui/                   Button, Badge, Kbd, Txt, Popover, Panel (Tafel), Dialog, CopyButton,
                            SecretValue, LogLine, Breadcrumb, Segmented, Toggle, TextField,
                            Notices, EmptyState, CommandLine, VirtualList, actions.ts            F
      util/                 time, errors, format, clipboard, motion, favicon    F
      shell/                Kopfzeile, Aufnahme, Menü, Anmeldung, Zustände, Einstellungen,
                            Palette, Hilfe, Scope-Dialoge                       F
      karte/  next/  host/  Karte, Lagebild, Out of Scope, Ebenen, Host-Tabelle,
                            Als Nächstes, Denkanstösse, Host-Detail             K
      terminals/  timeline/  evidence/  findings/  dialogs/
                            Terminals, Kontext-Dialog, Zeitachse, Warteliste, Belegansicht,
                            Findings, Export- und Screenshot-Dialog             V
      mock/                 siehe Mock-Modus
  tests/                    Vitest; tests/fundament (F), tests/karte (K), tests/verlauf (V)
  e2e/                      Playwright; fixtures.ts und fundament/ (F), karte/ (K), verlauf/ (V),
                            shots/ (je Besitzer eine Datei)
```

**Datenfluss.** Die Stores lesen nur über das `Backend`-Interface (`HttpBackend` oder `MockBackend`). Der globale SSE-Strom meldet nur Invalidierungen; der Projekt-Store holt danach gezielt `/changes?since=` und verteilt sie an die Bereichs-Stores (`ProjectPart`). Beim Ereignis `project` verwirft die App den Projekt-Store komplett: Abrufe abgebrochen, Ansichten per `{#key}` neu aufgebaut. Schreiben geht nur über Entscheide (`POST /decisions`), Kontext-Änderungen, Pause und Präsentationsmodus.

**Tastatur.** Ein einziger `keydown`-Listener (`src/lib/keys/keymap.ts`). Einzeltasten wirken nur ausserhalb von Eingabefeldern; Dialoge öffnen eine modale Ebene mit Fokusfalle (`trapFocus`). Die globalen Kürzel (⌘K bzw. Strg+K, `?`, `1` bis `4`, `⇧P`) und die Palettenaktionen stehen in `src/lib/shell/global.ts`; angezeigt wird ⌘K auf dem Mac, sonst «Strg K».

**Kopfzeile.** Varianten nach `AriadneKopfzeile.dc.html` am Attribut `data-variant` (normal, waiting, pause, held, locked, noproject, offline), Präsentation als Kennzeichen in jeder Variante. Unter 1280 px nur per CSS kompakt. Die Scope-Warnung ist keine modale Ebene, sondern eine Meldung beim Eintreffen (`UiStore.scopeCard`) mit Kennzeichen bis zum Quittieren (`PUT /ui/scope-ack`). Das Web-Pausenbudget (E117) steht im Aufnahme-Popover; lehnt der Server ab, bleibt die Grenze am Terminal sichtbar.

**Vorlieben.** `PrefsStore` setzt `data-theme` und `data-density` sofort und speichert auf dem Server; ältere Antworten überschreiben nie eine jüngere Wahl. Vor der Anmeldung folgt die Seite dem System (die Route braucht ein Token).

**Neu seit.** `SeenStore` meldet nur echtes Unsichtbarwerden (`visibilitychange`), nicht das Entladen beim Neuladen; so übersteht die Marke «+N seit HH:MM» das Neuladen.

**Texte.** Alle UI-Texte laufen über `t()`. Schweizer Rechtschreibung mit echten Umlauten, nie «ß», keine Emojis; `tests/fundament/i18n.test.ts` prüft das und die Präfixe je Besitzer.
