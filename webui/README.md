# Ariadne Web-UI

Die Oberfläche v0.1 von Ariadne nach dem Design in `docs/ui/design-v01/` (SCREENS, BEHAVIOR, Tokens): Kopfzeile mit Aufnahme, Karte mit Lagebild und Out of Scope, Spalte «Als Nächstes», Host-Detail, Terminals, Zeitachse mit Warteliste, Belegansicht, Findings, Anmeldung und Zustände. Svelte 5, TypeScript, Vite, Cytoscape.js mit fcose. Der Daemon liefert die gebaute UI aus `src/ariadne/web/static/` aus (Architektur 7.1). Die Schnittstelle steht in [docs/web-api.md](../docs/web-api.md), die Ergänzungen für diese Oberfläche in Abschnitt 18.

Stand 2026-10-18: gebaut nach Design v0.1 und gegen den echten Daemon geprüft, auch in einem Durchlauf als Nutzer mit echten zsh-Terminals (`e2e/nutzer/`). Abweichungen vom Design stehen unten unter «Abweichungen und Grenzen».

## Befehle

Node 22.12 oder neuer. Alle Versionen sind exakt gepinnt, `package-lock.json` ist Pflicht.

| Befehl | Zweck |
|---|---|
| `npm ci --ignore-scripts` | Abhängigkeiten aus dem Lockfile, ohne Install-Skripte |
| `npm run dev` | Dev-Server auf `127.0.0.1:5173`. Leitet `/api` an den Daemon (`ARIADNE_DAEMON_URL`, Standard `http://127.0.0.1:7330`). Läuft immer gegen die echte API; ohne Daemon zeigt die UI «Daemon nicht erreichbar» |
| `npm run dev:mock` | Dev-Server immer mit Mock-Daten |
| `npm run build` | Produktions-Build nach `../src/ariadne/web/static/` (gitignored), ohne Mock-Code |
| `npm run build:mock` | Build mit Mock-Daten nach `dist/` (gitignored) |
| `npm run preview:mock` | `dist/` auf `127.0.0.1:4173` ausliefern, mit derselben CSP wie der Daemon |
| `npm run check` | `svelte-check`, Warnungen gelten als Fehler |
| `npm run lint` | ESLint mit den Sicherheitsregeln |
| `npm test` | Vitest (jsdom) |
| `npm run test:e2e` | Playwright gegen den Mock-Build unter der Daemon-CSP (`*.mock.spec.ts`) |
| `npm run test:e2e:daemon` | Playwright gegen einen echten Daemon mit Fixture-Projekt MS2 (`*.daemon.spec.ts`, braucht `../.venv`) |
| `npm run test:e2e:nutzer` | Baut nach `src/ariadne/web/static/` und spielt den Durchlauf als Nutzer durch (`*.user.spec.ts`, etwa 6 bis 8 Minuten, braucht `../.venv` und `zsh`); Screenshots nach `ARIADNE_SHOTS_DIR`, sonst `.e2e/shots-nutzer/` |
| `npm run test:e2e:all` | Mock, Daemon und Nutzer-Durchlauf |
| `npm run shots` | Screenshots je Screen bei 1440x900, dunkel und hell, nach `.e2e/shots/` (Augenprüfung gegen die Design-Shots) |

Browsertests: Playwright 1.56.1 mit dem vorhandenen Chromium (`/opt/pw-browsers/chromium-1194/chrome-linux/chrome`, überschreibbar mit `ARIADNE_CHROMIUM`). Nie `playwright install`. Freie Ports wählt `playwright.config.ts` selbst. Jeder Browsertest scheitert, sobald die Seite eine CSP-Verletzung, einen Seitenfehler oder ein `<style>`-Element mit Inhalt meldet (`e2e/fixtures.ts`, mit Selbsttest in `e2e/fundament/guard.mock.spec.ts`).

Der Nutzer-Durchlauf steuert `tests/e2e/user_lab.py` (über `e2e/nutzer/lab.ts`, JSON-Zeilen auf stdin/stdout): isoliertes HOME mit XDG-Ordnern, `ariadne setup` und `init`, `ariadne start ms2`, Daemon mit Web-Server auf freiem Port, echte zsh-Terminals im PTY mit Shim, Markern und F12, Werkzeug-Attrappen für `nmap`, `msfconsole`, `nc` und `ip` mit den Daten aus Anhang A (nichts geht ins Netz). Der Test meldet sich mit dem Code aus `ariadne ui` an, spielt die MS2-Session durch, fotografiert jeden Screen aus `SCREENS.md` bei 1440x900 dunkel und hell, startet den Daemon neu und wechselt das Projekt. Unerwartete Konsolenmeldungen lassen ihn scheitern; am Ende prüft er, dass `localStorage` leer ist und die Shell kein Inline-Skript und keinen Inline-Stil enthält.

Der Daemon für `test:e2e:daemon` ist `tests/e2e/ui_fixture.py`: eigener Wegwerf-Ordner für HOME und XDG, Projekt `ms2` mit Scope `192.168.56.0/24`, nmap-Golden gegen .101, msf-Sitzung, Listener mit gefälschtem Callback, Eingabe ohne Echo, Entscheide wie im Standbild. Den Anmeldecode holt der Test über `ctl.sock` und öffnet `/#c=<code>` wie die Startdatei.

Hinweis zum Lockfile: `npm install` mit npm 10.9 bricht in diesem Abhängigkeitsbaum mit einem Arborist-Fehler ab (`edgesOut`). Das Lockfile wurde deshalb mit `npx npm@11.6.2 install --ignore-scripts` erzeugt. `npm ci` funktioniert mit npm 10 und 11.

## Mock-Modus

Der Mock bildet die API aus `docs/web-api.md` nach (`src/lib/mock/`), die UI merkt keinen Unterschied. Die Daten folgen dem Standbild 16:54 aus Anhang A des Briefings: Projekt `ms2`, Kali `192.168.56.102`, Hosts .101 (root, 23 Services), .103 (im Nebel), .104 (Sackgasse «nur RDP»), Kontextvorschlag K2, Zusammenführung K3, Denkanstösse D1 (R-ANON-ZUGRIFF) und D2 (R-VERSION-RECHERCHE), Finding F1, vier Einträge Out of Scope.

- Nur ausdrücklich aktiv: `npm run dev:mock`, `--mode mock` oder `VITE_ARIADNE_MOCK=1`. Der Produktions-Build enthält keinen Mock-Code, und der Dev-Server schaltet nie still auf Mock um.
- Szenario per Query-Parameter beim Laden, z. B. `/karte?mock=hostile`: `normal`, `calm`, `empty`, `noproject`, `locked`, `held`, `offline`, `many` (250 Hosts, nur Tabelle), `hostile` (feindliche Werte, Vorlage mit Shell-Sonderzeichen), `login`, `chain` (Hash-Kette verletzt), `noclip` (kein Werkzeug für die Zwischenablage). Für die Kopfzeile: `allon` (alle Terminals nehmen auf), `present` (Präsentationsmodus an), `scope` (Scope-Warnung nicht quittiert), `noconfirm` (Pause wird nie bestätigt, «wartet auf Bestätigung»), `budget` (E117: Server lehnt die Web-Pause ab, Rest 5 min), `local` (Sitzung lokal). Für die Karte: `grow` (nach 2,5 s kommt der Host 192.168.56.130 dazu; Browsertest «die Karte springt nicht unter der Maus»). Praxistest 1: `praxis` (Scope-Warnung für `curl http://recovery.vantis.internal/login` und zwei Klärungen «In den Scope aufnehmen?» nach nmap, eine mit öffentlicher Endung), `customer` (dasselbe im Profil customer: Scope nur anzeigen), `ende` (nach 1,5 s endet die Sitzung mit dem Ereignis `session`, Grund `stop`).
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
| Kein Browser-Speicher | `localStorage` und IndexedDB sind verboten, `sessionStorage` nur in `src/lib/api/auth.ts` für das Token dieses Tabs (E112). Vorlieben liegen auf dem Server (`/api/v1/ui/prefs`), Ansichtszustand in der URL. Beim Abmelden geht `DELETE /session` mit `credentials: 'same-origin'`, damit der Browser `Clear-Site-Data` des Daemons anwendet (sonst nur `omit`; Cookies gibt es keine) |
| Zwischenablage mit Ziel | `navigator.clipboard` nur in `src/lib/util/clipboard.ts`. Jeder Kopierknopf nennt sein Ziel (`CopyButton`: «Mac» oder «In die Kali»). Secrets nie in die Zwischenablage des Browsers, nur über den Daemon in die Kali (E111) |
| Keine fremden Ressourcen | keine CDN, keine Webfonts, nur Systemschriften; `connect-src 'self'` |
| Keine Konsolenausgabe | `console.log/info/debug` verboten (kein Token, keine Zieldaten in der Konsole) |
| Befehle nur vom Server | Denkanstösse zeigen fertig gerenderte Vorlagen, Anteile aus Zieldaten markiert, kein Ausführen-Knopf |
| Quelltext ohne Trojan Source | `tests/source-hygiene.test.ts` findet rohe Bidi- und Zero-Width-Zeichen; Testwerte als `\u`-Escape oder `String.fromCodePoint` |

**Ausnahme für Cytoscape:** Cytoscape legt beim Start ein `<style>`-Element an, das `style-src 'self'` blockieren würde. `src/lib/karte/csp.ts` legt vorher ein Platzhalter-Element mit derselben ID an, die eine Regel (`position: relative`) steht in `src/app.css`. Alle übrigen Styles setzt Cytoscape per CSSOM.

## Struktur

Besitzer im Bau v0.1: F = «ui-fundament», K = «ui-karte», V = «ui-verlauf», I = Integration.

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
                            shots/ (je Besitzer eine Datei), nutzer/ (I: lab.ts, durchlauf.user.spec.ts),
                            korrektur/ (Eigenschaften aus der Prüfung: Tastatur, Fokus, Kopfzeile, Karte)
```

**Datenfluss.** Die Stores lesen nur über das `Backend`-Interface (`HttpBackend` oder `MockBackend`). Der globale SSE-Strom meldet nur Invalidierungen; der Projekt-Store holt danach gezielt `/changes?since=` und verteilt sie an die Bereichs-Stores (`ProjectPart`). Beim Ereignis `project` verwirft die App den Projekt-Store komplett: Abrufe abgebrochen, Ansichten per `{#key}` neu aufgebaut. Schreiben geht nur über Entscheide (`POST /decisions`), Kontext-Änderungen, Pause und Präsentationsmodus.

**Tastatur.** Ein einziger `keydown`-Listener (`src/lib/keys/keymap.ts`). Einzeltasten wirken nur ausserhalb von Eingabefeldern; Dialoge öffnen eine modale Ebene mit Fokusfalle (`trapFocus`). Die globalen Kürzel (⌘K bzw. Strg+K, `?`, `1` bis `4`, `⇧P`) und die Palettenaktionen stehen in `src/lib/shell/global.ts`; angezeigt wird ⌘K auf dem Mac, sonst «Strg+K». Enter, Leertaste und Pfeile gehören dem fokussierten Bedienelement (Knopf, Link, Radio, Checkbox, Rollen option/menuitem/tab); eine Bindung wirkt dort nur mit `onControl` (Pfeile zwischen Host-Karten). Seiten-Kürzel eines Reiters ruhen, solange eine Tafel offen ist (`keys/page.ts`); die Tafel setzt den übrigen Inhalt `inert`. Ein ungespeichertes Formular sperrt die Reiterkürzel `1` bis `4` (Meldung statt Verlust).

**Kopfzeile.** Varianten nach `AriadneKopfzeile.dc.html` am Attribut `data-variant` (normal, waiting, pause, held, locked, noproject, offline), Präsentation als Kennzeichen in jeder Variante. Unter 1280 px nur per CSS kompakt. Die Scope-Warnung ist keine modale Ebene, sondern eine Meldung beim Eintreffen (`UiStore.scopeCard`) mit Kennzeichen bis zum Quittieren (`PUT /ui/scope-ack`). Das Web-Pausenbudget (E117) steht im Aufnahme-Popover; lehnt der Server ab, bleibt die Grenze am Terminal sichtbar.

**Vorlieben.** `PrefsStore` setzt `data-theme` und `data-density` sofort und speichert auf dem Server; ältere Antworten überschreiben nie eine jüngere Wahl. Vor der Anmeldung folgt die Seite dem System (die Route braucht ein Token).

**Neu seit.** `SeenStore` meldet nur echtes Unsichtbarwerden (`visibilitychange`), nicht das Entladen beim Neuladen; so übersteht die Marke «+N seit HH:MM» das Neuladen.

**Texte.** Alle UI-Texte laufen über `t()`. Schweizer Rechtschreibung mit echten Umlauten, nie «ß», keine Emojis; `tests/fundament/i18n.test.ts` prüft das und die Präfixe je Besitzer.

## Abweichungen und Grenzen

Verglichen mit den Design-Shots in `docs/ui/design-v01` (Augenprüfung der Screenshots aus dem Nutzer-Durchlauf, dunkel und hell):

- **Daten statt Standbild.** Der Durchlauf erzeugt seine Werte selbst; Uhrzeiten, Zahl der Denkanstösse (mit dem vollen MS2-Scan über 20 «Version recherchieren»), Nummern der Klärungen (K3 statt K2) und Positionen auf der Karte weichen darum vom Standbild ab. R-ANON-ZUGRIFF erscheint nicht, weil der Scan mit `-sC` `ftp-anon` schon geprüft hat.
- **Rückkehr-Kopf (Richtung 1b)** ist nicht gebaut; massgeblich ist 1a (Marke «+N seit» im Lagebild).
- **Kopfzeile:** auf Linux «Strg+K» statt «⌘K» (ohne Leerzeichen, damit der Hinweis nie umbricht). «Kopieren · Mac» heisst auch bei einer lokalen Sitzung so. Wird es eng, kürzen sich zuerst Pause und Aufnahme-Text; held steht unter 1440 px als «! pts/4 nicht gespeichert», Pause und Scope-Warnung als «Pause bis 17:00» und «Scope», Präsentation als Punkt (voller Text im title). Die Herkunft bleibt immer sichtbar, nichts läuft in die Reiter.
- **Scope-Warnung** steht unten rechts (auf dem Reiter Karte links neben der Spalte) statt oben, damit Spaltenkopf und gewählter Eintrag frei bleiben, und ist eine Live-Region (`role="alert"`).
- **Zeitachse:** Callbacks, die den Kontext nicht automatisch gesetzt haben, stehen als eigene Zeile «Callback von 192.168.56.101:49158» mit «Kontext unklar · K2».
- **«Denkanstoss anfordern (KI)», Export und Screenshot** sind deaktiviert mit Grund (Backend folgt, Routen antworten 501).
- **Host-Detail:** Unter Tags und Notiz stehen zusätzlich Widersprüche, Kennungen und Befehle in diesem Kontext (aus `dashboard-funktionen.md` 5.3). Die Quelle eines Nebel-Hosts nennt die Datei (`scans/sweep.xml`), nicht den Befehl.
- **Zeitachse:** Dateien eines Befehls stehen nur in seiner Unterzeile; die Unterzeile (Exit, Dateien) zeigt sich an der gewählten Zeile, bei laufenden Befehlen, Hinweisen und Exit ungleich 0. Offene Remote-Segmente (laufendes msf, Listener) erscheinen schon mit vorläufigen Zeilen.
- **Meldungen** («Name gespeichert») stehen oben in der Mitte und verschwinden nach 2,5 s; das Design zeigt keine.
