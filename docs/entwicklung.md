# Entwicklung

> Stand v0.1-Backend (2026-10-14, nach den Korrekturen aus drei Reviews), Erfassung, Bedienung und Auswertung nach den Entscheiden vom 2026-10-15 (E22, E23, E26, E28, E42, E45, E72, E88, E95, E96; Vertrag v0.1-Bedienung), integriert und Ende zu Ende getestet am 2026-10-15. Bau v0.1-Server (Vertrag v0.1-Server): Phase 1 am 2026-10-15 (E101 bis E104, API v2 in `docs/web-api.md`, Erweiterungspunkte im Daemon), Web-Server, API, Sicherung und Fernzugriff von vier Teilen gebaut, integriert und Ende zu Ende getestet am 2026-10-17 (E115). Etappe 4 (KI-Denkanstoss, Bericht-Export, Screenshots, Paket mit gebauter Oberfläche, E119, E120) integriert und Ende zu Ende getestet am 2026-10-18. Ergänzt die [Lösungsarchitektur](architektur.md) um das, was man zum Arbeiten am Code braucht: Umgebung, Tests, Landkarte der Module und die bekannten Grenzen.

## Umgebung

Ziel ist Kali Linux als normaler Benutzer. Entwickelt und getestet wird mit Python 3.11 bis 3.13.

```sh
sudo apt install python3-venv zsh bash tmux     # zsh und bash für die PTY-Tests, tmux für den Multiplexer-Test
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
```

- `pip install -e` ist nötig: Der Parser-Worker startet mit `python -I -B -m ariadne.ingest.worker` und findet das Paket nur über den venv, nicht über `PYTHONPATH`.
- `sqlcipher3` bringt eigene Wheels mit FTS5 mit. Das ähnlich benannte `sqlcipher3-binary` ist nicht gemeint.
- Für die Tests mit Tunnel (Marker `remote`) braucht es `openssh-server` (`sshd`, `ssh`, `ssh-keygen`, `ssh-agent`) und `lsof`; die Tests überspringen sich, wenn `sshd` fehlt. Läuft die Suite als root (Container), starten sshd, Daemon und Ordner unter einem unprivilegierten Benutzer mit Login-Shell (`ARIADNE_TEST_SSH_USER`, sonst der erste mit UID ab 1000), denn ohne Privilegien-Benutzer `sshd` startet ein sshd als root nicht. `age` und `shellcheck` sind optional (`shellcheck` prüft `kali-setup.sh`, wenn vorhanden).
- Für einen Probelauf in einem Wegwerf-HOME: `HOME=/tmp/x ariadne setup --no-systemd`, danach `ariadne init`, neues Terminal öffnen, `ariadne start lame --target 10.10.10.3`. Ab dann nimmt jedes Terminal auf, bis `ariadne stop`. Nie mit dem echten HOME testen, solange man nicht genau das will.

## Tests

Alle Tests laufen ohne Netz, nur in `tmp_path` und mit isolierten `HOME`/`XDG_*`-Variablen. Kein Test berührt echte Benutzerdateien.

| Ordner | Inhalt | Marker |
|---|---|---|
| `tests/unit/` | Fundament-Verträge (`test_foundation.py`, `test_contract_v01.py`), sicheres Öffnen, Kontext-argv, CLI-Ansichten (`test_cli_views.py`, `test_ausw_views.py`, `test_ausw_cli.py`), Mark-Hook-Regeln, Anmeldung des Terminals vor jeder Secret-Abfrage (`test_cli_secret_order.py`) | |
| `tests/shim/` | Scanner, Marker, Hotkeys, Ringpuffer, Transport, Titel; PTY-Tests mit echter zsh/bash gegen einen Fake-Daemon | `pty` |
| `tests/core/` | Krypto, Journal- und Blob-Vertrag (Memory und SQLCipher), Redaktor, Projekte, Daemon mit Fake-Shim (`test_daemon.py` Grundfluss, `test_daemon_capture.py` Daueraufnahme, Pause, Wechsel, Vorlauf, Zeit, Eingaben, Canary E72, `test_daemon_review.py` Korrekturen aus den Reviews: Strom-Ausrichtung, Schlüsselmaterial-Pause, Ausfallpuffer, Uhren und Leerlauf), CLI per Subprozess | |
| `tests/unit/test_erf_*.py` | Writer: Zusammenfassen der Rahmen ohne Verlust an Zeitgenauigkeit (Hypothesis) | |
| `tests/ingest/` | Scope, Ziele aus argv, Normalizer (Goldens, Hypothesis), Segmenter, Pipeline, Worker-Grenzen | |
| `tests/parsers/`, `tests/golden/` | Parser einzeln und als Golden-Fälle (`input.*`, `meta.toml`, `expected.jsonl`) | |
| `tests/projection/` | Claims, Zustände, Identität, Konflikte, Inbox, Status, Metasploitable2-Durchlauf; Drei-Spuren-Regel (`test_ausw_lanes.py`), Evidenzgruppen und Arten, eigene Adressen und `undo`, Kontext aus dem Callback, goldene Ziele MS2 und Lame (`test_ausw_golden.py`) | |
| `tests/integration/` | Daemon mit eingebauter Auswertung: Fake-Shim über echte Sockets, echte Parser in Workern, Begleitdateien, `net.route`, Ansichten, Entscheide, Import, Reparse, Redaktion | |
| `tests/e2e/` | Flugschreiber komplett (`helpers.py`: isoliertes Lab, Fake-`nmap`, -`nc`, -`ip`, Titel per OSC 2): `test_flight_recorder.py` (setup, init, `F12 h`, CLI-Ansichten, Journal, Canary, Vorlauf über einen Absturz, Pause und Rebind), `test_daily_use.py` (Alltag: `start --passphrase-fd`, zwei parallele Terminals, nmap auf das Fixture-Netz, Karte `auto`, Inbox leer, keine Kali-Adresse als Host, Titel `(auto)` aus dem Callback, verschränkte Zeitstempel, `F12 r` nur in einem Terminal, `ariadne undo`, `ariadne stop`; Vorlauf zweier Terminals mit der Frage und der Passphrase im aufgezeichneten Terminal) | `e2e`, `pty` |
| `tests/e2e/test_dashboard.py` | Dashboard als Nutzer: Weg E (setup, init, start, nmap, `read -s` und `getpass` im aufgezeichneten Terminal, `ariadne ui --no-open`, Navigation von der Startdatei, Anmeldung, Status, Karte, Zeitachse mit verdeckten Eingaben, Aufdecken, SSE nach einem Entscheid, `lock` beendet Sitzung und Strom, `unlock` öffnet das Projekt wieder, `stop` mit Hinweis, `backup --to-file`) und Weg B (sshd mit dem Drop-in aus `kali-setup.sh`, `ariadne-mac start` und `stop` unter zsh mit echtem `ssh`, `ssh-agent` und `lsof`, Anmeldung «über sshd», Sicherung auf den «Mac», `remote serve unlock` im PTY) | `e2e`, `web`, `pty`, `remote` |
| `tests/web/server/` | Server-Kern (T1 bis T7, T8 serverseitig): Konfiguration, `/proc`-Parser, Codes und Sitzungen mit austauschbarer Uhr, Middleware und Header gegen einen echten Server, Statik, SSE-Bus, `ariadne ui`. `helpers.py`: `run_web` (Daemon im Testprozess mit echtem Server auf Port 0), `Web.req`/`Web.raw`, `Stream` (SSE), `ClientProc` (Anfragen aus einem fremden Prozess), `FakeSshd` (`sh` als `sshd`), Test-API statt der echten (`use_test_api`) | `web` |
| `tests/web/api/` | API v2 (T8 Canary, T9 bis T11): jede Route mit MS2-Fixture und echtem Daemon, feindliche Werte, Präsentationsmodus über zwei Ströme, Entscheide, Ereignisquellen. `helpers.py`: `FakeBus`, `make_app` (Test-App mit Sitzungs-Middleware), `run_api`, `build_fixture`; `test_fullstack.py` gegen den echten Server | `web` |
| `tests/ai/` | KI-Denkanstoss (Etappe 4): Route mit echtem Daemon, MS2-Fixture und Fake-Transport (`httpx2.MockTransport`), Secret-Kanarienvogel und API-Key nie im Anfragekörper, feindliche Antworten (17 Fälle), Budget, Ablehnung, Ollama nicht erreichbar, CLI | |
| `tests/export/` | Bericht-Export (Etappe 4): goldener Durchlauf mit MS2-Fixture und feindlichem Befehl, Manifest und Kettenköpfe, `mdsafe` mit Hypothesis, Writer (Symlink, `O_EXCL`, Rechte), Sync-Ordner, Phasen über Reparse, CLI-Klartext | |
| `tests/screenshots/` | Screenshots (Etappe 4): kanonisches PNG und `check_png` (Hypothesis), echte Aufnahmen gegen einen eigenen Xvfb, Web-Durchlauf, Hotkey über FakeShim, CLI | |
| `tests/packaging/` | Gebaute Oberfläche und Wheel: Build-Vermerk passt zu den webui-Quellen, Wheel in frischem venv mit `setup`, `doctor` und Daemon (übersprungen ohne uv und hatchling im Cache) | |
| `tests/integ4/`, `tests/e2e/test_etappe4.py` | Integration Etappe 4: SSE `screenshot`, Fehlercodes `shot_*`, `Status.llm`; Durchlauf als Nutzer unter Xvfb (setup, init, `ai setup` mit Fake-Ollama auf Loopback, `start ms2`, `F12 s` im PTY, Screenshot und KI-Denkanstoss aus dem Dashboard, Finding, Phase korrigieren, Export `cys` und `htb`, `stop`, `backup`) | `e2e`, `pty`, `web` |
| `tests/rules/` | Regeln für Denkanstösse (B2): Goldene Fälle MS2 und Lame (`tests/golden/rules/`), Kontext-Encoder und Vorlagen (feindliche Werte ergeben keine Vorlage), Zustände (`d.suggestion.done`/`dismiss` über Reparse), Leistung mit 500 Hosts | |
| `tests/e2e/ui_fixture.py`, `tests/e2e/user_lab.py`, `webui/e2e/karte/karte_fixture.py` | Helfer der Browsertests (siehe «Browsertests»): Fixture-Daemon mit Projekt MS2, Durchlauf als Nutzer mit echten Terminals, Fixture-Daemon der Karte | |
| `tests/backup/` | Sicherung und Wiederherstellung (T16): Rundweg in ein leeres HOME, beschädigte Ströme, Pfade, Version, Rechte, WAL nach SIGKILL, Registry, Hinweis nach `stop`, CLI mit Kettenprüfung | |
| `tests/remote/` | Fernzugriff: `test_serve.py` (T12), `test_check.py` (T14, Fixture-Wurzel und Runner mit festen Antworten), `test_kali_setup.py` (Wegwerf-Wurzel `ARIADNE_SETUP_ROOT`, zweimal ohne Unterschied, echtes `sshd -t` und `nft -c`), `test_mac_helper.py` (T15, zsh mit Attrappen über `ARIADNE_MAC_SHIM_DIR`), `test_tunnel_e2e.py` (T13, echter sshd im Ordner `/tmp/ariadne-t13-*`) | `remote`, `web` |
| `tests/unit/test_contract_v01_server.py`, `tests/unit/test_anleitung_fernzugriff.py` | Namen und Signaturen der Teile; jeder Befehl und jede zitierte Meldung der Anleitung gegen den Code | |

Befehle:

```sh
python -m pytest                                   # alles (etwa 10 min, rund 2390 Tests)
python -m pytest -m "not pty and not e2e"          # ohne echte Shells (schnell)
python -m pytest -m remote                          # nur Tunnel-Tests mit sshd
python -m pytest -m web                             # alles mit echtem Web-Server (freier Loopback-Port)
python -m pytest tests/web tests/backup tests/remote tests/e2e/test_dashboard.py   # Bau v0.1-Server
python -m pytest tests/e2e -m e2e                  # nur der Flugschreiber
python -m pytest tests/golden --update-golden      # Golden-Erwartungen neu schreiben, zeigt vorher den Diff
ARIADNE_TEST_EXTRA_SHELLS=/pfad/zu/bash-5.3 python -m pytest tests/shim   # weitere Shells
ruff check src tests                               # Lint (Zeilenlänge 110, E F W I B UP S)
```

### Browsertests (Web-UI)

Die Oberfläche in `webui/` hat eigene Tests (Bedienung in [webui/README.md](../webui/README.md)); Node 22 (`/opt/node22/bin` in diesem Container), Abhängigkeiten mit `npm ci --ignore-scripts`. Playwright 1.56.1 nimmt das vorhandene Chromium `/opt/pw-browsers/chromium-1194/chrome-linux/chrome` (überschreibbar mit `ARIADNE_CHROMIUM`), headless; nie `playwright install`. Ports wählt `webui/playwright.config.ts` frei. Jeder Browsertest bricht bei einer CSP-Verletzung, einem Seitenfehler, einem `<style>`-Element mit Inhalt und (im Nutzer-Durchlauf) jeder unerwarteten Konsolenmeldung ab (`webui/e2e/fixtures.ts`).

```sh
cd webui
npm run check && npm run lint && npm test          # svelte-check, ESLint, Vitest (jsdom)
npm run test:e2e                                   # Projekt mock: Mock-Build unter der Daemon-CSP
npm run test:e2e:daemon                            # Projekt daemon: echter Daemon mit Fixture MS2
npm run test:e2e:nutzer                            # Projekt nutzer: Durchlauf als Nutzer, Screenshots
npm run test:e2e:all                               # alle drei
npm run shots                                      # Screenshots gegen den Mock (Augenprüfung)
```

Helfer für die Fixtures (alle mit eigenem Wegwerf-Ordner für `HOME` und `XDG_*`, nie Benutzerdateien):

- `tests/e2e/ui_fixture.py`: echter Daemon mit Web-Server und Projekt `ms2` wie im Standbild (nmap-Golden, msf-Sitzung, mehrdeutiger Callback, Eingabe ohne Echo, Entscheide, «Neu seit», Scope-Warnung, Finding F1); Szenarien `ms2`, `empty`, `noproject`, `locked`. Der Test holt den Anmeldecode über `ctl.sock`. Geprüft von `tests/e2e/test_ui_fixture.py`.
- `webui/e2e/karte/karte_fixture.py`: baut darauf auf, für Karte, Spalte und Host-Detail.
- `tests/e2e/user_lab.py`: der Nutzer-Durchlauf. Isoliertes HOME, `ariadne setup`, `init`, `start ms2`, Daemon mit Web-Server, echte zsh-Terminals im PTY mit Shim (pexpect), Werkzeug-Attrappen (`nmap`, `msfconsole`, `nc`, `ip`) mit den Daten aus Anhang A. Gesteuert über JSON-Zeilen auf stdin/stdout (`setup`, `cli`, `term_open`, `run`, `send`, `hidden_input`, `hotkey`, `title`, `ui_url`, `write_file`, `daemon_stop`, `daemon_start`, `close`); auf der Seite des Browsers `webui/e2e/nutzer/lab.ts`.

Regeln für neue Tests: deterministisch, kurze Socket-Pfade (`tmp_path_factory.mktemp`, AF_UNIX-Grenze), echte Shells nur mit `@pytest.mark.pty`, Zieldaten in Tests immer feindlich denken (Escape-Sequenzen, Bidi-Zeichen, gefälschte Marker). Nachgestellte Golden-Fälle sind in `meta.toml` als `source = "nachgestellt"` markiert und werden durch echte Lab-Aufnahmen ersetzt, sobald es sie gibt.

- **Kein Port 7330 in Tests.** `tests/conftest.py` setzt `ARIADNE_WEB=0` für alle Daemon-Prozesse; Tests mit Web-Server nehmen `[ui] port = 0` bzw. einen freien Port und entfernen die Variable nur für ihren Daemon (`tests/e2e/test_dashboard.py`, T13).
- **Ressourcen schliessen.** `pyproject.toml` macht `ResourceWarning` und nicht abfangbare Ausnahmen zu Fehlern. Dateien, Sockets, Transports und `StreamWriter` schliessen die Tests selbst; `sqlite3`-Verbindungen schliesst eine Fixture in `tests/conftest.py` am Ende jedes Tests.
- **Reihenfolge nicht annehmen.** Titel und Prompt können in beliebiger Reihenfolge ankommen. PTY-Tests prüfen Titel mit `expect_seen` (sucht auch im schon Gelesenen).
- **In einem aufgezeichneten Terminal** laufen die PTY-Tests (eigene PTYs, eigener Shim). Bei aktivem Projekt landet aber die pytest-Ausgabe in der Aufnahme: Tests besser mit `ariadne pause` (oder `F12 r`) oder mit `ARIADNE_DISABLE=1` in einem nicht aufgezeichneten Terminal starten.
- Ein Befund wird mit einem Test behoben, der vorher scheitert. Neue Tests decken unter anderem ab: Zeitgrenzen des Ausgabefilters (Hypothesis mit einem kleinen VT500-Modell), Redaktor über Events und Stille hinweg, Kontext im Vorlauf und nach einem Daemon-Neustart (E2E mit SIGKILL), Pause per Hotkey und CLI, Projektwechsel mit Remote-Sitzung, Eingaben ohne Hotkey-Bytes, mehrere Terminals gleichzeitig, Fehler der Auswertung im Daemon-Pfad, Notfallpfade des Shims (Paketkopie mit eingebautem Fehler).

## Landkarte der Module

**Fundament (Verträge, nur Standardbibliothek wo der Shim sie braucht)**

| Datei | Aufgabe |
|---|---|
| `events.py` | Event- und Entscheid-Katalog, `validate_header`, kanonisches JSON |
| `ontology.py` | Prädikate mit Kardinalität, Kartenebene, Inbox-Regel |
| `ctxrules.py` | Kontext-Stapel und argv-Regeln (Shim, Daemon und Segmenter gemeinsam) |
| `ids.py`, `paths.py`, `termsafe.py` | UUIDv7 und `cmd_id`; XDG-Pfade; der Encoder fürs Terminal |
| `_shim/protocol.py` | Rahmenprotokoll Shim und Daemon (HELLO, OUT, EVENT, STATE, ACK) |
| `store/api.py`, `store/chain.py`, `store/memory.py` | Journal- und Blob-Vertrag, Hash-Kette, Fakes für Tests |
| `parsers/api.py`, `scope/api.py` | Parser-Schnittstelle (`UnitView`, `Obs`, `Mention`, `Ref`), Scope-Urteil |

**Erfassung**

| Datei | Aufgabe |
|---|---|
| `shell/launcher.sh`, `shell/init.zsh`, `shell/init.bash` | Start aus der RC-Datei, Fallback auf die nackte Shell, Marker-Hooks (OSC 133 und Nonce-Marker 7701) |
| `_shim/launch.py`, `_shim/relay.py` | PTY anlegen, Relay-Schleife, Aufnahme-Zustand (Pause lokal mit Ablauf, `held` mit `req.rebind`, Multiplexer), Shim-Zeit an jedem Ereignis, Exit-Code |
| `_shim/inputrec.py` | Eingaben ans Kind bündeln (Enter, Ctrl-C/D, Paste als ein Rahmen, 4 KiB, 1 s) mit Zeitindex (E26) |
| `_shim/scanner.py`, `_shim/markers.py` | Escape-Automat, Filter (OSC 52, reflektierende Anfragen), Marker prüfen |
| `_shim/hotkey.py`, `_shim/miniprompt.py`, `_shim/title.py` | F12-Präfix, Mini-Prompt, Fenstertitel mit Zustand (`[REC lame]`, `[PAUSE 9 min lame]`, `[kein Projekt (Vorlauf 15 min)]`, `[gesperrt: ariadne start]`, `[Remote lame: nicht gespeichert]`, `[Multiplexer: Panes nehmen auf]`) |
| `_shim/transport.py`, `_shim/ringbuf.py` | Verbindung zum Daemon (Protokoll v2: OUTX mit Zeitindex, INPUT), RAM-Puffer, Resume, Gaps |

**Daemon und Speicher**

| Datei | Aufgabe |
|---|---|
| `daemon/core.py` | Sockets, Terminal-Register, Zustände (`paused`, `held`, `on`, `locked`, `preroll`, `off`), `start`/`stop`, Pause, Projektwechsel, Leerlauf-Ende, Hotkey-Anfragen, alle `ctl.sock`-Operationen der Erfassung |
| `daemon/writer.py` | Bündeln, Zusammenfassen der Rahmen mit Zeitindex, `append_many`, ACK, Commit- und Mark-Hooks (kein Schwärzen mehr, E72) |
| `daemon/preroll.py` | Vorlauf ohne Projekt: nur RAM, Fenster und Grenzen, Stapel am Fensteranfang (E95) |
| `daemon/config.py`, `daemon/active.py` | `[recording]` aus `config.toml`; zuletzt aktives Projekt (`active.json`) |
| `daemon/extensions.py` | Erweiterungen für `ariadne daemon run` (Web-Server); `ARIADNE_WEB=0` schaltet ihn ab. Erweiterungspunkte in `core.py`: `extensions`, `add_listener`/`remove_listener` (Ereignisse ohne Zieldaten, auch `job` beim Reparse), `add_ops`, `ctl_peer_pid()` (Aufrufer einer ctl-Operation), `presentation` |
| `sources/localaddr.py` | eigene Adressen aus `/proc/net/fib_trie` und `/proc/net/if_inet6` (`net.local_addrs`) |
| `daemon/ingest.py` | Pipeline in eigenem Thread, entprellt nach Commits, Reparse mit Dateitausch |
| `daemon/sources.py` | Mark-Hook: Begleitdateien beim D-Marker, `ip route get` beim C-Marker; `ariadne import`; Warteliste |
| `daemon/terminal.py`, `daemon/hardening.py`, `daemon/main.py`, `daemon/client.py` | Terminal-Zustand, Härtung (Core, Dumpable, flock), Start, CLI-Client |
| `crypto/*` | SQLCipher-Verbindungen, age, versiegelte Slots, Operator-Tresor |
| `store/journal.py`, `store/blobs.py` | Journal auf SQLCipher (plus `JournalReader` für Threads), age-Blob-Store |
| `project/*` | Projekte anlegen und öffnen, Einstellungen als TOML, Lab-Leitplanke |
| `secrets/redactor.py` | der eine Redaktor für eigene Secrets; Ausgangs-API `redact_for_exit`/`redact_json` (E72) |
| `sources/safeopen.py` | Dateien ohne Symlinks öffnen, `fstat`-Prüfungen, Sperrliste |

**Auswertung**

| Datei | Aufgabe |
|---|---|
| `ingest/pipeline.py` | Journal ab Wasserstand verarbeiten: Segmenter, Einheiten, Parser, Projektion |
| `ingest/seg_stream.py`, `ingest/normalizer.py` | Terminal-Strom zu Zeilen mit Offset-Karte, Alternate Screen über pyte |
| `ingest/segmenter.py`, `ingest/seg_activity.py` | Befehle, Kontextspannen, Einheiten; Aktivitätsprotokoll |
| `ingest/units.py`, `ingest/unit_store.py`, `ingest/schema_units.py`, `ingest/db.py` | Einheiten, Zeilen, FTS5, Schema von `derived.db` |
| `ingest/runner.py`, `ingest/worker.py` | Parser im Worker-Prozess ohne Schlüssel, mit rlimits; Ausgabe geprüft |
| `ingest/projection.py`, `ingest/proj_build.py`, `ingest/claims.py`, `ingest/identity.py`, `ingest/schema_claims.py` | Claims, Evidenzgruppen, Konfidenz, Drei-Spuren-Regel, eigene Adressen, `d.unit.distrust`, Kontext aus dem Callback, Identitäten, Konflikte, Inbox, Status, Sichten |
| `ingest/natures.py` | Arten der Prädikate (E45): `state` mit Verlauf, `version` mit Bereichen, `set` |
| `ingest/queries.py` | lesende Abfragen für die CLI-Ansichten, Suche, Sammelbestätigung (`resolve_confirm`), `undo` (`resolve_distrust`, `cmd_ref`), Reparse-Diff |
| `ingest/inputs.py` | Eingaben nach E104: Echo-Vergleich (`echo_seen`, `output_window`), Urteil (`classify`), Anzeige (`display_text`), Leser aus dem Journal (`collect_inputs`, `input_by_seq`) |
| `daemon/ops_eval.py` | ctl-Operationen der Auswertung (`show`, `search`, `claim.*`, `unit.distrust`, `reparse`), alles durch `redact_json` |
| `parsers/*` | `nmap.xml`, `nmap.text`, `regex.net`, `listener.callback`, sichere XML- und Regex-Bausteine, Registry |
| `scope/*` | Normalisierung, `ScopeMatcher`, Ziele aus argv |

**CLI**: `cli/main.py` (Erfassung und Bedienung), `cli/analysis.py` (Befehle der Auswertung: `show`, `search`, `confirm`, `reject`, `undo`, `reparse`), `cli/common.py` (Daemon-Zugang, `read_secret` mit Zeitgrenze), `cli/views.py` (Textansichten), `cli/setup.py` (Installer), `cli/doctor.py`.

**Web-Server** (`src/ariadne/web/`, Bau v0.1-Server, Architektur 7.2)

| Datei | Aufgabe |
|---|---|
| `web/config.py` | `[ui]` aus `config.toml`: nur `127.0.0.1` oder `::1`, Port 1024 bis 65535 (`0` für Tests), `session_hours`, `enabled` |
| `web/peer.py` | `/proc/net/tcp(6)` und `/proc/<pid>/fd`: UID, Inode, haltende Prozesse, Startzeit, `comm`; sshd-Vorfahren (`sshd_ancestor`). Alle Funktionen mit `proc_root` für Fixtures |
| `web/sessions.py` | Codes, Tokens (nur SHA-256), Bindung lokal bzw. über sshd, Ablauf (austauschbare Uhr `Clock` mit `wall_ns`/`boot_ns`), Fehlversuchssperre, Widerruf |
| `web/security.py` | äusserste Middleware: Peer, Host, Fetch-Metadaten mit der Ausnahme E115 (`shell_navigation`), OPTIONS, Origin, 1 MiB, Bearer; Header auf jeder Antwort; feste Fehlertexte `ERROR_TEXT` |
| `web/sse.py`, `web/static.py`, `web/app.py` | Ereignisbus (Bündelung, Ring, Herzschlag, Schliessen pro Sitzung); Statik mit SPA-Fallback; Verteiler `/api` an FastAPI (Sitzung, Ereignisstrom, `api.register`), sonst Statik |
| `web/server.py`, `web/integration.py`, `web/ctx.py` | eigener Socket und uvicorn im Loop (`PeerGate` mit austauschbarem Resolver, `WebServer`); Erweiterung des Daemons mit den ctl-Operationen `ui.*` und der 2-s-Prüfung (`WebExtension` mit `peer_resolver`, `clock`, `check_interval` für Tests); gemeinsame Typen |
| `web/api/` | API v2 (Architektur 7.3): `common.Api` als einziger Zugang zum Daemon, `errors`, `text`, `views`, `models`; Routen in `status`, `terminals`, `project`, `graph`, `hosts`, `next`, `timeline`, `evidence`, `decisions`, `search`, `secrets`, `clipboard` (in die Kali, E111), `suggestions` (Regeln und KI zusammen), `findings` (E113), `ui_state` (Vorlieben E112, «Neu seit» E106, Scope-Quittung), `ai`, `exports`, `screenshots`, `blobs` (Etappe 4), `later` (501), Ereignisquellen in `events` |
| `ingest/pending.py` | vorläufige Zeilen offener Einheiten (laufender Listener, msf-Sitzung) für Leser im Thread der Auswertung: Logauszug am Kontextvorschlag, Belegzeilen, Remote-Segment in der Zeitachse; nichts davon wird gespeichert |

**Sicherung** (`src/ariadne/backup/`, Architektur 8.9): `model` (Ergebnisse, Fehlercodes `CODES`), `config` (Empfänger), `manifest`, `collect` (Dateien, Sperren), `writer` (Tar-Strom, Pull-Verschlüsselung mit eigenem Schreiber, weil `pyrage.encrypt_io` Schreibfehler nicht zuverlässig meldet), `reader` (Prüfen, temporäre Ordner, Rollback, `DecryptingReader` für `--identity`), `registry`, `reminder`, `api` (`backup_to_stream`, `restore_from_stream`, Zusammenfassungen ohne Zieldaten).

**Fernzugriff** (`src/ariadne/remote/`, Architektur 8.11): `serve.py` (Forced Command, `HOLD` austauschbar), `check.py` (`run_checks`, `quick_ok`, `quick_checks`, `render`, `System` mit Wurzel, `/proc` und Runner), `parse.py` (`sshd -T`, `authorized_keys`, `tailscale debug prefs`). Dazu `packaging/smartlearn/kali-setup.sh` (POSIX sh, Wegwerf-Wurzel `ARIADNE_SETUP_ROOT` für Tests) und `packaging/mac/ariadne-mac` (zsh; `ARIADNE_MAC_SHIM_DIR`, `ARIADNE_MAC_PORT`, für Tests `ARIADNE_MAC_LOCAL_PORT`).

**CLI des Baus v0.1-Server**: `cli/ui.py` (`ariadne ui`), `cli/backup.py` (`ariadne backup`, `ariadne restore`), `cli/remote.py` (`ariadne remote check`, `ariadne remote serve`, `ensure_runtime_dir`).

**Regeln für Denkanstösse** (`src/ariadne/rules/`, [denkanstoesse.md](denkanstoesse.md)): Regel-Engine über der Projektion, Kontext-Encoder für Vorlagen (E68), Zustände über Entscheide.

**Web-Oberfläche** (`webui/`, Architektur 7.4): Svelte 5, Build nach `src/ariadne/web/static/`; Aufbau und Tests in [webui/README.md](../webui/README.md).

**KI** (`src/ariadne/ai/`, Architektur 6, Etappe 4): `config` (`ai.toml`), `budget` (Monatsbuch pro Operator), `providers` (cloud über das SDK, local über Ollama auf Loopback), `situation` (Lagebild mit einem Encoder pro Werteart), `schema` (Antwortschema und Prüfung), `store` (Entscheid `d.ai.denkanstoss`, Zustand, Einbindung in `/next`, `/suggestions` und `POST /decisions`), `gateway` (ein Auftrag zur Zeit, SSE `progress`), `ops` (ctl), `check` (`ariadne ai check`). CLI `cli/ai.py`.

**Export** (`src/ariadne/export/`, Architektur 8.7, Etappe 4): `collect` (nur lesend, maskiert), `mdsafe` (einziger Markdown-Encoder), `render` (Vorlagen `cys`, `htb`), `writer` (`openat`, `O_NOFOLLOW`, `O_EXCL`), `service`, `ops`; Phasenregeln in `ingest/proj_phases.py`. CLI `cli/export.py`.

**Screenshots** (`src/ariadne/sources/screenshot*.py`, Architektur 4.3, Etappe 4): `screenshot` (Aufnahme, PNG, `check_png`, dHash, feste Fehlertexte `SHOT_ERRORS`), `screenshot_worker` (eigener Prozess), `screenshot_service` (Ablage, Kontext, Hotkey, ctl `shot.take`). CLI `cli/shot.py`.

## Ablauf eines Befehls

1. zsh sendet vor dem Befehl den C-Marker, danach den D-Marker. Der Shim prüft Nonce und Vordergrund und schickt `term.mark` (mit Shim-Zeit), die Ausgabe (`OUTX` mit Zeitindex) und das Getippte (`INPUT`) an den Daemon.
2. Der Writer fasst Rahmen zusammen, schreibt alle 200 ms in `journal.db` (alles, verschlüsselt, ungeschwärzt) und bestätigt dem Shim. Ohne offenes Projekt hält der Daemon die Rahmen nur im Vorlauf (RAM).
3. Commit-Hook: Die Auswertung verarbeitet nach 500 ms Ruhe die neuen Events im eigenen Thread. Fertige Einheiten gehen an die Parser im Worker, die Projektion berechnet Claims, Hosts, Services und Inbox in `derived.db`. Im Profil lab gehen sichere Werte direkt als `auto` auf die Karte, die Inbox enthält nur, was zu entscheiden ist (Drei-Spuren-Regel). Nach jedem Durchgang meldet die Auswertung die Auto-Kontexte aus dem ersten Callback an den Daemon (Titel `(auto)`).
4. Mark-Hook: Beim C-Marker auf Kali holt `ip route get` die Quell-IP (`net.route`). Beim D-Marker liest der Daemon die Begleitdateien (z. B. `-oA scans/lame`) sicher ein und schreibt `file.observed`; die XML wird zur eigenen Einheit.
5. `ariadne show hosts` speichert alles Eingereihte, wartet auf einen Auswertungs-Durchgang und zeigt das Ergebnis.

## CLI als Ersatz für die Web-Oberfläche

| Befehl | Wirkung |
|---|---|
| `ariadne start [SLUG] [--target T] [--passphrase-fd N] [--preroll ask\|yes\|no]` | entsperren (falls nötig), Projekt öffnen oder anlegen, Vorlauf übernehmen; ohne Slug das zuletzt aktive Projekt |
| `ariadne stop` | Projekt beenden und sperren |
| `ariadne pause [--minutes N] [--terminal ID \| --all]`, `ariadne resume` | Pause dieses Terminals (Standard 10 min, wie `F12 r`) |
| `ariadne status` | Daemon, Tresor, Projekt, Leerlauf-Uhr, Vorlauf, pro Terminal Zustand und Kontext |
| `ariadne show hosts\|services\|inbox\|timeline\|keysteps\|pending` | Textansichten, alle Werte über `term_safe`, Secrets maskiert, eigene Secrets ersetzt; `auto` und Zähler der stillen Spur, Zeitachse mit «nmap 14:02: 21 Werte übernommen (ariadne undo 9f3c1a7e@1234)» |
| `ariadne search TEXT` | Volltextsuche über die Ausgabe (ohne Prompt-Echo), mit Kontext-Host |
| `ariadne undo 9f3c1a7e@1234 [--reason TEXT]` | Werte eines Befehls verwerfen (`d.unit.distrust`); Kurz-ID wie in `ariadne status` |
| `ariadne confirm g1a2b3c4d` / `ariadne confirm <claim>` | Sammelbestätigung einer Inbox-Gruppe (nur sichere Werte, der Rest wird pro Grund gemeldet) bzw. eines Claims (Präfix ab 8 Zeichen) |
| `ariadne reject <claim> [--reason]` | Claim verwerfen |
| `ariadne mark foothold\|privesc\|pivot\|loot [--host H] [--note N]` | Schlüsselschritt, im Terminal mit dessen Offset und Kontext |
| `ariadne import PFAD [--host H]` | Datei ausdrücklich übernehmen (auch ausserhalb des Arbeitsbereichs, nie über Symlinks, nie aus der Sperrliste) |
| `ariadne reparse` | `derived.db` neu bauen, atomar tauschen, Unterschiede und verwaiste Entscheide zeigen |
| `ariadne daemon stop` | Daemon beenden (offenes Projekt wird geschlossen) |
| `ariadne ui [--code \| --sessions \| --revoke [ID]] [--no-open]` | Dashboard öffnen (Startdatei mit Einmal-Code), Tippcode, Sitzungen mit Herkunft, widerrufen |
| `ariadne backup [--to-file PFAD] [--project SLUG]`, `ariadne restore [--from-file PFAD] [--identity DATEI\|-] [--no-verify]` | verschlüsselte Sicherung an die Empfänger, Wiederherstellen in eine frische Installation mit Kettenprüfung |
| `ariadne remote check [--full]`, `ariadne remote serve` | Fernzugriff prüfen; Forced Command des Mac-Schlüssels (nur über `authorized_keys`) |

## Bekannte Grenzen des v0.1-Backends

- **Etappe 4 (KI, Export, Screenshots).** Gebaut und Ende zu Ende getestet (Stand 2026-10-18), aber nur mit Fake-Anbietern: Die KI lief nie gegen die echte Anthropic-API oder ein echtes Ollama; der SSE-Fortschritt zeigt Tokens erst am Ende (kein Streaming). Screenshots nur unter X11, Bereich nur per Koordinaten, Pixel nicht geschwärzt, Bilder aus dem Ziel werden nicht ausgeliefert (kein Pillow). Der Export kennt keine Mermaid-Grafik; Credentials.md listet nur `secret_value`. «Bestätigt» und «widerlegt» eines KI-Denkanstosses unterscheiden sich nach dem Neuladen nicht (beides `done`).
- **Öffnen und Schliessen von Datenbanken nacheinander.** Die mit `sqlcipher3` gelieferte SQLite nimmt beim Öffnen einer Datei und beim Schliessen einer WAL-Verbindung dieselben zwei Sperren der Unix-VFS in umgekehrter Reihenfolge; öffnet ein Thread `state.db`, während ein anderer eine Verbindung darauf schliesst, hängt der Prozess (einmal im Fixture-Daemon der Browsertests beobachtet, gdb-Backtrace). `crypto/db.py` serialisiert darum Öffnen und Schliessen prozessweit (`_OPEN_CLOSE`, Test `tests/core/test_db_open_close.py`). Eine Verbindung, die ohne `close()` vom Garbage Collector abgeräumt wird, umgeht die Sperre.
- **Browser nur Chromium.** Die Browsertests laufen mit Chromium headless (Abschnitt «Browsertests»): `sessionStorage` nur für das Token, Tabs, `displaySafe`, strenge CSP ohne `'unsafe-inline'` (Svelte 5 und Cytoscape kommen ohne aus). Firefox und Safari sind nicht getestet; was sie bei der Navigation von der `file://`-Startdatei schicken (`Sec-Fetch-Site: cross-site`, E115), ist angenommen.
- **Peer-Prüfung.** Den Client-Socket sucht der Server per Netlink `sock_diag` (gezielt, im Loop, etwa 15 µs); nur wenn Netlink fehlt, liest er `/proc/net/tcp` (vorgefiltert nach Port). Fremde Verbindungen schliesst er so sofort; höchstens 16 Suchen in den fd-Tabellen warten gleichzeitig, jede weitere neue Verbindung wird ohne Antwort geschlossen (auch eine eigene, unter einer Flut). Der Fall IPv4-mapped über Netlink ist mangels IPv6 im Container nur mit Fixtures geprüft. Ein Shim, der während eines Stillstands des Daemons endet, sendet weder Daten noch `term.gap` (unverändert; der Stillstand selbst ist behoben).
- **Peer-Bindung.** Lokal (Weg E) gilt das Token nur aus dem Prozess, der den Code getauscht hat; stellt Firefox Anfragen aus wechselnden Prozessen, endet die Sitzung (lieber neu anmelden). Halten mehrere Prozesse den Socket, bindet der Tausch an die kleinste PID. Über sshd wird eine Verbindung ohne lesbaren Prozess angenommen, solange der gebundene sshd lebt (web-api.md 16, Punkt 8). Nach Ablauf von 12 h antwortet REST sofort mit 401, ein offener Strom schliesst bei der nächsten Prüfung (höchstens 2 s). Der Body (höchstens 1 MiB) wird vor der Token-Prüfung gelesen. Ohne IPv6 im Container ist `bind = "::1"` nur in Unit-Tests geprüft.
- **Befehlstexte im Web.** Befehlstexte und daraus abgeleitete Titel (Zeitachse, Suche, Einheit, Terminals, Belege, Arbeitsliste) maskieren bekannte Secrets aus `secret_value`, im Präsentationsmodus dazu die Secret-Bereiche der Prompt-Zeilen. Die CLI (`ariadne show timeline`, `search`) zeigt Befehlstexte weiter unmaskiert (eigenes Terminal). Die Volltextsuche verwirft Treffer, die nur dank eines eigenen Secrets entstehen (Tokenizer wie `unicode61` nachgebaut; bei Abweichungen fällt eher ein Treffer weg).
- **API.** Antworten sind noch keine Pydantic-Modelle (das OpenAPI-Schema beschreibt nur die Anfragen). Die Zeitachse trägt die jüngsten 5000 Einträge und baut die Liste pro Anfrage neu; mit `types=input` wertet sie bis 1000 Eingaben mit Echo-Vergleich aus. `lab_guard.public_targets` prüft gegen die Standard-Allowlist, nicht gegen eine Erweiterung in `config.toml`. Das Profil customer lässt sich in v0.1 nicht anlegen, «Bestätigen» ist darum nur mit lab geprüft.
- **Sicherung.** Nur geschlossene Projekte (vorher `lock` oder `stop`); während der Sicherung melden `start` und `unlock` «Gerade läuft eine Sicherung» (Markierung `.vault/.backup-running` mit PID) und öffnen nichts, danach geht `start`. Im Arbeitsbereich: Dateien von root kommen mit, fremde oder nicht lesbare werden übersprungen (Zahl in der Zusammenfassung, Namen nie); eine Datei, die nur wächst, wird mit ihrem Stand beim ersten Lesen gesichert («grown» steht nur in der Zusammenfassung, nicht im Manifest, weil das Manifest vor den Dateien kommt). Eine im Arbeitsbereich ersetzte oder am Anfang geänderte Datei bricht weiter ab (Meldung mit Projekt, ohne Dateinamen). Die Kettenprüfung nach `restore` öffnet jedes Projekt kurz (dabei verwirft der Daemon einen vorhandenen Vorlauf) und schreibt Ereignisse für Öffnen und Schliessen. Restore geht nur in eine Installation ohne Operator-Tresor, nicht ein einzelnes Projekt in eine bestehende. Nur X25519-Empfänger und -Identitäten (keine Plugins, keine SSH-Schlüssel). Die Registry liegt im `state_dir` und reist nicht mit.
- **Fernzugriff.** Im Container läuft sshd unprivilegiert und kann kein PTY übergeben: `ssh -t kali-sl unlock` und der Tippcode über einen echten sshd sind nicht Ende zu Ende geprüft (das PTY kommt in den Tests aus pexpect). `kali-setup.sh` ist nur in der Wegwerf-Wurzel geprüft (kein systemd, kein `runuser`, kein echtes `systemctl`); die erzeugten Dateien bestehen echtes `sshd -t` und `nft -c`. `ariadne-mac` ist nur unter Linux mit zsh geprüft (macOS `open`, `lsof`, `ps`, `mktemp` ungeprüft). `quick_ok` verlangt genau einen Schlüssel in `authorized_keys` und wertet alle Prüfungen ohne root aus (R10), darunter `systemctl` und `tailscale debug prefs` (höchstens 8 s je Programm); läuft systemd nicht (Container), gibt es dazu nur eine Warnung, lauscht sshd dann aber ausserhalb von Loopback auf Port 22, verweigert es den Code (fail-closed). Ohne `--full` ist «Filter-Unit aktiv» nur eine Warnung (die Tabelle selbst braucht root). `remote check` beachtet `ARIADNE_SETUP_ROOT` auch im Betrieb (sshd gibt nur Variablen aus `AcceptEnv` weiter; `--full` warnt bei mehr als `LANG`/`LC_*`). Kein automatischer Neuaufbau des Tunnels (launchd-Agent, v0.2).
- **Kein Watcher.** Dateien kommen nur als Begleitdateien eines Befehls (`companions`) oder per `ariadne import` ins Projekt. Was ein Tool ohne passende argv-Regel schreibt, bleibt unbemerkt; es gibt keinen Abgleich beim Öffnen.
- **Warteliste nur zum Lesen.** `ariadne show pending` zeigt Begleitdateien ausserhalb des Arbeitsbereichs und abgelehnte Dateien; übernehmen geht per `ariadne import`, ein Abhaken gibt es nicht.
- **Auswertung blockiert beim Schliessen kurz.** Projekt schliessen oder wechseln bricht den laufenden Durchgang vor der nächsten Einheit ab, wartet aber auf den gerade laufenden Worker (höchstens 60 s, meist unter 100 ms).
- **Ein Worker-Prozess pro Einheit**, synchron. Kein seccomp und kein Landlock (v0.2): `RLIMIT_FSIZE=0` verhindert das Schreiben von Daten, nicht aber `O_CREAT`, `O_TRUNC`, `rename` und `unlink` (Test als `xfail` markiert). Grosse Projekte brauchen beim Reparse entsprechend lange.
- **Kein Umgang mit Gift-Events.** Wirft die Projektion bei einem Event immer wieder (nicht pro Einheit, sondern z. B. in `rebuild`), rollt jeder Durchgang zurück. Aufnahme und ACKs laufen weiter, `status` und `show` nennen den Fehler; die Auswertung steht, bis der Fehler behoben ist.
- **Projektion rechnet immer alles neu** (etwa 0,7 s bei 50 Hosts mit je 25 Services).
- **Eigene Secrets stehen im Journal (E72).** Das Journal, Begleitdateien und Importe speichern alles ungeschwärzt, nur verschlüsselt. Ersetzt wird an den Ausgängen über `Redactor.redact_for_exit`/`redact_json` (Ansichten und Suche der CLI, künftig KI, Export, Bericht). Jeder neue Ausgang muss das tun; vergessene Ausgänge sind das grösste Risiko. Nur exakte Treffer der eigenen Liste; zerlegtes Echo mit Cursorbewegungen oder `\r`-Neuzeichnen trifft der Redaktor nicht.
- **Eingaben (E26).** Gespeichert wird alles, was ans Programm im PTY geht, auch Passwörter ohne Echo und Antworten des Terminals (Cursorposition, Farben). Nicht dabei: Hotkey-Präfix und -Taste, Mini-Prompt. Die CLI meldet ihr Terminal vor jedem `getpass` an (`pause_terminal`), damit Ariadnes eigene Passphrase weder ins Journal noch in den Vorlauf kommt; andere Programme, die Ariadnes Passphrase abfragen, gibt es nicht. `remote_cmd`-Einheiten fehlen (v0.2).
- **Eingaben ohne Echo (E104).** Angezeigt (`ariadne show inputs`, Web-API) werden sie nur verdeckt. Der Shim markiert den Passwortmodus des Kindes (`ECHO` aus, `ICANON` an) beim Lesen der Taste; wer vor dem Umschalten tippt (Type-ahead), bekommt kein Flag, und dann entscheidet der Echo-Vergleich. Der Echo-Vergleich (`ingest/inputs.py`) kennt nur ein einfaches Zeilenmodell (CR, LF, Backspace, CSI C/D/G/K/P/@) und merkt sich die Cursor-Spalte am Zeilenende: Bildschirm-Programme wie vim werden zu oft verdeckt; das ist gewollt. Kurze Eingaben (unter 12 Zeichen) zählen nur als Echo, wenn sie eine angezeigte Zeile beenden oder direkt vor dem Cursor stehen (rechter Prompt, Vorschläge); ein Tab gilt als Platzhalter für ein vervollständigtes Wort. Die Liste liest das Journal (`IngestService.query_journal`), nicht `derived.db`; bei sehr vielen Eingaben ist `ariadne show inputs` langsamer.
- **Entsperren (E101 bis E103).** `ariadne unlock` öffnet ein aktives Projekt wie `ariadne start`; nach einem Absturz übernimmt es den Ausfallpuffer ohne Frage (E102), auch von Terminals ohne Bindung, die nach dem Neustart aufgingen. Die gesperrte Zeit nach einem bewussten `ariadne lock` gilt nicht als Ausfallpuffer: `start`/`unlock` fragen dafür wie beim Vorlauf. Startet der Daemon nach einem `lock` neu, weiss er davon nichts mehr; was danach gepuffert wird, gilt als Ausfallpuffer.
- **Vorlauf nur im RAM des Daemons.** Ohne Projekt (oder gesperrt) hält der Daemon pro Terminal höchstens `preroll_minutes` (15) und `preroll_terminal_mib` (8 MiB), gesamt `preroll_total_mib` (64 MiB). Ein Absturz oder Neustart des Daemons verliert ihn; Swap kann ihn auslagern (`doctor` prüft verschlüsselten Swap). Kontext-Entscheide im Vorlauf werden als Schnappschuss gehalten, Schlüsselschritte ohne Projekt nicht gespeichert.
- **Shims vor dem Update (Protokoll 1)** nehmen weiter auf, aber ohne Zeitindex, ohne Eingaben und ohne `req.rebind`: Nach einem Projektwechsel bleiben sie `off`, bis das Terminal neu startet; `F12 r` pausiert sie wie neue Shims.
- **Kontext nach `F12 h`.** Die Einheiten übernehmen den Host ab dem Zeitpunkt des Entscheids, die Projektion überträgt ihn auf die ganze Stufe, die bei `from_off` lief (Stufen aus `ctx_span`, siehe `events.DCtxSet`).
- **Kontext-Entscheide ohne Aufnahme** (Pause, Remote-Sitzung beim alten Projekt, Vorlauf) wirken nur auf Stapel und Titel. Ins Journal kommen sie mit dem Schnappschuss bei der nächsten Aufnahme (im Vorlauf als gehaltener Schnappschuss), nicht als `d.ctx.set`. Schlüsselschritte ohne Aufnahme werden ohne Terminal-Offset gespeichert.
- **Jobs und `fg`.** Der Stapel führt angehaltene Jobs in der Reihenfolge des Anhaltens (auch ohne Stufe, z. B. vim). `fg %n` setzt voraus, dass keine Hintergrundjobs (`&`) die Nummern verschoben haben; `%name` gilt als unklar und aktiviert nichts. Nach einem Schnappschuss mit angehaltenen Stufen ist die Reihenfolge unbekannt, dann gilt die jüngste angehaltene Stufe.
- **D- und A-Marker im Rennen.** Der Vordergrund wird beim Lesen geprüft, nicht beim Schreiben. Hängt der Shim stark hinterher und läuft schon der nächste, vorgetippte Befehl, gilt ein echter D als nicht im Vordergrund (Stufe bleibt bis zum nächsten D offen).
- **Nonce in der Umgebung.** `ARIADNE_NONCE` bleibt exportiert, Unter-Shells brauchen sie. Ein D oder A ausserhalb des Vordergrunds setzt den Zähler aber nicht mehr hoch; gefälschte C-Marker mit geleakter Nonce bleiben möglich.
- **`zsh -ic`, `bash -ic`, `zsh -i skript`** starten ohne Shim (der Befehl läuft, wird aber nicht aufgenommen). Login-Shells bleiben Login-Shells; dabei liest die innere Shell das Profil noch einmal (`.zprofile` bzw. der Teil von `~/.profile` vor `.bashrc`).
- **Neues Terminal-Fenster aus einer aufgezeichneten Shell** (`qterminal &`, `code .`, `script`) bekommt einen eigenen Shim: «nested» gilt nur, wenn ein Shim schon genau dieses TTY aufnimmt. Läuft ein Programm in einem eigenen PTY *und* ist es im äusseren Terminal sichtbar, entsteht eine Doppelaufnahme.
- **Multiplexer (E8).** Läuft ein tmux-, screen-, zellij- oder dtach-Client im Vordergrund, nimmt der äussere Shim weder Ausgabe noch Eingaben auf (`term.gap` mit Grund `multiplexer`, Titel `[Multiplexer: Panes nehmen auf]`, `req.status` an den Daemon); die Panes haben eigene Shims. Panes ohne eigenen Shim (`tmux new-window 'ssh host'`) werden dadurch gar nicht aufgenommen.
- **Ausgabefilter fail-closed.** Hält ein Ziel eine Folge länger als 100 ms offen, geht eine angefangene ESC- oder CSI-Folge roh hinaus, wird bei Bedarf mit `CAN` beendet; ein Titel, OSC 52, Marker oder DECRQSS wird bis zum Terminator (höchstens 1 MiB) verworfen. Ein langsamer, legitimer Titel geht dabei verloren. C1-Einleitungen in UTF-8 (U+0090, U+0098, U+009B bis U+009F) erscheinen als `??`.
- **Scope.** Hostnamen mit ß, ς, ZWJ oder ZWNJ gelten als `unknown` bzw. werden als Ziel abgelehnt (IDNA2003 und UTS 46 lesen sie verschieden; bitte die `xn--`-Form angeben). Ausschlüsse für URL-Pfade greifen auch für kodierte, gross geschriebene, doppelte Schrägstriche, `;params` und `%2f`; Einschlüsse bleiben streng.
- **Gesperrt nach einem Neustart** (`locked`): Der Daemon bestätigt die Rahmen sofort und hält sie im Vorlauf (Grenzen oben). Was älter als das Fenster ist, geht verloren; `ariadne start` fragt nach der Übernahme.
- **Projektwechsel mit Remote-Sitzung (E28).** Ein Terminal bleibt beim alten Projekt (`held`, nichts wird gespeichert), bis der Shim an der lokalen Shell steht (letzter gültiger A- oder D-Marker, Stapel nur `local`/`su`, auch keine angehaltene Remote-Stufe). Eine Remote-Sitzung, die nie endet, hält das Terminal bis dahin fest.
- **Zeit (E96).** Der Zeitindex ist auf 1 ms genau (ein Eintrag pro `read()`, frühestens 1 ms nach dem letzten); Bytes, die der Ausgabefilter über eine Lesegrenze hinweg zurückhält (angefangene Escape-Folge), tragen die Zeit des späteren `read()`. `mono_ns` gilt nur innerhalb eines Boots. Programme, die selbst puffern, bleiben ungenau.
- **Alte `derived.db` nach Redaktion oder Reparse** wird vor dem Löschen mit Nullen überschrieben. Auf SSDs und Copy-on-Write-Dateisystemen ist das nur nach bestem Bemühen; ein eigener Schlüssel pro Generation (Crypto-Shredding) fehlt.
- **bash vor 5.3** liefert den Befehlstext erst im D-Marker: Session-Starter (ssh, `nc -l`) erkennt der Live-Stapel dort nicht, die Auswertung ordnet rückwirkend zu.
- **`ip route get`** nur für IP-Literale aus argv (höchstens 8 pro Befehl), nie für Namen. Fehlt `ip`, gibt es keine Quell-IP.
- **Begleitdateien** tragen die Empfangszeit im Daemon; sie erscheinen nach dem Befehl, der sie erzeugt hat, unter Umständen nach weiteren schnellen Befehlen.
- **Terminals ohne BYE** (Shim abgestürzt) bleiben im Register und bekommen kein `term.close`. Mit BYE schreibt der Daemon `term.close` auch während einer Pause. Ein Terminal, das im Vorlauf endet, bleibt übernehmbar, bis sein Fenster abläuft.
- **Drei-Spuren-Regel.** Systemkonten zählt die Projektion über das Attribut `uid` (1 bis 999); bis ein passwd-Parser (v0.2) es liefert, bleibt der Zähler 0. Ebenso kommen «vom Ziel angeboten» und «heuristisch, wichtig» erst mit Credential-Parsern im echten Betrieb vor. Hostnamen ausserhalb des Scopes, allgemeinere Versionen und ältere Zustände bleiben still. Die Sammelbestätigung lässt auch verdächtige Quellen aus; eigene Adressen in der Ausgabe der Gruppe zählt sie als `own_address`, ohne einen Claim dafür anzulegen.
- **Eigene Adressen** kennt die Auswertung nur aus `net.local_addrs` (Daemon, `/proc`) und `net.route` (`ip route get` bei IP-Literalen in argv). Fehlen beide, bleibt Kali als Nebel ohne Inbox-Eintrag stehen. Eigene Adressen verfallen nie.
- **Kontext aus dem Callback** nur im Profil lab (customer schlägt nur vor). Mehrdeutig sind mehrere erste Callbacks oder vertrauenswürdige Folge-Callbacks mit anderer IP; Callback-Zeilen, die das Ziel selbst ausgibt, zählen nicht. Offene Listener-Stufen parst die Pipeline bis 200 Zeilen sofort, danach wie bisher erst bei Stille oder Sitzungsende. Meldet die Auswertung einen Auto-Host nicht mehr, nimmt der Daemon ihn aus dem Live-Stapel aufnehmender Terminals.
- **`ariadne undo`** nur für Befehle, aus denen Werte stammen, und nur einmal (ein zweites `undo` desselben Befehls ergibt «schon rückgängig gemacht» bzw. 409, bis `d.revoke` es aufhebt). Zwischen `confirm` und `undo` gilt der spätere Entscheid; nur mit `d.claim.edit` gesetzte Werte überstehen `undo`. Eine Datei ohne Host (z. B. `loot/`) erzeugt im Profil lab «Kontext klären», das nur ein neuer Import mit `--host` löst.
- **Kurz-IDs.** `ariadne status`, `ariadne undo` und «Kontext klären» zeigen die letzten 8 Zeichen der `terminal_id` (der Anfang einer UUIDv7 ist die Startzeit und bei Terminals aus derselben Minute gleich). `undo` und `--terminal` nehmen auch den Anfang, solange er eindeutig ist.
- **Secret-Abfragen der CLI** enden nach 10 Minuten (`SECRET_PROMPT_S`), bevor die Anmeldung des Terminals (`pause_terminal`, 11 min) abläuft. Danach `ariadne start` neu aufrufen.
- **`project close`** beendet das Projekt wie `stop` (`stopped: true`, `system.project_end` mit Grund `stop`), sperrt aber nicht; gebundene Terminals gehen in `held`.
- **Leerlauf** zählt jeden Ausgaberahmen, auch im Vorlauf. Ein Programm mit Dauerausgabe (`watch`, `top`) hält das Projekt beliebig lange offen.
- **Grosse Module.** `daemon/core.py` (rund 2350 Zeilen) und `ingest/proj_build.py` (rund 1450 Zeilen) sind nach dem Umbau gross; das Aufteilen ist offen.
- Alle Messwerte stammen aus dem Container, nicht aus der Kali-VM; QTerminal ist ungeprüft.

## Offene Abweichungen von der Architektur

- **8.6, Peer-Prüfung:** `/proc/<pid>/exe` ist bei `PR_SET_DUMPABLE 0` (3.2) für denselben Benutzer nicht lesbar. Der Daemon prüft nur `comm == ariadne-shim` und die UID. Die Architektur sollte das so festhalten.
- **5.6 und 13, `forbid_dtd`:** Jede nmap-XML beginnt mit `<!DOCTYPE nmaprun>`. `parsers/safe.py` ersetzt nur eine leere DOCTYPE-Deklaration im Prolog durch Leerzeichen gleicher Länge, jede andere DTD wird weiter abgelehnt. Betrifft vermutlich auch Burp-XML.
- **3.1, Doppel-Wrapping:** «nested» gilt nicht mehr für jeden Shim unter den Vorfahren, sondern nur, wenn der Prozess direkt unter einem Vorfahren-Shim dasselbe kontrollierende Terminal hat wie die neue Shell (`/proc/<pid>/stat`, Feld `tty_nr`). Sonst bliebe jedes Fenster still unaufgezeichnet, das aus einer aufgezeichneten Shell startet. Den Multiplexer-Sonderfall braucht es dafür nicht mehr.
- **3.3 und 3.5, Kontext-Stapel:** Massgeblich ist der Stapel des Shims (er sieht alle Marker, auch ohne Aufnahme). Der Daemon übernimmt ihn per `HELLO` (neues Terminal, Daemon-Neustart) und `req.ctx.sync` (ohne Aufnahme); der Shim übernimmt `STATE.stack` nur nach einem Kontext-Entscheid oder einem automatischen Host aus der Auswertung (`STATE.ctx_version`, `host_source="auto"`, nie im Journal). Der Shim wertet wie Daemon und Segmenter `cmd_expanded` aus (Aliase).
- **3.6, Projektbindung:** Die Bindung reist im `HELLO` mit und übersteht so einen Daemon-Neustart. Kontext-Entscheide eines Terminals, das nicht aufnimmt, werden nicht gespeichert (siehe Grenzen).
- **3.7, Protokoll:** Die Felder von `HELLO` und `STATE` stehen vollständig nur im Docstring von `_shim/protocol.py` (unter anderem `gap_hint`, Lückengrund `daemon_down`, Anfrage `req.ctx.sync`); die Architektur nennt nur die wichtigsten.
- **3.8, Haltefrist:** Eine Folge, die länger als 8 KiB oder 100 ms offen bleibt, geht nicht mehr als normale Bytes weiter (fail-closed, siehe Grenzen). Abgebrochene Strings gefilterter Arten werden verworfen. Die Architektur sollte das so festhalten.
- **5.8, IDNA:** Statt IDNA2003 überall gilt für Namen mit UTS-46-Deviation-Zeichen fail-closed `unknown`.
- **8.5, Schwärzen:** Eigene Secrets unter 4 Zeichen lehnt `secrets add` ab (die Architektur nennt keine Mindestlänge).
- **7.2 und R12, Fetch-Metadaten (E115):** Eine Navigation zur SPA-Shell darf auch `cross-site` oder `same-site` sein (Startdatei aus `file://`); alles andere bleibt bei `same-origin` oder `none`.
- **4.4 und R10, Weg B ohne `ListenAddress`:** `kali-setup.sh` beschränkt sshd über den Filter auf `tailscale0` und `AllowUsers USER@100.64.0.0/10`, nicht über die Tailscale-Adresse (sshd startet beim Booten vor tailscaled).
- **4.2, R9, T10, T15, Insel-Profil:** entfällt seit E93; der Mac-Helfer öffnet den normalen Standardbrowser.
- **Vertrag v0.1-Server 3.2, `daemon.project.info.name`:** `ProjectInfo` hat kein Feld `name`; die API liest den Namen aus den Projekteinstellungen (`[project] name`).
- **`docs/web-api.md`** ist seit dem 2026-10-15 die API v2 (Pause pro Terminal, Arbeitsliste, Eingaben, Sitzungen mit Peer-Bindung); der Pfad bleibt `/api/v1`.
- **8.6, Daemon-Start:** Die systemd-Unit startet mit `python -I -m ariadne.daemon` und `WorkingDirectory=/`, ebenso `--detach` (`-I`), damit kein Modul aus dem Arbeitsordner (z. B. Loot im Home) in den Prozess mit allen Schlüsseln lädt.
