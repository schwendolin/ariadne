# Entwicklung

> Stand v0.1-Backend (2026-10-14, nach den Korrekturen aus drei Reviews), Erfassung, Bedienung und Auswertung nach den Entscheiden vom 2026-10-15 (E22, E23, E26, E28, E42, E45, E72, E88, E95, E96; Vertrag v0.1-Bedienung), integriert und Ende zu Ende getestet am 2026-10-15. Bau v0.1-Server, Phase 1 (2026-10-15, nach einem Neustart geprüft am 2026-10-17): E101 bis E104, API v2 (`docs/web-api.md`), Erweiterungspunkte im Daemon und Grundgerüste für Web-Server, API, Sicherung und Fernzugriff. Ergänzt die [Lösungsarchitektur](architektur.md) um das, was man zum Arbeiten am Code braucht: Umgebung, Tests, Landkarte der Module und die bekannten Grenzen.

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
| `tests/web/server/`, `tests/web/api/`, `tests/backup/`, `tests/remote/` | Bau v0.1-Server (Vertrag v0.1-Server, Tests T1 bis T16 aus dem Konzept Fernzugriff); Tests mit echtem Server auf einem freien Loopback-Port tragen `web`, Tests mit `sshd` tragen `remote` (ohne `sshd` übersprungen). Daemon-Prozesse der Tests laufen mit `ARIADNE_WEB=0` | `web`, `remote` |

Befehle:

```sh
python -m pytest                                   # alles (etwa 3 min, 1129 Tests)
python -m pytest -m "not pty and not e2e"          # ohne echte Shells (schnell)
python -m pytest -m remote                          # nur Tunnel-Tests mit sshd
python -m pytest tests/e2e -m e2e                  # nur der Flugschreiber
python -m pytest tests/golden --update-golden      # Golden-Erwartungen neu schreiben, zeigt vorher den Diff
ARIADNE_TEST_EXTRA_SHELLS=/pfad/zu/bash-5.3 python -m pytest tests/shim   # weitere Shells
ruff check src tests                               # Lint (Zeilenlänge 110, E F W I B UP S)
```

Regeln für neue Tests: deterministisch, kurze Socket-Pfade (`tmp_path_factory.mktemp`, AF_UNIX-Grenze), echte Shells nur mit `@pytest.mark.pty`, Zieldaten in Tests immer feindlich denken (Escape-Sequenzen, Bidi-Zeichen, gefälschte Marker). Nachgestellte Golden-Fälle sind in `meta.toml` als `source = "nachgestellt"` markiert und werden durch echte Lab-Aufnahmen ersetzt, sobald es sie gibt.

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

**Im Bau v0.1-Server** (Phase 1 hat Stubs mit festen Signaturen angelegt, Vertrag v0.1-Server): `web/` (Server-Kern, Sicherheit, Sitzungen, SSE; `web/api/` Routen der API v2; die gebaute SPA unter `web/static/` bleibt), `backup/` (Sicherung und Wiederherstellung), `remote/` (`remote check`, `remote serve`), CLI `cli/ui.py`, `cli/backup.py`, `cli/remote.py`. Jedes Stub-Modul trägt `STUB = True`, bis sein Teil steht.

**Leer (spätere Versionen)**: `ai/` und `export/` (nur der Hinweis, dass jeder Ausgang `Redactor.redact_for_exit` nutzen muss), `rules/`.

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

## Bekannte Grenzen des v0.1-Backends

- **Web-API im Bau, kein Export.** Die Svelte-Oberfläche liegt gebaut unter `web/static/` (Mock-Modus); die API v2 ist spezifiziert (`docs/web-api.md`), Server und Routen entstehen im Bau v0.1-Server. Regeln, KI-Denkanstösse, Screenshots und Markdown-Export sind noch nicht gebaut.
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
- **`ariadne undo`** nur für Befehle, aus denen Werte stammen. Zwischen `confirm` und `undo` gilt der spätere Entscheid; nur mit `d.claim.edit` gesetzte Werte überstehen `undo`. Eine Datei ohne Host (z. B. `loot/`) erzeugt im Profil lab «Kontext klären», das nur ein neuer Import mit `--host` löst.
- **Kurz-IDs.** `ariadne status`, `ariadne undo` und «Kontext klären» zeigen die letzten 8 Zeichen der `terminal_id` (der Anfang einer UUIDv7 ist die Startzeit und bei Terminals aus derselben Minute gleich). `undo` und `--terminal` nehmen auch den Anfang, solange er eindeutig ist.
- **Secret-Abfragen der CLI** enden nach 10 Minuten (`SECRET_PROMPT_S`), bevor die Anmeldung des Terminals (`pause_terminal`, 11 min) abläuft. Danach `ariadne start` neu aufrufen.
- **`project close`** beendet das Projekt wie `stop` (`stopped: true`, `system.project_end` mit Grund `stop`), sperrt aber nicht; gebundene Terminals gehen in `held`.
- **Leerlauf** zählt jeden Ausgaberahmen, auch im Vorlauf. Ein Programm mit Dauerausgabe (`watch`, `top`) hält das Projekt beliebig lange offen.
- **Grosse Module.** `daemon/core.py` (rund 1950 Zeilen) und `ingest/proj_build.py` (rund 1400 Zeilen) sind nach dem Umbau gross; das Aufteilen ist offen.
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
- **`docs/web-api.md`** ist seit dem 2026-10-15 die API v2 (Pause pro Terminal, Arbeitsliste, Eingaben, Sitzungen mit Peer-Bindung); der Pfad bleibt `/api/v1`.
- **8.6, Daemon-Start:** Die systemd-Unit startet mit `python -I -m ariadne.daemon` und `WorkingDirectory=/`, ebenso `--detach` (`-I`), damit kein Modul aus dem Arbeitsordner (z. B. Loot im Home) in den Prozess mit allen Schlüsseln lädt.
