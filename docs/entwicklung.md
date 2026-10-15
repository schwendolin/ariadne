# Entwicklung

> Stand v0.1-Backend (2026-10-14, nach den Korrekturen aus drei Reviews). Ergänzt die [Lösungsarchitektur](architektur.md) um das, was man zum Arbeiten am Code braucht: Umgebung, Tests, Landkarte der Module und die bekannten Grenzen.

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
- Für einen Probelauf in einem Wegwerf-HOME: `HOME=/tmp/x ariadne setup --no-systemd`, danach `ariadne init`, `ariadne project new lame --target 10.10.10.3`, neues Terminal öffnen, `ariadne rec on`. Nie mit dem echten HOME testen, solange man nicht genau das will.

## Tests

Alle Tests laufen ohne Netz, nur in `tmp_path` und mit isolierten `HOME`/`XDG_*`-Variablen. Kein Test berührt echte Benutzerdateien.

| Ordner | Inhalt | Marker |
|---|---|---|
| `tests/unit/` | Fundament-Verträge (`test_foundation.py`), sicheres Öffnen, Kontext-argv, CLI-Ansichten, Mark-Hook-Regeln | |
| `tests/shim/` | Scanner, Marker, Hotkeys, Ringpuffer, Transport, Titel; PTY-Tests mit echter zsh/bash gegen einen Fake-Daemon | `pty` |
| `tests/core/` | Krypto, Journal- und Blob-Vertrag (Memory und SQLCipher), Redaktor, Projekte, Daemon mit Fake-Shim, CLI per Subprozess, Canary | |
| `tests/ingest/` | Scope, Ziele aus argv, Normalizer (Goldens, Hypothesis), Segmenter, Pipeline, Worker-Grenzen | |
| `tests/parsers/`, `tests/golden/` | Parser einzeln und als Golden-Fälle (`input.*`, `meta.toml`, `expected.jsonl`) | |
| `tests/projection/` | Claims, Zustände, Identität, Konflikte, Inbox, Status, Metasploitable2-Durchlauf | |
| `tests/integration/` | Daemon mit eingebauter Auswertung: Fake-Shim über echte Sockets, echte Parser in Workern, Begleitdateien, `net.route`, Ansichten, Entscheide, Import, Reparse, Redaktion | |
| `tests/e2e/` | Flugschreiber komplett: `setup`, `init`, Daemon-Prozess, zsh mit Shim per pexpect, Fake-`nmap`, Fake-`nc`, `F12 h`, CLI-Ansichten, Journal-Prüfung, Canary | `e2e`, `pty` |

Befehle:

```sh
python -m pytest                                   # alles (etwa 110 s)
python -m pytest -m "not pty and not e2e"          # ohne echte Shells (schnell)
python -m pytest tests/e2e -m e2e                  # nur der Flugschreiber
python -m pytest tests/golden --update-golden      # Golden-Erwartungen neu schreiben, zeigt vorher den Diff
ARIADNE_TEST_EXTRA_SHELLS=/pfad/zu/bash-5.3 python -m pytest tests/shim   # weitere Shells
ruff check src tests                               # Lint (Zeilenlänge 110, E F W I B UP S)
```

Regeln für neue Tests: deterministisch, kurze Socket-Pfade (`tmp_path_factory.mktemp`, AF_UNIX-Grenze), echte Shells nur mit `@pytest.mark.pty`, Zieldaten in Tests immer feindlich denken (Escape-Sequenzen, Bidi-Zeichen, gefälschte Marker). Nachgestellte Golden-Fälle sind in `meta.toml` als `source = "nachgestellt"` markiert und werden durch echte Lab-Aufnahmen ersetzt, sobald es sie gibt.

- **Ressourcen schliessen.** `pyproject.toml` macht `ResourceWarning` und nicht abfangbare Ausnahmen zu Fehlern. Dateien, Sockets, Transports und `StreamWriter` schliessen die Tests selbst; `sqlite3`-Verbindungen schliesst eine Fixture in `tests/conftest.py` am Ende jedes Tests.
- **Reihenfolge nicht annehmen.** Titel und Prompt können in beliebiger Reihenfolge ankommen. PTY-Tests prüfen Titel mit `expect_seen` (sucht auch im schon Gelesenen).
- **In einem aufgezeichneten Terminal** laufen die PTY-Tests (eigene PTYs, eigener Shim). Bei REC an landet aber die pytest-Ausgabe in der Aufnahme: Tests besser bei REC aus oder mit `ARIADNE_DISABLE=1` in einem nicht aufgezeichneten Terminal starten.
- Ein Befund wird mit einem Test behoben, der vorher scheitert. Neue Tests decken unter anderem ab: Zeitgrenzen des Ausgabefilters (Hypothesis mit einem kleinen VT500-Modell), Redaktor über Events und Stille hinweg, Kontext bei REC aus und nach einem Daemon-Neustart (E2E mit SIGKILL), mehrere Terminals gleichzeitig, Fehler der Auswertung im Daemon-Pfad, Notfallpfade des Shims (Paketkopie mit eingebautem Fehler).

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
| `_shim/launch.py`, `_shim/relay.py` | PTY anlegen, Relay-Schleife, REC-Logik, Exit-Code |
| `_shim/scanner.py`, `_shim/markers.py` | Escape-Automat, Filter (OSC 52, reflektierende Anfragen), Marker prüfen |
| `_shim/hotkey.py`, `_shim/miniprompt.py`, `_shim/title.py` | F12-Präfix, Mini-Prompt, Fenstertitel mit REC-Anzeige |
| `_shim/transport.py`, `_shim/ringbuf.py` | Verbindung zum Daemon, RAM-Puffer, Resume, Gaps |

**Daemon und Speicher**

| Datei | Aufgabe |
|---|---|
| `daemon/core.py` | Sockets, Terminal-Register, REC, Projektbindung, Hotkey-Anfragen, alle `ctl.sock`-Operationen |
| `daemon/writer.py` | Bündeln, Redaktor, `append_many`, ACK, Commit- und Mark-Hooks |
| `daemon/ingest.py` | Pipeline in eigenem Thread, entprellt nach Commits, Reparse mit Dateitausch |
| `daemon/sources.py` | Mark-Hook: Begleitdateien beim D-Marker, `ip route get` beim C-Marker; `ariadne import`; Warteliste |
| `daemon/terminal.py`, `daemon/hardening.py`, `daemon/main.py`, `daemon/client.py` | Terminal-Zustand, Härtung (Core, Dumpable, flock), Start, CLI-Client |
| `crypto/*` | SQLCipher-Verbindungen, age, versiegelte Slots, Operator-Tresor |
| `store/journal.py`, `store/blobs.py` | Journal auf SQLCipher (plus `JournalReader` für Threads), age-Blob-Store |
| `project/*` | Projekte anlegen und öffnen, Einstellungen als TOML, Lab-Leitplanke |
| `secrets/redactor.py` | der eine Redaktor für eigene Secrets |
| `sources/safeopen.py` | Dateien ohne Symlinks öffnen, `fstat`-Prüfungen, Sperrliste |

**Auswertung**

| Datei | Aufgabe |
|---|---|
| `ingest/pipeline.py` | Journal ab Wasserstand verarbeiten: Segmenter, Einheiten, Parser, Projektion |
| `ingest/seg_stream.py`, `ingest/normalizer.py` | Terminal-Strom zu Zeilen mit Offset-Karte, Alternate Screen über pyte |
| `ingest/segmenter.py`, `ingest/seg_activity.py` | Befehle, Kontextspannen, Einheiten; Aktivitätsprotokoll |
| `ingest/units.py`, `ingest/unit_store.py`, `ingest/schema_units.py`, `ingest/db.py` | Einheiten, Zeilen, FTS5, Schema von `derived.db` |
| `ingest/runner.py`, `ingest/worker.py` | Parser im Worker-Prozess ohne Schlüssel, mit rlimits; Ausgabe geprüft |
| `ingest/projection.py`, `ingest/proj_build.py`, `ingest/claims.py`, `ingest/identity.py`, `ingest/schema_claims.py` | Claims, Konfidenz, Identitäten, Konflikte, Inbox, Status, Sichten |
| `ingest/queries.py` | lesende Abfragen für die CLI-Ansichten, Suche, Reparse-Diff |
| `parsers/*` | `nmap.xml`, `nmap.text`, `regex.net`, `listener.callback`, sichere XML- und Regex-Bausteine, Registry |
| `scope/*` | Normalisierung, `ScopeMatcher`, Ziele aus argv |

**CLI**: `cli/main.py` (alle Befehle), `cli/views.py` (Textansichten), `cli/setup.py` (Installer), `cli/doctor.py`.

**Leer (spätere Versionen)**: `ai/`, `rules/`, `export/`, `web/` (nur die gebaute SPA unter `web/static/`, ohne API).

## Ablauf eines Befehls

1. zsh sendet vor dem Befehl den C-Marker, danach den D-Marker. Der Shim prüft Nonce und Vordergrund und schickt `term.mark` und die Ausgabe (`OUT`) an den Daemon.
2. Der Writer schwärzt eigene Secrets, schreibt alle 200 ms in `journal.db` und bestätigt dem Shim.
3. Commit-Hook: Die Auswertung verarbeitet nach 500 ms Ruhe die neuen Events im eigenen Thread. Fertige Einheiten gehen an die Parser im Worker, die Projektion berechnet Claims, Hosts, Services und Inbox in `derived.db`.
4. Mark-Hook: Beim C-Marker auf Kali holt `ip route get` die Quell-IP (`net.route`). Beim D-Marker liest der Daemon die Begleitdateien (z. B. `-oA scans/lame`) sicher ein und schreibt `file.observed`; die XML wird zur eigenen Einheit.
5. `ariadne show hosts` speichert alles Eingereihte, wartet auf einen Auswertungs-Durchgang und zeigt das Ergebnis.

## CLI als Ersatz für die Web-Oberfläche

| Befehl | Wirkung |
|---|---|
| `ariadne show hosts\|services\|inbox\|timeline\|keysteps\|pending` | Textansichten, alle Werte über `term_safe`, Secrets maskiert |
| `ariadne search TEXT` | Volltextsuche über die Ausgabe (ohne Prompt-Echo), mit Kontext-Host |
| `ariadne confirm g1a2b3c4d` / `ariadne confirm <claim>` | Sammelbestätigung einer Inbox-Gruppe bzw. eines Claims (Präfix ab 8 Zeichen) |
| `ariadne reject <claim> [--reason]` | Claim verwerfen |
| `ariadne mark foothold\|privesc\|pivot\|loot [--host H] [--note N]` | Schlüsselschritt, im Terminal mit dessen Offset und Kontext |
| `ariadne import PFAD [--host H]` | Datei ausdrücklich übernehmen (auch ausserhalb des Arbeitsbereichs, nie über Symlinks, nie aus der Sperrliste) |
| `ariadne reparse` | `derived.db` neu bauen, atomar tauschen, Unterschiede und verwaiste Entscheide zeigen |
| `ariadne daemon stop` | Daemon beenden (offenes Projekt wird geschlossen) |

## Bekannte Grenzen des v0.1-Backends

- **Keine Web-API und kein Export.** Die Svelte-Oberfläche liegt gebaut unter `web/static/`, die FastAPI-Routen fehlen. Regeln, KI-Denkanstösse, Screenshots und Markdown-Export sind noch nicht gebaut.
- **Kein Watcher.** Dateien kommen nur als Begleitdateien eines Befehls (`companions`) oder per `ariadne import` ins Projekt. Was ein Tool ohne passende argv-Regel schreibt, bleibt unbemerkt; es gibt keinen Abgleich beim Öffnen.
- **Warteliste nur zum Lesen.** `ariadne show pending` zeigt Begleitdateien ausserhalb des Arbeitsbereichs und abgelehnte Dateien; übernehmen geht per `ariadne import`, ein Abhaken gibt es nicht.
- **Auswertung blockiert beim Schliessen kurz.** Projekt schliessen oder wechseln bricht den laufenden Durchgang vor der nächsten Einheit ab, wartet aber auf den gerade laufenden Worker (höchstens 60 s, meist unter 100 ms).
- **Ein Worker-Prozess pro Einheit**, synchron. Kein seccomp und kein Landlock (v0.2): `RLIMIT_FSIZE=0` verhindert das Schreiben von Daten, nicht aber `O_CREAT`, `O_TRUNC`, `rename` und `unlink` (Test als `xfail` markiert). Grosse Projekte brauchen beim Reparse entsprechend lange.
- **Kein Umgang mit Gift-Events.** Wirft die Projektion bei einem Event immer wieder (nicht pro Einheit, sondern z. B. in `rebuild`), rollt jeder Durchgang zurück. Aufnahme und ACKs laufen weiter, `status` und `show` nennen den Fehler; die Auswertung steht, bis der Fehler behoben ist.
- **Projektion rechnet immer alles neu** (etwa 0,7 s bei 50 Hosts mit je 25 Services).
- **Rückhalt des Redaktors.** Die letzten `max_len - 1` Zeichen der Sicht (längstes eigenes Secret minus eins) warten auf weitere Ausgabe. Vor einem anderen Event und nach 10 s Stille wird alles frei, was kein eigenes Secret beginnen kann; ein echter Secret-Anfang bleibt, Events dahinter warten und gehen an ihrer Stromposition ins Journal. Hart frei geben nur REC aus, Projektwechsel, Pause und das Ende des Terminals. ACKs können entsprechend nachhinken. `show` erzwingt bewusst keinen Flush.
- **Redaktor und Zeilenbearbeitung.** Die Sicht wendet Backspace an (Tippfehler im Echo), nicht aber Cursorbewegungen, `\r`-Neuzeichnen oder das Ersetzen des ganzen Echo-Bereichs B bis C nach einem Treffer im Befehlstext (Architektur 8.5 Punkt 2, dafür bräuchte es eine nachträgliche Redaktion). Felder an der Längengrenze der Hooks (Befehl 1000, PWD 300 Zeichen) schwärzt der Daemon auch, wenn sie mit dem Anfang eines eigenen Secrets enden; Variablen über 128 Zeichen schicken die Hooks gar nicht.
- **Kontext nach `F12 h`.** Die Einheiten übernehmen den Host ab dem Zeitpunkt des Entscheids, die Projektion überträgt ihn auf die ganze Stufe, die bei `from_off` lief (Stufen aus `ctx_span`, siehe `events.DCtxSet`).
- **Kontext-Entscheide bei REC aus** (Hotkey, `ariadne ctx`) wirken nur auf Stapel und Titel. Ins Journal kommen sie mit dem Schnappschuss beim nächsten REC an (der Host steht dann in der Stufe), nicht als `d.ctx.set`. Schlüsselschritte bei REC aus werden ohne Terminal-Offset gespeichert.
- **Jobs und `fg`.** Der Stapel führt angehaltene Jobs in der Reihenfolge des Anhaltens (auch ohne Stufe, z. B. vim). `fg %n` setzt voraus, dass keine Hintergrundjobs (`&`) die Nummern verschoben haben; `%name` gilt als unklar und aktiviert nichts. Nach einem Schnappschuss mit angehaltenen Stufen ist die Reihenfolge unbekannt, dann gilt die jüngste angehaltene Stufe.
- **D- und A-Marker im Rennen.** Der Vordergrund wird beim Lesen geprüft, nicht beim Schreiben. Hängt der Shim stark hinterher und läuft schon der nächste, vorgetippte Befehl, gilt ein echter D als nicht im Vordergrund (Stufe bleibt bis zum nächsten D offen).
- **Nonce in der Umgebung.** `ARIADNE_NONCE` bleibt exportiert, Unter-Shells brauchen sie. Ein D oder A ausserhalb des Vordergrunds setzt den Zähler aber nicht mehr hoch; gefälschte C-Marker mit geleakter Nonce bleiben möglich.
- **`zsh -ic`, `bash -ic`, `zsh -i skript`** starten ohne Shim (der Befehl läuft, wird aber nicht aufgenommen). Login-Shells bleiben Login-Shells; dabei liest die innere Shell das Profil noch einmal (`.zprofile` bzw. der Teil von `~/.profile` vor `.bashrc`).
- **Neues Terminal-Fenster aus einer aufgezeichneten Shell** (`qterminal &`, `code .`, `script`) bekommt einen eigenen Shim: «nested» gilt nur, wenn ein Shim schon genau dieses TTY aufnimmt. Läuft ein Programm in einem eigenen PTY *und* ist es im äusseren Terminal sichtbar, entsteht eine Doppelaufnahme.
- **Multiplexer.** Läuft ein tmux-, screen-, zellij- oder dtach-Client im Vordergrund, nimmt der äussere Shim nichts auf (`term.gap` mit Grund `multiplexer`); die Panes haben eigene Shims. Panes ohne eigenen Shim (`tmux new-window 'ssh host'`) werden dadurch gar nicht aufgenommen.
- **Ausgabefilter fail-closed.** Hält ein Ziel eine Folge länger als 100 ms offen, geht eine angefangene ESC- oder CSI-Folge roh hinaus, wird bei Bedarf mit `CAN` beendet; ein Titel, OSC 52, Marker oder DECRQSS wird bis zum Terminator (höchstens 1 MiB) verworfen. Ein langsamer, legitimer Titel geht dabei verloren. C1-Einleitungen in UTF-8 (U+0090, U+0098, U+009B bis U+009F) erscheinen als `??`.
- **Scope.** Hostnamen mit ß, ς, ZWJ oder ZWNJ gelten als `unknown` bzw. werden als Ziel abgelehnt (IDNA2003 und UTS 46 lesen sie verschieden; bitte die `xn--`-Form angeben). Ausschlüsse für URL-Pfade greifen auch für kodierte, gross geschriebene, doppelte Schrägstriche, `;params` und `%2f`; Einschlüsse bleiben streng.
- **Daemon-Puffer im Zustand `waiting`** (Projekt gesperrt) höchstens 16 MiB. Darüber nimmt der Daemon nichts mehr an und bestätigt nichts; der Shim hält die Rahmen (32 MiB) und sendet sie nach dem Entsperren erneut. Hotkey-Anfragen wirken trotzdem sofort, nur einmal.
- **Alte `derived.db` nach Redaktion oder Reparse** wird vor dem Löschen mit Nullen überschrieben. Auf SSDs und Copy-on-Write-Dateisystemen ist das nur nach bestem Bemühen; ein eigener Schlüssel pro Generation (Crypto-Shredding) fehlt.
- **bash vor 5.3** liefert den Befehlstext erst im D-Marker: Session-Starter (ssh, `nc -l`) erkennt der Live-Stapel dort nicht, die Auswertung ordnet rückwirkend zu.
- **`ip route get`** nur für IP-Literale aus argv (höchstens 8 pro Befehl), nie für Namen. Fehlt `ip`, gibt es keine Quell-IP.
- **Zeitachse sortiert nach Speicherzeit.** `term.out` und Shim-Events tragen die Empfangszeit im Daemon, Begleitdateien erscheinen nach dem Befehl, der sie erzeugt hat, aber unter Umständen nach weiteren schnellen Befehlen.
- **Terminals ohne BYE** (Shim abgestürzt) bleiben im Register und bekommen kein `term.close`. Mit BYE schreibt der Daemon `term.close` auch bei REC aus.
- Alle Messwerte stammen aus dem Container, nicht aus der Kali-VM; QTerminal ist ungeprüft.

## Offene Abweichungen von der Architektur

- **8.6, Peer-Prüfung:** `/proc/<pid>/exe` ist bei `PR_SET_DUMPABLE 0` (3.2) für denselben Benutzer nicht lesbar. Der Daemon prüft nur `comm == ariadne-shim` und die UID. Die Architektur sollte das so festhalten.
- **5.6 und 13, `forbid_dtd`:** Jede nmap-XML beginnt mit `<!DOCTYPE nmaprun>`. `parsers/safe.py` ersetzt nur eine leere DOCTYPE-Deklaration im Prolog durch Leerzeichen gleicher Länge, jede andere DTD wird weiter abgelehnt. Betrifft vermutlich auch Burp-XML.
- **3.1, Doppel-Wrapping:** «nested» gilt nicht mehr für jeden Shim unter den Vorfahren, sondern nur, wenn der Prozess direkt unter einem Vorfahren-Shim dasselbe kontrollierende Terminal hat wie die neue Shell (`/proc/<pid>/stat`, Feld `tty_nr`). Sonst bliebe jedes Fenster still unaufgezeichnet, das aus einer aufgezeichneten Shell startet. Den Multiplexer-Sonderfall braucht es dafür nicht mehr.
- **3.3 und 3.5, Kontext-Stapel:** Massgeblich ist der Stapel des Shims (er sieht alle Marker, auch bei REC aus). Der Daemon übernimmt ihn per `HELLO` (neues Terminal, Daemon-Neustart) und `req.ctx.sync` (REC aus); der Shim übernimmt `STATE.stack` nur nach einem Kontext-Entscheid (`STATE.ctx_version`). Der Shim wertet wie Daemon und Segmenter `cmd_expanded` aus (Aliase).
- **3.6, Projektbindung:** Die Bindung reist im `HELLO` mit und übersteht so einen Daemon-Neustart. Kontext-Entscheide eines Terminals, das nicht aufnimmt, werden nicht gespeichert (siehe Grenzen).
- **3.7, Protokoll:** `HELLO` trägt zusätzlich `stack`, `bound_project_id`, `bound_slug` und `gap_hint`, `STATE` zusätzlich `ctx_version` und `daemon_id` (Neustart erkennen, Lückengrund `daemon_down`). Neue Anfrage `req.ctx.sync`, neuer Lückengrund `multiplexer`.
- **3.8, Haltefrist:** Eine Folge, die länger als 8 KiB oder 100 ms offen bleibt, geht nicht mehr als normale Bytes weiter (fail-closed, siehe Grenzen). Abgebrochene Strings gefilterter Arten werden verworfen. Die Architektur sollte das so festhalten.
- **5.8, IDNA:** Statt IDNA2003 überall gilt für Namen mit UTS-46-Deviation-Zeichen fail-closed `unknown`.
- **8.5, Rückhalt:** Events geben nur frei, was kein eigenes Secret beginnen kann, und warten sonst hinter dem Rückhalt; Begleitdateien und Importe laufen vor dem Speichern durch den Redaktor (`file.observed.redactions`). Eigene Secrets unter 4 Zeichen lehnt `secrets add` ab.
- **8.6, Daemon-Start:** Die systemd-Unit startet mit `python -I -m ariadne.daemon` und `WorkingDirectory=/`, ebenso `--detach` (`-I`), damit kein Modul aus dem Arbeitsordner (z. B. Loot im Home) in den Prozess mit allen Schlüsseln lädt.
