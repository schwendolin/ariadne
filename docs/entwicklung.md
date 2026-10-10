# Entwicklung

> Stand v0.1-Backend (2026-10-10). Ergänzt die [Lösungsarchitektur](architektur.md) um das, was man zum Arbeiten am Code braucht: Umgebung, Tests, Landkarte der Module und die bekannten Grenzen.

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
python -m pytest                                   # alles (etwa 90 s)
python -m pytest -m "not pty and not e2e"          # ohne echte Shells (schnell)
python -m pytest tests/e2e -m e2e                  # nur der Flugschreiber
python -m pytest tests/golden --update-golden      # Golden-Erwartungen neu schreiben, zeigt vorher den Diff
ARIADNE_TEST_EXTRA_SHELLS=/pfad/zu/bash-5.3 python -m pytest tests/shim   # weitere Shells
ruff check src tests                               # Lint (Zeilenlänge 110, E F W I B UP S)
```

Regeln für neue Tests: deterministisch, kurze Socket-Pfade (`tmp_path_factory.mktemp`, AF_UNIX-Grenze), echte Shells nur mit `@pytest.mark.pty`, Zieldaten in Tests immer feindlich denken (Escape-Sequenzen, Bidi-Zeichen, gefälschte Marker). Nachgestellte Golden-Fälle sind in `meta.toml` als `source = "nachgestellt"` markiert und werden durch echte Lab-Aufnahmen ersetzt, sobald es sie gibt.

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
- **Ein Worker-Prozess pro Einheit**, synchron. Kein seccomp und kein Landlock (v0.2). Grosse Projekte brauchen beim Reparse entsprechend lange.
- **Projektion rechnet immer alles neu** (etwa 0,7 s bei 50 Hosts mit je 25 Services).
- **Rückhalt des Redaktors.** Bis zur Länge des längsten eigenen Secrets minus eins bleibt am Stromende zurück, bis der nächste Marker oder 10 s Stille kommt. `show` erzwingt bewusst keinen Flush.
- **Kontext nach `F12 h`.** Die Einheiten übernehmen den Host ab dem Zeitpunkt des Entscheids, die Projektion überträgt ihn auf die ganze Stufe (siehe `events.DCtxSet`).
- **bash vor 5.3** liefert den Befehlstext erst im D-Marker: Session-Starter (ssh, `nc -l`) erkennt der Live-Stapel dort nicht, die Auswertung ordnet rückwirkend zu.
- **`ip route get`** nur für IP-Literale aus argv (höchstens 8 pro Befehl), nie für Namen. Fehlt `ip`, gibt es keine Quell-IP.
- **Zeitachse sortiert nach Speicherzeit.** Begleitdateien erscheinen nach dem Befehl, der sie erzeugt hat, aber unter Umständen nach weiteren schnellen Befehlen.
- **Terminals ohne BYE** bleiben im Register und bekommen kein `term.close`.
- Alle Messwerte stammen aus dem Container, nicht aus der Kali-VM; QTerminal ist ungeprüft.

## Offene Abweichungen von der Architektur

- **8.6, Peer-Prüfung:** `/proc/<pid>/exe` ist bei `PR_SET_DUMPABLE 0` (3.2) für denselben Benutzer nicht lesbar. Der Daemon prüft nur `comm == ariadne-shim` und die UID. Die Architektur sollte das so festhalten.
- **5.6 und 13, `forbid_dtd`:** Jede nmap-XML beginnt mit `<!DOCTYPE nmaprun>`. `parsers/safe.py` ersetzt nur eine leere DOCTYPE-Deklaration im Prolog durch Leerzeichen gleicher Länge, jede andere DTD wird weiter abgelehnt. Betrifft vermutlich auch Burp-XML.
