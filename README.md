# Ariadne

Flugschreiber und Kartograf für Pentests unter Linux. Ariadne nimmt Terminals, Dateien und Screenshots auf, liest daraus Hosts, Services und Zugänge aus und malt Schritt für Schritt eine Karte der Zielumgebung. Zu jedem Fakt zeigt es die Quelle. Ariadne beobachtet und gibt Denkanstösse, greift aber nie selbst an.

Status: v0.1 im Bau (Stand 2026-10-18). Aufnahme, verschlüsseltes Journal und Auswertung mit Karte laufen über die CLI; dazu das Dashboard im Browser nach Design v0.1 (Karte, «Als Nächstes» mit Denkanstössen aus Regeln, Terminals, Zeitachse, Belege, Findings), Sicherung und Fernzugriff vom Mac, seit Etappe 4 auch KI-Denkanstösse auf Knopfdruck, Screenshots (X11) und der Bericht-Export als Markdown. Nicht für Kundendaten.

## Im Alltag

Einmal einrichten (Kali, normaler Benutzer):

```sh
pipx install <wheel oder git-URL>   # Paket ariadne-recon, Befehl ariadne
ariadne setup                        # Zeile in .zshrc/.bashrc, systemd-Dienst
ariadne init                         # Operator-Tresor: Passphrase, Recovery-Code offline aufbewahren
ariadne ai setup                     # optional: KI-Anbieter (cloud oder local) und Modell-ID
```

Alle Wege ins private Repo (Deploy-Key, Token ohne Echo, Wheel über die Datei-Übertragung) und die Prüfung mit `ariadne doctor` stehen in [docs/installation.md](docs/installation.md).

Danach offene Terminals einmal neu öffnen. Ohne Projekt zeigt der Fenstertitel `[kein Projekt (Vorlauf 15 min)]`: Ariadne hält die letzten Minuten nur im Arbeitsspeicher.

Pro Lab und nach jedem Neustart der VM:

```sh
ariadne start lame --target 10.10.10.3   # Passphrase, Projekt anlegen oder öffnen
ariadne start                            # später: das zuletzt aktive Projekt
```

`ariadne start` fragt, ob die letzten Minuten aus dem Vorlauf übernommen werden sollen. Ab dann nehmen alle Terminals auf, auch parallele, mit der Zeit des Shims auf etwa 1 ms genau. Titel: `[REC lame]`.

Arbeiten wie immer. Ein `nmap -sV -oA scans/lame 10.10.10.3` setzt Hosts und Services direkt auf die Karte, markiert als «auto». Kommt eine Reverse Shell auf einen Listener, setzt Ariadne den Host aus dem ersten Callback selbst (`(auto)` im Titel); bei Pivots oder Port-Forwards setzt du ihn mit `F12` und `h`.

| Was | Wie |
|---|---|
| dieses Terminal 10 Minuten pausieren | `F12` `r` (nochmals `F12` `r` setzt fort) oder `ariadne pause [--minutes N]`, `ariadne resume` |
| Zustand ansehen | `ariadne status` (Projekt, Leerlauf-Uhr, Vorlauf, Zustand pro Terminal) |
| Karte und Arbeitsliste | `ariadne show hosts`, `ariadne show services`, `ariadne show inbox` |
| Zeitachse | `ariadne show timeline` («nmap 14:02: 21 Werte übernommen (ariadne undo 9f3c1a7e@1234)») |
| Werte eines Befehls verwerfen | `ariadne undo 9f3c1a7e@1234 --reason "falsches Ziel"` |
| Wert bestätigen oder verwerfen | `ariadne confirm <claim>`, `ariadne reject <claim>` |
| Schlüsselschritt | `F12` `k` oder `ariadne mark foothold` |
| Suche | `ariadne search "vsftpd 2.3.4"` |

Die Inbox enthält nur, was du entscheiden musst: KI-Werte, echte Widersprüche, unklarer Kontext. Unsicheres bleibt als Nebel oder Zähler.

Am Ende:

```sh
ariadne stop    # Projekt beenden und sperren
```

Nach 12 Stunden ohne Ausgabe in irgendeinem Terminal beendet Ariadne das Projekt von selbst. `ariadne lock` sperrt nur, das Projekt bleibt aktiv; `ariadne unlock` entsperrt und öffnet es wieder, die Aufnahme läuft sofort weiter. Eigene Secrets (`ariadne secrets add`) stehen verschlüsselt im Journal und werden vor KI, Export und Bericht ersetzt. Passwörter, die du ohne Echo tippst (sudo, ssh, su), speichert Ariadne vollständig, zeigt sie aber verdeckt (`ariadne show inputs`).

## Dashboard

Der Daemon liefert das Dashboard nur auf `127.0.0.1:7330` aus. Anmelden geht nur mit einem Einmal-Code aus der CLI, nie mit der Passphrase:

```sh
ariadne ui              # Browser der Kali öffnen (Startdatei mit Code, nach 10 s gelöscht)
ariadne ui --code       # kurzen Code zum Eintippen zeigen
ariadne ui --sessions   # angemeldete Sitzungen mit Herkunft (lokal oder über sshd)
ariadne ui --revoke     # alle abmelden
```

Eine Anmeldung gilt höchstens 12 Stunden und endet mit `lock`, `stop`, einem Neustart des Daemons und dem Tunnel. Einstellungen in `~/.config/ariadne/config.toml` unter `[ui]` (nur Loopback).

Im Dashboard steht links die Karte (Kali, Scope-Segmente, Hosts mit Zugriff, Nebel und Sackgassen, der rote Faden der Schlüsselschritte), rechts die Spalte «Als Nächstes»: zuerst, was du klären musst (Kontext einer Reverse Shell, Zusammenführen, Widersprüche), dann Denkanstösse mit Begründung, Beleg und Befehlsvorlage zum Kopieren. Ausgeführt wird nie etwas. Dazu die Reiter Terminals, Zeitachse (mit Rückgängig pro Befehl) und Findings; jeder Wert führt zu seinem Beleg bis zur Logzeile. Tasten: `1` bis `4` Reiter, `j k` wechseln, `a x e u` annehmen, verwerfen, ändern, rückgängig, `↵` Beleg, `⌘K` bzw. `Strg K` Palette, `⇧P` Präsentationsmodus (Secrets und Eingaben ohne Echo bleiben verdeckt), `?` Hilfe. Secrets kopiert «In die Kali» über den Daemon, nie in die Zwischenablage des Browsers. Die Schnittstelle beschreibt [docs/web-api.md](docs/web-api.md), die Oberfläche [webui/README.md](webui/README.md).

## KI, Screenshots und Export

- **KI-Denkanstoss** (optional): Knopf «Denkanstoss anfordern (KI)» in der Spalte «Als Nächstes». Ariadne schickt ein knappes Lagebild aus der Karte (nie Rohausgaben, eigene Secrets ersetzt) an den Anbieter aus `ariadne ai setup`: `cloud` (Anthropic-API, pro Projekt mit `ariadne ai allow-cloud` freigeben) oder `local` (Ollama auf `127.0.0.1`). Zurück kommen höchstens vier geprüfte Hypothesen, Fragen oder Prüfziele mit «bestätigt, wenn» und «widerlegt, wenn»; Befehle nur aus der Vorlagenbibliothek. Monatslimit mit Warnung ab 80 %; `ariadne ai status` zeigt den Verbrauch.
- **Screenshots** (X11): `F12 s` im Terminal (aktives Fenster), `ariadne shot window|monitor|region`, im Dashboard mit Countdown. Gespeichert verschlüsselt als PNG ohne Metadaten, mit Terminal, Host und Zeit; die Pixel selbst werden nicht geschwärzt.
- **Export**: `ariadne export` (Vorlage `cys`, `--template htb`) oder «Export» im Dashboard schreibt Markdown nach `~/ariadne/<projekt>/exports/<zeit>-<vorlage>/`: Übersicht, Angriffspfad, Writeup nach Phasen, Findings, Hosts, Zeitachse, Belege mit Kettenkopf und `manifest.json`. Ziel-Credentials sind maskiert; Klartext nur im Terminal (`--klartext`, Profil lab). Phasen der Befehle prüfst und korrigierst du in der Zeitachse oder mit `ariadne export --phasen` und `--phase`.

## Sicherung

Die Schule kann die VM jederzeit zurücksetzen. Darum nach jeder Session sichern, verschlüsselt mit age an Empfänger ausserhalb der VM (`~/.config/ariadne/backup-recipients.txt`, eine Zeile `age1…` pro Empfänger):

```sh
ariadne stop                                  # danach zeigt Ariadne, ob eine Sicherung fehlt
ariadne backup --to-file ~/Abgabe/sicherung.age
ariadne restore --from-file sicherung.age --identity -   # in einer frischen Kali ohne ariadne init
```

Gesichert werden der Operator-Tresor, die Konfiguration und die Projekte, nur geschlossene. `restore` prüft Manifest, Version und alle Hashes, bevor es etwas schreibt, und danach jede Kette.

## Fernzugriff vom Mac

Mit Tailscale und SSH erscheint das Dashboard im Browser des Macs, die Passphrase tippst du im Mac-Terminal (`ariadne-mac unlock`), und `ariadne-mac stop` holt die Sicherung auf den Mac. Der SSH-Schlüssel des Macs öffnet nur den Tunnel zu Port 7330 und sieben feste Befehle, nie eine Shell. Einrichten mit `packaging/smartlearn/kali-setup.sh` in der Kali und `packaging/mac/ariadne-mac` auf dem Mac, prüfen mit `ariadne remote check --full`. Schritt für Schritt: [docs/anleitung-fernzugriff.md](docs/anleitung-fernzugriff.md).

## Dokumente

- [Vision](VISION.md): Zielbild, Grundsätze, Roadmap, offene Punkte
- [Lösungsarchitektur](docs/architektur.md): Teilsysteme, Datenmodell, Sicherheitsarchitektur, Roadmap im Detail
- [Entwicklung](docs/entwicklung.md): Umgebung, Tests, Landkarte der Module, bekannte Grenzen
- [Web-API](docs/web-api.md): HTTP-Schnittstelle des Dashboards (v2)
- [Installation](docs/installation.md) und [Praxistest](docs/praxistest.md): Installation in der Kali, Checkliste für den ersten echten Lauf
- [Anleitung Fernzugriff](docs/anleitung-fernzugriff.md) und [Konzept Fernzugriff](docs/konzept-fernzugriff.md): Dashboard auf dem Mac, Sicherung, Sicherheitskonzept
- [Entscheidungsprotokoll](docs/entscheide.md): was entschieden wurde, warum und von wem
- [Fragenkatalog](docs/fragenkatalog.md): Brainstorming mit Antwortoptionen und Empfehlungen
