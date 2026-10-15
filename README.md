# Ariadne

Flugschreiber und Kartograf für Pentests unter Linux. Ariadne nimmt Terminals, Dateien und Screenshots auf, liest daraus Hosts, Services und Zugänge aus und malt Schritt für Schritt eine Karte der Zielumgebung. Zu jedem Fakt zeigt es die Quelle. Ariadne beobachtet und gibt Denkanstösse, greift aber nie selbst an.

Status: v0.1-Backend (Stand 2026-10-15). Aufnahme, verschlüsseltes Journal und Auswertung mit Karte über die CLI laufen; Web-API, Regeln, KI und Export folgen. Nicht für Kundendaten.

## Im Alltag

Einmal einrichten (Kali, normaler Benutzer):

```sh
pipx install <wheel oder git-URL>   # Paket ariadne-recon, Befehl ariadne
ariadne setup                        # Zeile in .zshrc/.bashrc, systemd-Dienst
ariadne init                         # Operator-Tresor: Passphrase, Recovery-Code offline aufbewahren
```

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

Nach 12 Stunden ohne Ausgabe in irgendeinem Terminal beendet Ariadne das Projekt von selbst. `ariadne lock` sperrt nur, das Projekt bleibt aktiv. Eigene Secrets (`ariadne secrets add`) stehen verschlüsselt im Journal und werden vor KI, Export und Bericht ersetzt.

## Dokumente

- [Vision](VISION.md): Zielbild, Grundsätze, Roadmap, offene Punkte
- [Lösungsarchitektur](docs/architektur.md): Teilsysteme, Datenmodell, Sicherheitsarchitektur, Roadmap im Detail
- [Entwicklung](docs/entwicklung.md): Umgebung, Tests, Landkarte der Module, bekannte Grenzen
- [Entscheidungsprotokoll](docs/entscheide.md): was entschieden wurde, warum und von wem
- [Fragenkatalog](docs/fragenkatalog.md): Brainstorming mit Antwortoptionen und Empfehlungen
