# Ariadne: Vision

> Stand 2026-10-08, Entwurf. Erarbeitet im Dialog mit KI-Unterstützung (Claude) auf Basis der Antworten im [Fragenkatalog](docs/fragenkatalog.md). Die einzelnen Entscheide und wer sie getroffen hat, stehen im [Entscheidungsprotokoll](docs/entscheide.md). Die technische Umsetzung beschreibt die [Lösungsarchitektur](docs/architektur.md).

## Kurzfassung

Ariadne ist der **Flugschreiber und Kartograf** eines Pentests unter Linux. Auf Knopfdruck zeichnet es auf, was in den Terminals, im Projektordner und auf dem Bildschirm passiert. Es liest daraus Hosts, Services, Zugänge und Schwachstellenhinweise aus und malt Schritt für Schritt eine Karte der Zielumgebung. Der Faden auf der Karte zeigt jederzeit, auf welchem Weg man wohin gekommen ist. Zu jedem Fakt lässt sich die Stelle zeigen, aus der er stammt.

Ariadne beobachtet, dokumentiert und gibt Denkanstösse. Es greift nie selbst an.

## Problem

Drei Dinge gehen in einem Pentest regelmässig schief:

1. **Man verliert den Überblick.** Nach ein paar Scans, Shells und Passwörtern liegen die Informationen verstreut in Terminals, Dateien und im eigenen Kopf. Was schon geprüft wurde, was offen ist und welches Passwort wo funktioniert, weiss man nach ein paar Stunden nicht mehr sicher.
2. **Man steckt fest.** Oft fehlt nicht das Wissen, sondern der Anstoss, einen vergessenen Schritt doch noch zu machen: ein Full-Port-Scan, ein UDP-Scan, neue Credentials gegen alle bekannten Dienste.
3. **Die Belege fehlen am Ende.** Beim Schreiben des Berichts muss man den genauen Befehl, den Output und den Zeitpunkt aus History und Screenshots zusammensuchen. Wie man auf den ersten Host gekommen ist, lässt sich dann oft nur noch ungefähr rekonstruieren.

## Zielbild

Nach den ersten Minuten steht eine grobe Übersicht: Der Scope zeichnet die Umrisse, der erste nmap-Lauf setzt graue Hosts in den Nebel. Mit jedem Scan, jeder Shell und jedem Passwort füllt sich das Bild. Grau wird zu Farbe, Unbekanntes zu Bekanntem. Eine kräftige Linie, der Faden, verbindet die Schlüsselschritte von Kali bis zum letzten Host.

Am Ende einer Lab-Session liegt ein Markdown-Bericht bereit: Übersicht, Angriffspfad, Writeup-Gerüst nach dem Phasenschema des Moduls Cybersecurity und Belege mit Befehl, Ausschnitt, Zeitpunkt und Screenshot.

Ein typischer Ablauf:

1. `ariadne start lame --target 10.10.10.3` entsperrt Ariadne und legt das Projekt an. Ab jetzt nimmt Ariadne alle Terminals auf, auch parallele, mit genauem Zeitstempel.
2. Das Dashboard läuft im Browser, in der Kali oder über einen SSH-Tunnel auf dem Mac.
3. `nmap -sV -oA scans/lame 10.10.10.3` setzt Ports und Versionen direkt auf die Karte, markiert als «auto».
4. Der Denkanstoss «Unauthentisierten Zugriff auf FTP prüfen» erscheint, mit Begründung und Beleg.
5. Kommt die Reverse Shell, setzt Ariadne den Host aus dem ersten Callback selbst. Nur bei Pivots oder Port-Forwards setzt man ihn mit `F12` und `h`. Ab dann stimmt der Kontext, und die `/etc/passwd` landet beim richtigen Host.
6. `F12` und `k` markiert den Foothold als Schlüsselschritt. Der Faden wächst.
7. Am Ende erzeugt `ariadne export` das Writeup-Gerüst mit allen Belegen, `ariadne backup` sichert das Projekt ausserhalb der VM, und `ariadne stop` sperrt.

## Für wen und in welchem Rahmen

| Thema | Festlegung |
|---|---|
| Nutzer | eine Person, Student HF Informatik (Cybersecurity), arbeitet hauptberuflich in der IT |
| Einsatz | zuerst Schule und Labs (Metasploitable2, Übungsboxen bis ca. 10 Hosts), danach professionelle Aufträge. Kundenaufträge sind vorerst fiktiv |
| Plattform | Kali Linux im Standard-Setup (zsh, QTerminal, Xfce) in einer VM mit eher knapper Leistung, offline lauffähig, kompatibel mit anderen Shells und Terminals |
| Projektform | privates Projekt, keine Schul- oder Diplomarbeit |
| Entwicklung | allein, KI-unterstützt, ca. 20 Stunden pro Woche, Start sofort |
| KI | Claude über die API als Standard; lokale Modelle optional, weil die VM wenig Leistung hat |
| Zertifizierungen | keine geplant, daher kein Prüfungsmodus |

## Grundsätze

1. **Beobachten, nicht handeln.** Ariadne schickt keine eigenen Pakete an Ziele und löst keine Zielnamen per DNS auf. Der Browser-Recorder ist kein Widerspruch: Er leitet nur weiter, was dein Testbrowser verlangt, und löst dafür die Namen auf, die der Browser anfragt.
2. **Jeder Fakt hat eine Quelle.** Ein Klick auf einen Wert zeigt den Befehl, den Output-Ausschnitt, die Datei oder die Bildregion, aus der er stammt.
3. **Rohdaten sind unveränderlich.** Was aufgenommen wurde, bleibt dauerhaft und verschlüsselt gespeichert. Auswertungen lassen sich jederzeit neu berechnen, deine Entscheide überstehen das.
4. **Einmal starten, alles aufnehmen.** Solange ein Projekt aktiv ist, nimmt Ariadne alle Terminals auf. `F12 r` pausiert ein Terminal für 10 Minuten. Der Zustand ist immer sichtbar.
5. **Automatisch, was sicher ist, Entscheid, wo es zählt.** Werte bekannter Parser im Scope gehen direkt auf die Karte, markiert als «auto» und pro Befehl rückgängig. Unsicheres bleibt als Nebel. KI-Werte, Widersprüche und Unklares landen in der Arbeitsliste, und dein Entscheid geht immer vor.
6. **KI als Denkpartner, nicht als Autopilot.** Denkanstösse kommen aus festen Regeln und aus einem Sprachmodell, immer begründet, gekennzeichnet und mit Belegen. Ein Lernmodus gibt zuerst eine Frage, dann eine Richtung, erst zuletzt einen Befehl.
7. **Zieldaten sind feindlich.** Alles, was ein Ziel beeinflussen kann, wird so behandelt, als hätte ein Angreifer es geschrieben: Output, Banner, Hostnamen, Dateien, Bilder und KI-Texte darüber.
8. **Local-first.** Ariadne läuft ohne Internet. Daten gehen nur an einen Cloud-Dienst, wenn das Projekt es erlaubt.
9. **Die Shell geht nie kaputt.** Fällt Ariadne aus, arbeitet das Terminal normal weiter, nur ohne Aufnahme.
10. **Ein Fakt ist kein Finding.** «Port 445 offen» sammelt Ariadne. «SMB-Signing fehlt, Relay möglich» ist ein Urteil des Pentesters.

## Was Ariadne kann

**Aufnehmen.** Ein kleiner Wrapper um jede Shell nimmt Ein- und Ausgabe aller Terminals auf, unabhängig von Terminal-Programm und Multiplexer, mit einem Zeitstempel auf die Millisekunde. Shell-Integrationen für zsh und bash (später fish) liefern Befehlsgrenzen, Exit-Codes und Arbeitsordner. Daraus entsteht eine Zeitachse aller Terminals. Dazu kommen der überwachte Projektordner, Screenshots, ab v0.2 ein Aufzeichnungs-Proxy für den Browser, Burp- und HAR-Importe, später Zwischenablage und PCAPs.

**Kontext kennen.** Ariadne führt pro Terminal einen Stapel, zum Beispiel `Kali › web01 (www-data) › mysql`. Startet eine Remote-Session, steht der Kontext zuerst auf «unbekannt». Mit einem Tastenkürzel setzt du den Host, auch mitten in evil-winrm oder einer Reverse Shell.

**Verstehen.** Parser lesen die Ausgaben bekannter Tools, bevorzugt ihre strukturierten Dateien wie nmap-XML. Ein Regex-Netz fängt IPs, Hashes, URLs und CVEs aus beliebigem Text. Ein Sprachmodell ergänzt, darf aber nur Werte liefern, die wörtlich im Rohtext stehen.

**Karte zeigen.** Die Web-Oberfläche zeigt links die Karte mit umschaltbaren Ebenen (Topologie, Services, Credentials, Angriffspfad, später Web-Struktur und Active Directory) und rechts die Arbeitsliste «Als Nächstes». Dazu kommen Tabellen, eine Credential-Matrix, eine Zeitachse und die Belegansicht. Das Dashboard lässt sich über einen SSH-Tunnel auch vom Mac aus öffnen.

**Denkanstösse geben.** Regeln erkennen offene Prüfziele («SMB offen, Shares noch nicht aufgelistet»). Auf Knopfdruck erstellt ein Sprachmodell aus einem kompakten Lagebild weitere Anstösse. Ariadne führt nichts davon aus.

**Belegen und berichten.** Der Export erzeugt Markdown: Übersicht, Angriffspfad, Writeup-Gerüst, Hosts und Belege. Eine Vorlage folgt dem Schema aus dem Modul Cybersecurity (Reconnaissance, Scanning/Enumeration, Exploitation, Post-Exploitation, Reporting) mit MITRE-ATT&CK-IDs, Schweregraden und Massnahmen.

**Schützen.** Projekte sind strikt getrennt und verschlüsselt. Gespeichert wird alles vollständig; eigene Secrets (sudo-Passwort, API-Keys) werden ersetzt, bevor etwas Ariadne verlässt: vor der KI, beim Export und im Bericht. Eine Hash-Kette macht nachträgliche Änderungen am Rohlog erkennbar. Backups sind verschlüsselt und liegen ausserhalb der VM.

## Was Ariadne nicht ist

- **Kein Autopilot.** Kein automatisches Scannen, Sprayen oder Exploiten. PentestGPT ab v1.0 geht in diese Richtung, Ariadne bewusst nicht.
- **Kein Scanner und kein Exploit-Framework.** Ariadne liest die Ergebnisse von nmap, NetExec, Metasploit und Co., ersetzt sie aber nicht.
- **Kein Ersatz für BloodHound oder Burp.** Für tiefe AD-Pfadanalysen und Web-Tests bleiben die Spezialwerkzeuge. Ariadne importiert ihre Kernergebnisse.
- **Kein Report-Generator, der Findings bewertet.** Ariadne liefert die Belege. Bewerten und Formulieren bleibt Aufgabe des Pentesters.
- **Kein Team-Server** vorerst. Das Datenmodell trägt eine Operator-ID, damit Teamarbeit später möglich ist.
- **Kein Prüfungsmodus.** Er ist im aktuellen Rahmen nicht nötig.

## Roadmap

Jede Version ist für sich nutzbar. Ab v0.1 läuft jede Lab-Übung mit Ariadne, und was dabei stört, wird zum Backlog der nächsten Version. Details stehen in der [Lösungsarchitektur, Abschnitt 11](docs/architektur.md#11-roadmap).

| Version | Ziel | Kern |
|---|---|---|
| **v0.1** Flugschreiber mit erster Karte | Eine Metasploitable2- oder einfache HTB-Session lückenlos aufnehmen und als Writeup exportieren | Shell-Wrapper für zsh und bash, `ariadne start` mit Daueraufnahme, Kontext per Tastenkürzel, verschlüsselte Ablage, nmap-Parser und Regex-Netz, Drei-Spuren-Regel, Web-Oberfläche «Karte und Arbeitsliste», Belegansicht, Screenshots unter X11, Regeln und KI-Denkanstoss auf Knopfdruck, Markdown-Export, Backup, Fernzugriff vom Mac über Tailscale und SSH |
| **v0.2** Bild ausmalen und verstehen | Ein Lab mit mehreren Hosts, Pivots und Credentials | typische Lab-Tools als Parser, linpeas, KI-Extraktion, lokale KI über Ollama, Credential-Matrix, Tunnel, Fragen an die Karte, OCR, Browser-Recorder mit Testbrowser, HAR- und Burp-Import, Offline-Paket |
| **v0.3** bereit für Kunden | Ein (fiktiver) Kundenauftrag nach professionellen Massstäben | Kundenprofil, verschlüsselter Arbeitsordner, Aktivitätsprotokoll-Export, Cleanup-Liste, Findings, Löschnachweis, Vision, Firefox-Erweiterung mit Tab-Screenshots, PCAP, Active Directory |
| **v0.4+** Ausbau | Grosse Netze, Komfort, Langzeitpflege | semantischer Zoom, Zeitreise, Burp-Erweiterung, Teamfunktionen |

## Erfolgskriterien

- **v0.1:** Eine vollständige Metasploitable2-Session ist nach einem einzigen `ariadne start` aufgenommen. Jeder Fakt auf der Karte führt zu seiner Quelle, der Faden zeigt Foothold und Root, und der Export taugt ohne Nacharbeit als Gerüst für einen Lab-Bericht.
- **Kein Klartext-Leck:** Ein Canary-Test findet nach dem Schliessen eines Projekts keinen markierten Testwert im Klartext, weder im Home noch in Logs, Coredumps oder Exporten.
- **Robustheit:** Ein feindliches Test-Ziel (präparierte Hostnamen, Escape-Sequenzen, gefälschte Marker, XSS-Strings) bringt weder Shell, Daemon noch Web-Oberfläche dazu, etwas Unerwünschtes zu tun.
- **Nutzung:** Ab v0.1 läuft jede Lab-Übung mit Ariadne. Sinkt die Nutzung, ist das ein Signal für das Backlog, nicht für mehr Funktionen.

## Offene Punkte

Keine blockierenden Fragen mehr. Was noch offen ist, klärt sich beim Bauen:

1. **Testmaterial:** Echte Outputs aus Metasploitable2 fehlen noch. Bis dahin bauen die Tests auf nachgestellten Outputs der wichtigsten Tools auf (nmap zuerst). Sobald echte Outputs vorliegen, ersetzen sie die nachgestellten.
2. **VM-Details:** Die Kali läuft als VM im SmartLearn-Netz der Schule (VMware vSphere), bedient über die Webkonsole; sie kommt ins Internet, und Tailscale ist erlaubt. Offen sind Masterset, Hostkeys und Lebensdauer der VM. `ariadne remote check` und `ariadne doctor` prüfen das beim ersten Start.
