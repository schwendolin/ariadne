# Ariadne: Fragenkatalog mit Empfehlungen

Brainstorming zur Vision von Ariadne, einem Hilfstool für Pentests unter Linux. Es erfasst Terminal-Ein- und -Ausgaben, Dateien und Screenshots, liest neue Werte automatisch aus und baut Schritt für Schritt eine Karte der Zielumgebung.

Jede Frage hat Antwortmöglichkeiten und eine Empfehlung aus Sicht eines erfahrenen Pentesters. Die Empfehlungen sind aufeinander abgestimmt und ergeben zusammen ein Gesamtbild, das eine Person neben Job und Studium bauen kann. Abschnitt 11 enthält Fragen, die im ersten Entwurf fehlten.

**So antworten:** «Empfehlungen passen, ausser 2.2: …, 9.1: …». Die Fragen, die nur du beantworten kannst, stehen am Ende.

## Leitbild

Ariadne ist der **Flugschreiber und Kartograf** eines Pentests. Es zeichnet alles mit Herkunft auf, baut daraus die Karte und den Angriffspfad und liefert die Belege für den Report. Es ergänzt Obsidian, SysReptor und BloodHound, statt sie zu ersetzen. Ariadne beobachtet, dokumentiert und macht später Vorschläge. Es greift nie selbst an.

## Grundsatzentscheide

Diese Entscheide ziehen sich durch den ganzen Katalog. Ändert sich einer davon, ändern sich viele Einzelantworten.

1. **zsh und tmux sind Pflicht.** zsh-Hooks liefern die Befehlsgrenzen (Befehl, Zeit, Exit-Code, OSC-133-Marker), `tmux pipe-pane` liefert den Output. Damit ist der Terminal-Emulator egal, und es braucht keinen eigenen PTY-Wrapper.
2. **Host-Kontext über tmux, nicht über die Shell.** In evil-winrm, ssh oder einer Reverse Shell geht jede Eingabe ans Ziel. Der Kontext wird deshalb per tmux-Taste gesetzt, als Stapel pro Pane (Kali > ssh web01 > su root > mysql). Startet eine Remote-Session, kommt automatisch die Stufe «unbekannt» dazu. Meldet sich die lokale zsh zurück, springt der Kontext automatisch auf Kali.
3. **Drei Datenschichten in SQLite, ein Projektordner pro Auftrag.** (1) Rohdaten sind unveränderlich. (2) Fakten sind Behauptungen mit Quelle und jederzeit neu berechenbar. (3) Nutzerentscheide (bestätigen, Kontext, Status, Notizen) sind eigene Events, die nach jedem Reparse erneut angewendet werden. Ein Host ist eine Entität mit mehreren Adressen, nie die IP selbst. Zeiten werden in UTC gespeichert. UUIDs und Operator-ID sind ab Tag 1 dabei.
4. **Strukturierte Dateien vor Terminaltext.** Zuerst nmap -oX, ffuf-JSON und Co. Feste Parser mit Golden-Tests, ein Regex-Netz fängt den Rest als unbestätigte Kandidaten. Ein LLM kommt erst später und nur über ein Gateway.
5. **Projektprofile lab, exam und customer** steuern alles Heikle: LLM, Vorschläge, Exportziele, Strenge der Scope-Prüfung, Verschlüsselung.
6. **Fakt ist nicht gleich Finding.** Fakten sammelt Ariadne automatisch. Ein Finding entsteht nur durch dein Urteil.
7. **Gestaffelt bauen.** Jede Version ist für sich nutzbar. Was nicht in v0.1 gehört, steht explizit in einer späteren Version.

## Roadmap

| Version | Ziel | Inhalt |
|---|---|---|
| **v0.1** (ca. 50 bis 70 h) | Eine HTB-Box mit Shell auf dem Ziel komplett lösen und lückenlos dokumentieren | Projekt-CLI (`new`, `use`, `pause`, `resume`) mit Ordnerstruktur, Scope-Datei und Profil (lab, exam). zsh-Hook plus tmux pipe-pane. Kontext per tmux-Taste, Status in der tmux-Statuszeile. SQLite mit drei Schichten und `reparse`. nmap-XML-Parser, der nach Befehlsende automatisch läuft. Regex-Netz (IPs, URLs, Hashes, CVEs) in eine Inbox. `cred add`, Status und Tags per CLI, `mark foothold/privesc/pivot/loot`. CLI-Ansichten (hosts, services, creds, timeline, search). Markdown-Export als Writeup-Gerüst mit Angriffspfad und Belegen. `ariadne shot` mit Flameshot. Eigene Secrets per exakter Liste schwärzen. Installation per pipx. |
| **v0.2** | Ein Multi-Host-Lab (z. B. HTB Pro Lab, GOAD-Light) | Lokale Web-UI (Tabellen, Timeline, Credential-Matrix, Graph für Pivots). Parser für NetExec (inkl. Fehlschläge), hydra, ffuf, feroxbuster/gobuster, Potfile, passwd/shadow, secretsdump. inotify-Watcher. Heuristik für Host-Kontext und Status als Vorschlag. Scope-Widget (accept-line). Hash-Typ-Erkennung. |
| **v0.3** | Bereit für echte Aufträge | Kundenprofil mit Ausschlüssen und Zeitfenstern, age-Archive, Crypto-Shredding, Löschnachweis, Präsentationsmodus. Regel-Engine mit Vorschlägen und «noch offen» pro Service. Parser für linpeas/winPEAS, enum4linux-ng, nuclei und Config-Dateien. searchsploit als Hinweis. Finding-Objekt, Aktivitätsprotokoll mit Quell-IP, Artefakt-Liste für das Cleanup. |
| **später** | Breite | LLM-Gateway (Extraktion, Fragen in normaler Sprache, Vorschläge), OCR und Vision, Importe (Burp, Metasploit-DB, nxcdb, Responder, BloodHound, gowitness), Export nach SysReptor und docx, Team-Funktionen, bash-Unterstützung, Headless-Betrieb. |

**Nie:** Autonome Angriffe wie Credential-Spraying oder Exploits ohne deine ausdrückliche Bestätigung.


## 1. Zweck und Kontext

### 1.1 Einsatzzweck [Kernfrage]

*Wofür nutzt du es? Schule, CTFs und HackTheBox, eine Zertifizierung wie OSCP, echte Kundenaufträge oder alles davon?*

- **A) Schule und Labs (CYS, Metasploitable2)**: Ein Host, bekannte Lücken, Report mit Phasen und Belegen. Gut für erste Parser-Tests, aber zu einfach für das Problem Kontext-Zuordnung.
- **B) CTF und HackTheBox**: Viele kurze Engagements, Writeups, Pivoting in Pro Labs. Viel Nutzung, ideales Testfeld im Eigengebrauch (Dogfooding) für jedes neue Feature.
- **C) Zertifizierung (OSCP, CPTS, eJPT)**: Zeitdruck, und der Report entscheidet über das Bestehen. Regeln je nach Zertifizierung sehr unterschiedlich: OSCP verbietet LLMs und automatische Exploitation-Tools, eJPT und CPTS sind deutlich lockerer.
- **D) Echte Kundenaufträge**: Scope, Vertraulichkeit, Nachvollziehbarkeit, Löschung nach Auftrag. Höchster Anspruch, kaum Fehlertoleranz, rechtliche Folgen bei Fehlern.
- **E) Alles, nach Phasen gestaffelt**: MVP für Labs und HTB, Architektur von Anfang an auftragstauglich. Etwas mehr Designdisziplin, dafür später kein Neuschreiben.

**Empfehlung:** E, gestaffelt. B ist dein Haupttestfeld (viel Nutzung, echte Pivots). A liefert erste Testdaten für Parser. C setzt den Massstab für die Report-Qualität. D gibt Designregeln vor (Scope, Vertraulichkeit, Löschbarkeit), aber noch keine Features. Wer nur für Labs baut, schreibt später das Datenmodell neu. Wer sofort für Kunden baut, wird nie fertig.

> **Aus der Praxis:** OffSec verbietet im OSCP-Exam LLM- und AI-Chatbots. Plane einen Exam-Modus, der das LLM ganz abschaltet, und prüf vor der Prüfung die aktuellen Regeln. Die Kontext-Zuordnung kannst du erst mit Multi-Host-Labs wie GOAD oder HTB Pro Labs testen.

### 1.2 Grösster Schmerzpunkt [Kernfrage]

*Was nervt dich heute am meisten?*

- **A) Überblick über Hosts und Stand verlieren**: Welche Hosts, Ports und Services gibt es, was ist geprüft, was offen? Wird schon ab einer Handvoll Hosts kritisch.
- **B) Notizen lückenhaft oder vergessen**: Mitten in der Arbeit notiert niemand sauber. Nachträgliche Notizen sind unvollständig und haben keinen Zeitstempel.
- **C) Reporting am Ende ist mühsam**: Screenshots, Befehle, Outputs und Zeitpunkte zusammensuchen kostet oft so viel Zeit wie das Testen selbst.
- **D) Credentials nicht systematisch getestet**: Unklar, welcher User mit welchem Passwort oder Hash auf welchem Host und Protokoll getestet wurde. Wiederverwendete Passwörter bleiben unentdeckt.
- **E) Weg hinein nicht mehr nachvollziehbar**: Der Angriffspfad fehlt: Welche Info führte zu welchem Zugang? Ohne ihn ist ein Finding nicht reproduzierbar.

**Empfehlung:** E + C als Kern, A ergibt sich fast von selbst. Alle drei speisen sich aus derselben Quelle: einem lückenlosen Befehls-Log mit Provenienz. D ist das beste Feature direkt nach dem MVP, als Cred-Matrix (User x Host x Protokoll x Ergebnis). B ist ein Symptom: Wenn Ariadne automatisch erfasst, musst du weniger selbst notieren.

> **Aus der Praxis:** Der Klassiker: Tag 3, Domain Admin erreicht, aber niemand weiss mehr, aus welchem Share das erste Passwort stammte. Ohne Quelle und Zeitstempel ist das Finding nicht belegbar, und der Kunde kann es nicht nachstellen.

### 1.3 Einzel- oder Teamnutzung

*Arbeitest nur du damit, oder sollen mehrere Leute gleichzeitig an derselben Karte arbeiten?*

- **A) Nur ich, lokale Datenbank**: Einfachste Architektur: SQLite, kein Server. Team geht später nur mit Neubau, wenn das Datenmodell es nicht vorsieht.
- **B) Allein, Datenmodell aber teamfähig**: Operator-ID pro Fakt, UUIDs, Events, die nur angehängt und nie überschrieben werden. Kostet wenig und erlaubt später Merge und Sync.
- **C) Asynchron teilen per Export und Merge**: Projekte exportieren, zusammenführen, per Git teilen. Gut für Gruppenarbeit, aber Konflikte bei gleichzeitigen Änderungen.
- **D) Echtzeit-Zusammenarbeit über Server**: Mehrere Operatoren live auf einer Karte. Braucht Server, Login, Rechte und Sync. Ein eigenes Grossprojekt.

**Empfehlung:** B für das MVP, C als erster Teamschritt (z. B. für Gruppenarbeiten), D erst bei echtem Bedarf. Echtzeit-Sync allein zu bauen frisst Monate, die dem Kernnutzen fehlen. Mit Operator-ID und Event-Log ab Tag 1 verbaust du dir nichts.

> **Aus der Praxis:** Im Team-Pentest ist das teuerste Problem nicht fehlender Live-Sync, sondern Doppelarbeit und gesperrte Konten, weil zwei Leute gleichzeitig Passwörter sprayen. Schon ein geteiltes «Wer hat was wann getestet?» verhindert das.

### 1.4 Zielbild typischer Tag

*Ariadne funktioniert in einem Jahr perfekt. Wie sieht ein typischer Pentest-Tag aus?*

- **A) HTB-Abend: eine Box, drei Stunden**: Ariadne läuft im Hintergrund mit. Am Ende steht automatisch ein Writeup-Gerüst mit Befehlen, Funden und dem Weg hinein.
- **B) Zertifizierungsprüfung unter Zeitdruck**: Beim OSCP knapp 24 Stunden testen, dann 24 Stunden Report. Ariadne liefert Timeline und Belege pro Ziel, ohne LLM.
- **C) Interner Kundenpentest, AD, mehrere Tage**: Dutzende Hosts, Pivots, Credentials. Ariadne führt Karte, Cred-Matrix und Kontext pro Shell, der Report-Entwurf wächst täglich.
- **D) Externer Test mit striktem Scope**: Ariadne warnt bei Zielen ausserhalb des Scopes und belegt jede Aktion mit Zeitstempel, falls der Kunde nachfragt.

**Empfehlung:** Beispiel C: Morgens `ariadne new kunde-x` mit Scope anlegen. `nmap -oA` schreibt in den Projektordner, die Karte füllt sich. In evil-winrm auf FS01 drückst du einmal die tmux-Taste und setzt den Host, ab dann stimmt der Kontext in diesem Pane. Ein Passwort aus einer web.config erscheint in der Credential-Matrix mit «auf 12 Hosts ungetestet». Abends stehen Timeline, Angriffspfad und Belege im Projekt-Vault, jeweils mit Befehl, Output und Zeit.

> **Aus der Praxis:** Erzähl den Tag rückwärts: Was musst du am letzten Tag im Report belegen? Daraus ergibt sich, was Ariadne am ersten Tag erfassen muss. Und nach Auftragsende muss alles nachweisbar löschbar sein.

### 1.5 Bestehende Tools und Lücken

*Was können bestehende Tools, und was fehlt dort?*

- **A) Faraday und Dradis: Import, Zusammenarbeit**: Stark: importieren Outputs vieler Scanner, mehrbenutzerfähig. Faraday verknüpft Fakten sogar mit dem erzeugenden Befehl (faraday-cli). Lücke: kein Kontext für Remote-Shells, kein Angriffspfad, schwerfälliges Server-Setup.
- **B) SysReptor: Reporting**: Stark: Markdown zu PDF, Vorlagen auch für OSCP, API und CLI reptor. Lücke: Inhalte erfasst du selbst, keine laufende Erkundung.
- **C) Ghostwriter und Reconmap: Projektverwaltung**: Stark: Projekte, Scope, Infrastruktur, Oplogs (Ghostwriter), Tasks und Befehle (Reconmap). Lücke: für Firmen gebaut, ohne Integrationen viel Handarbeit.
- **D) BloodHound: AD-Angriffspfade als Graph**: Stark: zeigt Pfade zu Domain Admin. Seit BloodHound CE v8 (2025) nimmt es über OpenGraph auch eigene Knoten und Kanten auf. Lücke: kennt dein Terminal und deinen Weg nicht.
- **E) PentestGPT: LLM als Begleiter**: Seit v1.0 (Ende 2025) ein autonomer Agent, der Tools selbst ausführt. Der frühere Begleitmodus läuft als pentestgpt-legacy weiter. Lücke: Es arbeitet statt dir, nicht mit dir, und führt kein Faktenmodell mit Herkunft über deine eigene Arbeit.

**Empfehlung:** Ariadne als Zubringer bauen, nicht als Konkurrenz. Die Lücke sind automatisches Erfassen, Host-Kontext in Remote-Shells und der Weg dorthin. Export nach Obsidian und SysReptor, BloodHound verlinken bzw. später per OpenGraph beliefern statt nachbauen. Mach vorher eine HTB-Box bewusst mit Faraday oder Dradis CE: Die Reibung dabei zeigt dir, was Ariadne können muss.

> **Aus der Praxis:** Unterschätzt: Die Metasploit-Datenbank (hosts, services, creds, loot, gefüllt über db_nmap) und nxcdb von NetExec erfassen heute schon viel. Ariadne sollte sie importieren statt nachbauen.

## 2. Terminal erfassen

### 2.1 Terminal-Verlauf speichern

*Soll der komplette Terminal-Verlauf dauerhaft gespeichert werden, oder reichen die extrahierten Werte?*

- **A) Vollständiges Rohlog plus extrahierte Werte**: Jeder Befehl mit Output, Zeitstempel, Exit-Code und cwd, abspielbar. Liefert Beweis und Provenienz und lässt sich später neu parsen. Braucht Verschlüsselung und ein Löschkonzept.
- **B) Nur extrahierte Werte speichern**: Schlank und datensparsam, aber kein Beweis. Was ein Parser falsch liest oder übersieht, ist verloren. Mit besseren Parsern kann man nicht neu parsen.
- **C) Rohlog mit automatischem Ablaufdatum**: Rohdaten bleiben z. B. 30 Tage oder bis zur Reportabgabe. Kompromiss für Kundenaufträge, aber Nachfragen nach der Abgabe lassen sich nicht mehr belegen.
- **D) Rohlog nur für markierte Abschnitte**: Du markierst wichtige Passagen von Hand. Wenig Daten, aber in der Praxis fehlt genau der Moment, den man nicht für wichtig hielt.

**Empfehlung:** A, die Aufbewahrung pro Projekt einstellbar (C als Option). Einheit ist lokal der einzelne Befehl, in Remote-Sessions das Segment zwischen zwei Kontextwechseln. Jeder Fakt verweist per Byte-Offset auf seine Stelle im Rohstrom. Neben dem Beweis der grösste Vorteil: Mit einem besseren Parser wertest du alte Labs neu aus. Speicherplatz spielt keine Rolle, Text komprimiert sehr gut.

> **Aus der Praxis:** Typischer Anruf: «Server X ist um 14:32 abgestürzt, wart ihr das?» Darauf antwortet nur ein lückenloses Log mit Zeitstempeln. Rohlogs enthalten Klartext-Creds, gehören also nie in einen Obsidian-Vault, der mit der Cloud synchronisiert wird.

### 2.2 Shell und Terminal-Setup

*Welche Shell und welches Setup (Multiplexer, Terminal-Emulator)?*

- **A) zsh in QTerminal (Kali-Standard)**: Das Setup ab Installation. zsh liefert mit preexec/precmd saubere Befehlsgrenzen. Ohne Multiplexer ist die Session weg, sobald du das Fenster schliesst.
- **B) zsh plus tmux**: Profi-Standard: Sessions überleben Abbrüche, Panes und Fenster lassen sich benennen. tmux pipe-pane schneidet Output mit, egal welcher Terminal-Emulator läuft.
- **C) bash, mit oder ohne tmux**: Geht auch, Befehlsgrenzen aber nur über PROMPT_COMMAND und DEBUG-Trap bzw. bash-preexec. Etwas fummeliger als zsh.
- **D) fish oder exotischer Emulator**: fish ist nicht POSIX-kompatibel und hat eine eigene Hook-Syntax. Doppelter Integrationsaufwand für wenige Nutzer im Pentest-Umfeld.

**Empfehlung:** B, und zwar verbindlich: zsh und tmux sind Voraussetzung. zsh-Hooks liefern die Befehlsgrenzen (OSC-133-Marker), tmux pipe-pane den Output, unabhängig vom Terminal-Emulator. Kein eigener PTY-Wrapper im MVP. Ohne tmux gibt es nur ein Befehlslog mit sichtbarer Warnung. bash später über bash-preexec, fish gar nicht. Falls du tmux noch nicht nutzt: jetzt angewöhnen.

> **Aus der Praxis:** Lass die zsh-Hooks OSC-133-Marker in den Strom schreiben (Semantic Prompts). Damit zerlegt der Logger den Rohstrom sauber in Befehle. Achtung: Fehlende Marker beweisen keine Remote-Session, auch ein langer nmap-Lauf sendet keine.

### 2.3 Logging-Start

*Startet das Logging automatisch in jedem Terminal oder bewusst pro Session?*

- **A) Immer automatisch in jedem Terminal**: Nichts wird vergessen. Aber Privates, Arbeit beim IT-Dienstleister und Schulkram landen ohne Projektzuordnung im selben Topf.
- **B) Bewusst pro Session starten**: Saubere Trennung, aber die Shell, in der du Root bekommst, ist garantiert die ungeloggte.
- **C) Automatisch, sobald ein Projekt aktiv ist**: `ariadne use htb-lame` setzt das aktive Projekt. Jedes neue Terminal loggt dorthin, der Prompt zeigt es an. `ariadne pause` für Privates.
- **D) An die tmux-Session gebunden**: Die tmux-Session «htb-lame» ist das Projekt, das Logging startet mit der Session. Elegant, setzt aber zwingend tmux voraus.

**Empfehlung:** C, und D als Standard, weil tmux ohnehin Pflicht ist. Automatisch an, sobald ein Projekt aktiv ist: Das funktioniert besser als jede Disziplin. Projekt, Profil und Logging-Status stehen in der tmux-Statuszeile, denn ein Prompt-Hinweis wie [ariadne:lame] verschwindet, sobald du in einer Remote-Shell bist. `ariadne pause` für Privates gehört dazu.

> **Aus der Praxis:** Der häufigste Doku-Fehler überhaupt: Der Exploit hat geklappt, aber in diesem Fenster lief kein Logging. Das aus dem Gedächtnis nachzubauen kostet Stunden und ist im Report angreifbar.

### 2.4 Host-Kontext in Sessions [Kernfrage]

*Muss Ariadne erkennen, dass du in einer Session auf einem anderen Host bist (nc, pwncat, SSH, evil-winrm, meterpreter, mysql)?*

- **A) Heuristische Auto-Erkennung**: Erkennt den Start einer Session an Befehlen (ssh, evil-winrm, nc -lvnp), Connect-Meldungen, Prompt-Mustern und Ausgaben von hostname, whoami, ipconfig.
- **B) Kontext manuell wechseln (Befehl/Hotkey)**: `ariadne ctx web01` oder Hotkey. Immer korrekt, wenn gesetzt, aber unter Stress vergisst man es zuverlässig.
- **C) Integrationen pro Tool**: msfconsole spool und db_export, pwncat-cs-Datenbank, SSH-Wrapper. Präzise, aber Aufwand pro Tool, und Updates machen sie kaputt.
- **D) Kein Host-Kontext, alles lokal**: Am einfachsten, aber der Graph wird falsch: Die /etc/passwd des Ziels landet bei deinem Kali. Für die Karte wertlos.

**Empfehlung:** Ja, zwingend. v0.1: B über eine tmux-Taste (z. B. Präfix + h), denn in evil-winrm oder einer Reverse Shell geht jede Eingabe ans Ziel, ein Ariadne-Befehl ist dort nicht möglich. Dazu minimale Automatik: Startet ssh, evil-winrm oder nc -lvnp, kommt die Stufe «unbekannt» auf den Kontext-Stapel des Panes. Meldet sich die lokale zsh zurück, springt er sicher auf Kali. Heuristik A ab v0.2, nur als Vorschlag. C später für Metasploit. Der mysql-Client ist ein neuer Sessiontyp, kein neuer Host.

> **Aus der Praxis:** Listener-Zeilen wie «connect to [...] from [...]» liefern die Ziel-IP gratis. Vorsicht beim Pivoting: Ein Host hat oft mehrere IPs (dual-homed, NAT). Ist die IP die Host-Identität, entstehen Phantom-Hosts im Graph.

### 2.5 Parallele Terminals

*Mehrere Terminals parallel: ein gemeinsamer Strom oder getrennt?*

- **A) Ein gemeinsamer Strom**: Einfach, aber die Kontexte vermischen sich: Scan-Output wird plötzlich dem Host der Reverse Shell im Nachbarfenster zugeordnet.
- **B) Strikt getrennte Ströme**: Sauber, aber ohne Gesamtbild. Der Zusammenhang zwischen Exploit und eingehender Shell geht verloren.
- **C) Getrennte Ströme, eine Zeitachse, ein Graph**: Jedes Terminal/Pane hat einen eigenen Kontext-Stapel. Fakten fliessen in einen Graph, die Zeitachse ist zusammengeführt und nach Terminal filterbar.

**Empfehlung:** C, eine echte Alternative gibt es nicht. Der Kontext gilt pro Terminal, das Wissen global. Benenne die Ströme nach tmux-Fenster oder Pane (z. B. «scan», «exploit», «shell-web01»), dann bleibt die Zeitachse lesbar. Für ein Team später bekommt jeder Strom zusätzlich eine Operator-ID, das Datenmodell bleibt gleich.

> **Aus der Praxis:** Der Exploit läuft in Terminal 2, die Shell kommt in Terminal 3 an. Ariadne sollte beides über Zeit und LHOST/LPORT verknüpfen. Genau diese Kette (Befehl > Callback > Shell) ist der Angriffspfad, den der Report braucht.

### 2.6 Riesige Outputs

*Wie umgehen mit riesigen Outputs wie linpeas?*

- **A) Alles speichern, alles vollständig parsen**: Nichts geht verloren, aber die Parser müssen schnell und robust sein. Ohne Filter flutet linpeas den Graph mit Tausenden Pseudo-Fakten.
- **B) Output abschneiden**: Spart Platz, aber relevante Treffer stehen oft weit unten. Als Beweis lückenhaft, nicht zu empfehlen.
- **C) Roh speichern, Spezialparser plus Zusammenfassung**: Ein linpeas/winPEAS-Parser übernimmt nur markierte Funde als Fakten. Der Rest ist durchsuchbar, mit Link auf die Zeile. Die Karte zeigt «12 Hinweise» statt 4000 Zeilen.
- **D) LLM fasst zusammen**: Deckt auch unbekannte Tools ab, aber kann halluzinieren und gefährdet die Vertraulichkeit. Nur lokal und als Vorschlag sinnvoll.

**Empfehlung:** C, D optional lokal und erst mit dem LLM-Gateway. Asynchron verarbeiten, das Terminal darf nie blockieren. Neue Fakten deduplizieren und nur echte Neuigkeiten melden. Eigene Parser für linpeas, winPEAS und enum4linux-ng kommen in v0.3, bis dahin reicht die Volltextsuche. Praxisregel ab sofort: Grosse Outputs auf dem Ziel in eine Datei schreiben, herunterladen und mit `ariadne import --host <host>` einlesen.

> **Aus der Praxis:** linpeas markiert wahrscheinliche Privesc-Vektoren farbig (rot/gelb). Die ANSI-Farbcodes sind also Signal: erst auswerten, dann entfernen. Über instabile Reverse Shells kommt Output oft verstümmelt an. Besser auf dem Ziel in eine Datei schreiben und zurückholen.

## 3. Dateien, Screenshots, weitere Quellen

### 3.1 Welche Dateien lesen

*Welche Dateien soll Ariadne lesen?*

- **A) MVP: Recon-Outputs der Standardtools**: nmap-XML (-oX/-oA), ffuf-JSON, nuclei-JSONL, gobuster/feroxbuster-Text. Deterministisch parsbar, sofort nützlich bei Metasploitable2 und HTB.
- **B) MVP: Loot-Klassiker**: /etc/passwd, /etc/shadow, secretsdump-Format, hashcat-Potfile, SSH-Keys, dazu .env, wp-config.php, web.config, die per Muster nach Creds und Hosts durchsucht werden.
- **C) Phase 2: AD und Frameworks**: BloodHound-JSON (bloodhound-python liefert das Legacy-Format, für BloodHound CE braucht es bloodhound-ce-python oder SharpHound CE), NetExec-Ausgaben, Metasploit db_export. Für AD-Labs zentral, aber grosse Datenmengen.
- **D) Eigene Notizen eher als Ausgabe**: Obsidian ist das Ziel für Exporte, nicht die Quelle. Höchstens strukturierte Teile (Frontmatter, Tags, Checklisten) einlesen, Freitext ist unzuverlässig.
- **E) Kaum/nie: Binärformate und Kundendokumente**: SAM-Hive und NTDS.dit (eine ESE-Datenbank, kein Hive) selbst parsen, PDFs, Office-Dateien. Dafür gibt es impacket-secretsdump. Viel Aufwand und ein Risiko für die Vertraulichkeit.

**Empfehlung:** Reihenfolge nach Nutzen. v0.1: nmap-XML plus Regex-Netz. v0.2: ffuf-JSON, feroxbuster/gobuster, NetExec, hashcat-Potfile, /etc/passwd und /etc/shadow, secretsdump. v0.3: linpeas/winPEAS (nur markierte Funde), enum4linux-ng (-oJ), nuclei-JSONL, Config-Dateien. BloodHound nur als Import der Kernfakten, sobald du AD-Labs machst. D als Exportrichtung, E nicht.

> **Aus der Praxis:** Lass nmap immer mit -oA laufen und parse nur das XML. Bildschirm- und -oN-Output ändern sich zwischen Versionen, -oG gilt laut nmap-Doku als deprecated. Wer -oA verinnerlicht, bekommt die Basis von Ariadne gratis.

### 3.2 Ordner überwachen

*Projektordner automatisch überwachen oder gezielt füttern?*

- **A) Ganzen Projektordner automatisch überwachen**: inotify meldet jede neue Datei, Ariadne erkennt den Typ und parst sie. Bequem, bringt aber Temp-Dateien, halbe Dateien und Rauschen.
- **B) Gezielt per Import-Befehl füttern**: `ariadne import scans/web.xml`. Volle Kontrolle, aber du vergisst es genau dann, wenn es zählt.
- **C) Watcher mit fester Ordnerstruktur**: scans/, loot/, screenshots/, notes/. Der Ordner bestimmt Parser und Vertraulichkeitsstufe. Ariadne legt die Struktur beim Projektstart an.
- **D) Shell-Hook kündigt Dateien an**: Der Shell-Hook sieht -oA oder -o im Befehl, wartet auf die Datei und verknüpft sie mit Befehl und Host-Kontext.

**Empfehlung:** D + C, in v0.1 ohne Hintergrunddienst: Der precmd-Hook sieht -oX oder -oA im eben beendeten Befehl (die Datei ist dann vollständig) und stösst den Import im Hintergrund an. Alles andere läuft über `ariadne import` (B). Die feste Ordnerstruktur gibt es ab v0.1, der inotify-Watcher für loot/ und screenshots/ folgt in v0.2. D ist das Killerfeature: Zu jeder Datei ist bekannt, welcher Befehl sie wann gegen welches Ziel erzeugt hat.

> **Aus der Praxis:** Watcher feuern auch bei halben Dateien. nmap-XML ist erst nach dem Scan gültig, weil das Root-Tag zuletzt geschlossen wird. Erst bei IN_CLOSE_WRITE bzw. Prozessende parsen, und Parser so bauen, dass erneutes Einlesen keine Duplikate erzeugt.

### 3.3 Screenshots auswerten

*Was ist auf Screenshots zu sehen, und reicht OCR oder soll Ariadne den Inhalt verstehen?*

- **A) Nur als Beweis mit Kontext anhängen**: Der Screenshot hängt mit Zeitstempel und aktivem Kontext an Host oder Finding. Keine Analyse, keine Fehler, reicht für den Report.
- **B) OCR für die Volltextsuche**: Tesseract lokal macht Screenshots durchsuchbar (Admin-Panel, Fehlermeldung). Bei Dark Themes und kleiner Schrift fehleranfällig.
- **C) OCR plus Musterextraktion**: Schlägt IPs, URLs, Versionsnummern und Usernamen aus dem OCR-Text als Fakten-Kandidaten vor, mit Status «unbestätigt».
- **D) Inhalt per Vision-LLM verstehen**: Erkennt Login-Panel, Stacktrace, Windows-Dialog. Lokal mit einem multimodalen Modell möglich, Cloud nur bei Lab-Daten vertretbar.

**Empfehlung:** v0.1: A, Screenshots als Beweis mit Zeitstempel und aktivem Kontext. B (OCR mit Tesseract) und C später, D optional lokal über das LLM-Gateway. Typisch zu sehen: Web-Logins und Admin-Panels, Fehlermeldungen mit Versionen, RDP-Desktops, Proof-Shots. Terminal-Inhalte liefert schon der Logger als Text, OCR braucht es also nur für GUI und Web.

> **Aus der Praxis:** Ein Screenshot ist vor allem Beweis. Einsteiger knipsen eine Root-Shell, auf der weder Hostname noch IP zu sehen sind. Für den Kunden ist das wertlos. Ariadne könnte warnen: «Proof-Screenshot ohne Host-Identifikation».

### 3.4 Wer macht Screenshots

*Wer macht die Screenshots?*

- **A) Du mit Flameshot, Ariadne überwacht Ordner**: Bewährt und ohne Aufwand. Host und Finding lassen sich nur über den Zeitstempel zuordnen, also unscharf.
- **B) Ariadne-Hotkey startet Flameshot**: z. B. `flameshot gui -p <projekt>/screenshots`. Ariadne hängt aktiven Host, letzten Befehl und eine optionale Notiz gleich an.
- **C) Automatische Screenshots aller HTTP-Dienste**: Wie gowitness oder aquatone. Sehr nützlich für die Übersicht, baut aber aktiv Verbindungen zum Ziel auf, ist also kein reines Beobachten mehr.
- **D) Terminal-Beweise aus dem Log erzeugen**: Befehl, Output und Zeitstempel als Bild oder Codeblock für den Report. Manuelle Terminal-Screenshots fallen weg.

**Empfehlung:** B + D. `ariadne shot` startet Flameshot mit -p in screenshots/ und hängt aktiven Host, letzten Befehl und eine optionale Notiz an. Terminal-Belege erzeugt der Export direkt aus dem Log. C nur als Import: Du startest gowitness selbst, Ariadne liest die Ergebnisse. Das passt zu «beobachten, nicht angreifen», und den Scope kontrollierst weiterhin du.

> **Aus der Praxis:** Automatische Web-Screenshots treffen gern Ziele ausserhalb des Scopes, etwa vHosts, die auf Drittanbieter, CDNs oder SaaS zeigen. Bei Kundenaufträgen jede URL zuerst mit der Scope-Liste abgleichen, auch wenn es nur ein HTTP-Request ist.

### 3.5 Weitere Quellen

*Sind weitere Quellen interessant (Burp, Browser, Zwischenablage, PCAPs)?*

- **A) Burp-/ZAP-History bzw. HAR**: Endpunkte, Parameter, Cookies, Technologien. Für Webtests extrem wertvoll. Export als XML aus Burp oder als HAR aus den Browser-DevTools.
- **B) Metasploit-DB und Logs von Angriffstools**: hosts, services, creds aus msfdb per db_export, Responder-Logs mit Hashes. Strukturiert, kaum Parser-Risiko.
- **C) PCAPs**: Liefert passiv Hosts, Dienste und Klartext-Protokolle via tshark oder Zeek. Bei internen Tests nützlich, im HTB-Alltag selten.
- **D) Zwischenablage**: Fängt kopierte Hashes und Creds ab, aber auch deine eigenen Passwörter aus dem Passwortmanager. Nur explizit sinnvoll.
- **E) Browser-Verlauf**: Meist Rauschen und Privates. Burp liefert dieselben URLs sauberer und samt Inhalt.

**Empfehlung:** A + B nach v0.3, C optional später, D nur explizit per Hotkey oder `ariadne paste`, E nicht. Burp ist für Webtests nach dem Terminal die wichtigste Quelle. Responder- und Metasploit-Daten sind strukturiert, also günstige Parser mit grossem Nutzen.

> **Aus der Praxis:** Automatisches Mitlesen der Zwischenablage ist der klassische Weg, auf dem das eigene E-Banking-Passwort im Kundenprojekt landet. Bei Quellen ausserhalb des Terminals ist explizit besser als automatisch.

## 4. Neue Werte auslesen

### 4.1 Wichtige Werte priorisieren [Kernfrage]

*Welche Werte sind wichtig?*

- **A) Muss im MVP: Netz und Zugänge**: IP, Hostname, Domain, Port/Protokoll, Service und Version, OS, User, Passwörter, NTLM- und Linux-Hashes, Flags. Kern jeder Box und jedes Labs.
- **B) Muss im MVP: Angriffsflächen und Credential-Ergebnisse**: URLs/Endpunkte, vHosts, Shares mit Rechten, interessante Dateipfade, CVEs, plus pro Credential: wo getestet, Ergebnis (gültig, Admin, fehlgeschlagen).
- **C) Phase 2: AD-Kern und Secrets**: Domain-User, Gruppen, Admin-Mitgliedschaften, SPNs, Kerberos-Hashes (AS-REP/TGS), Tokens und API-Keys aus Configs per Regex-Mustern.
- **D) Import statt Eigenbau: ACLs, GPOs, ADCS**: Komplexe AD-Beziehungen aus BloodHound-Daten importieren oder verlinken. Selbst parsen lohnt nicht, BloodHound macht das besser.
- **E) Nie automatisch: Inhalte von Kundendaten**: Dateiinhalte, DB-Dumps, Mails, Personendaten nicht ins Modell übernehmen, nur Fundstelle und Art referenzieren. Senkt Haftungs- und Leckrisiko.

**Empfehlung:** v0.1: A über nmap, Regex-Netz und `ariadne cred add`. v0.2: B mit Testergebnis pro Credential (gültig, Admin, fehlgeschlagen) aus NetExec und hydra. C später, D als Import, E als feste Regel ab Tag 1. Der grösste Hebel ist die Verknüpfung: welches Secret gehört zu welchem User, wo wurde es getestet, mit welchem Ergebnis.

> **Aus der Praxis:** Speichere auch Fehlschläge. 'svc_sql:Summer2024! auf 10.10.10.5 SMB: gültig, kein Admin; WinRM: abgelehnt' verhindert, dass du dieselbe Kombination nach sechs Stunden nochmals testest oder einen Account sperrst.

### 4.2 Parser, LLM oder Hybrid [Kernfrage]

*Feste Parser, LLM oder gemischt?*

- **A) Nur feste Parser**: Zuverlässig, testbar, reproduzierbar. Deckt aber nur bekannte Tools und Formate ab, alles andere geht stillschweigend verloren.
- **B) Nur LLM**: Breite Abdeckung ohne Parser-Aufwand. Dafür Halluzinationen, Latenz, Kosten, nicht reproduzierbar. Eine erfundene IP in der Karte ist gefährlich.
- **C) Parser zuerst, LLM für den Rest**: Bekannte Tools deterministisch, unbekannter Output optional ans LLM. LLM-Ergebnisse nur als Vorschlag mit Verweis auf die Quellzeile.
- **D) Parser plus Regex-Netz, LLM später**: Parser für die Top-Tools, generische Muster für IPs, Hashes, URLs, CVEs, E-Mails als Auffangnetz. Kein Modell nötig, sofort offline lauffähig.

**Empfehlung:** C als Zielbild, gestartet als D. Rund zehn Tools liefern den Grossteil der Fakten: nmap (-oX), NetExec, ffuf, feroxbuster/gobuster, enum4linux-ng, smbmap, hydra, secretsdump, hashcat-Potfile. Die baust du sauber, Regex fängt den Rest als unbestätigte Kandidaten. Das LLM kommt erst nach v0.3 als austauschbares Plugin hinter einem Gateway und muss jeden Wert wörtlich im Rohtext belegen.

> **Aus der Praxis:** Lass das LLM nie frei formulieren, sondern nur Werte zurückgeben, die wörtlich im Input vorkommen, und prüfe das per String-Match. So filterst du Halluzinationen deterministisch. Und: nmap-XML ist viel stabiler zu parsen als die Textausgabe.

### 4.3 LLM lokal oder Cloud

*Falls LLM: lokal oder Cloud?*

- **A) Nur lokal über Ollama**: Nichts verlässt den Rechner, offline nutzbar. Kleinere Modelle sind schwächer und brauchen RAM/GPU, für reine Extraktion oft ausreichend.
- **B) Nur Cloud-API**: Beste Qualität, keine Hardware nötig. Secrets und Kundendaten verlassen den Rechner, in vielen Aufträgen vertraglich unzulässig.
- **C) Pro Projekt festgelegt, Default lokal/aus**: Projektprofil bestimmt die Policy: Lab/HTB darf Cloud, Kundenauftrag nur lokal oder gar kein LLM. Bewusste, dokumentierte Entscheidung.
- **D) Cloud mit Schwärzung vorher**: Secrets, IPs, Namen durch Platzhalter ersetzen, Antwort lokal zurückübersetzen. Hilfreich, aber aufwendig und nie vollständig dicht.

**Empfehlung:** C, mit A als Standard für alles Sensible. Die Entscheidung gehört ins Projektprofil, nicht in einen globalen Schalter: harter Block für Kunden- und Prüfungsprojekte, sichtbarer Status, Log jedes Aufrufs. Technisch gibt es genau ein LLM-Gateway, das als einzige Komponente ein Modell ansprechen darf. D nur als Zusatz für Labs. Ariadne muss ohne LLM vollständig funktionieren.

> **Aus der Praxis:** Lies Auftrag, NDA und Prüfungsregeln: Kundenverträge regeln oft, wo Daten verarbeitet werden dürfen, und OffSec schliesst laut Exam Guide AI-Chatbots/LLMs in der OSCP-Prüfung aus. Ein Projektprofil 'Prüfung' mit LLM aus schützt dich vor einem Versehen.

### 4.4 Direkt oder bestätigen

*Erkannte Werte direkt in die Karte oder erst bestätigen?*

- **A) Alles direkt in die Karte**: Schnell, kein Klickaufwand. Fehlextraktionen und Rauschen verschmutzen die Karte unbemerkt, das Vertrauen ins Tool sinkt.
- **B) Alles erst bestätigen**: Saubere Daten, volle Kontrolle. Führt zu Bestätigungsmüdigkeit: Nach 50 Vorschlägen klickt man blind auf Annehmen.
- **C) Nach Vertrauen der Quelle**: Fakten aus strukturierten Parsern direkt, Regex-, OCR- und LLM-Treffer in eine Inbox zur Bestätigung, auch gesammelt.
- **D) Direkt, aber als unbestätigt markiert**: Alles erscheint sofort, unsichere Fakten visuell abgesetzt und jederzeit verwerfbar. Kompromiss, aber Markierungen werden gern ignoriert.

**Empfehlung:** C, ergänzt um eine Scope-Regel. Fakten aus strukturiertem Parser-Output landen direkt, alles Heuristische in einer Inbox mit Sammelbestätigung. Werte ausserhalb des definierten Scopes landen nie automatisch als Ziel, sondern immer als Hinweis. So bleibt die Karte vertrauenswürdig, ohne dass du zum Klickknecht wirst.

> **Aus der Praxis:** Out-of-Scope ist der Klassiker: DNS-Antworten oder Configs enthalten IPs von Cloud-Anbietern, Partnern oder dem Firmen-Office. Landen die automatisch als Ziel in der Karte, scannst du sie beim nächsten Durchlauf mit. Das kann ein Vertragsbruch sein.

### 4.5 Aktualität und Nachauswertung

*Wie aktuell muss die Karte sein, und sollen alte Logs nachträglich auswertbar sein?*

- **A) Echtzeit-Streaming während des Befehls**: Parst Output schon während er läuft. Aufwendig und fehleranfällig mit PTY-Steuerzeichen, nur für sehr lange Scans nützlich.
- **B) Wenige Sekunden nach Befehlsende**: Befehl als abgeschlossene Einheit mit Input, Output, Exit-Code. Einfach, robust und für die Praxis völlig ausreichend.
- **C) Nur auf Knopfdruck/Batch**: Am einfachsten zu bauen, aber kein Live-Überblick. Man vergisst den Import, und die Karte veraltet.
- **D) Nachträglicher Import alter Logs**: script- und asciinema-Aufnahmen, tmux-Logs, Tool-Outputs nachträglich auswerten. Wichtig für bestehende Labs und den Einstieg mitten im Projekt.

**Empfehlung:** B + D über dieselbe Pipeline. Der Live-Collector schreibt nur Rohdaten, ein Ingest-Prozess wertet sie aus, egal ob frisch oder drei Wochen alt. Dann ist nachträgliches Auswerten kein Extra-Feature, sondern derselbe Code. Für lange Scans genügt es, die -oX-Datei zu beobachten, statt den Terminal-Stream live zu parsen.

> **Aus der Praxis:** Rohdaten unveränderlich speichern und Auswertung strikt trennen. Nach einem Parser-Bugfix wertest du das ganze Engagement neu aus, ohne etwas zu verlieren. Das ist zugleich deine Beweiskette für den Report.

### 4.6 Widersprüche erkennen

*Soll Ariadne Widersprüche erkennen?*

- **A) Nein, neuester Wert gewinnt**: Einfach. Ein ungenauer Fingerprint überschreibt aber einen korrekten Banner, und die Information, dass es zwei Werte gab, ist weg.
- **B) Alle Werte behalten, ohne Hinweis**: Kein Datenverlust, jede Behauptung mit Quelle. Der Widerspruch fällt aber nur auf, wenn man zufällig hinschaut.
- **C) Behalten und Konflikt markieren**: Mehrere Quellen pro Attribut, sichtbarer Konflikt-Hinweis, du entscheidest oder lässt offen. Kaum Mehraufwand bei richtigem Datenmodell.
- **D) Automatisch nach Quellenvertrauen auflösen**: Regeln wie 'Banner schlägt Fingerprint'. Bequem, aber versteckt Fälle, die eigentlich selbst ein Befund sind.

**Empfehlung:** C. Speichere Fakten als Behauptungen mit Quelle (wer sagt was, wann, von wo), nicht als einfache Attribute. Dann ist Konflikterkennung fast gratis. Widersprüche sind oft selbst wertvoll: anderer vHost, Reverse Proxy, Load Balancer oder Backport-Patches. Eine Bevorzugung wie in D taugt als Anzeige-Default, nie als Löschregel.

> **Aus der Praxis:** Debian und Ubuntu backporten Sicherheitspatches, ohne die Upstream-Versionsnummer zu ändern. 'Apache 2.4.29' kann also gepatcht sein. Wer daraus ungeprüft CVEs in den Report schreibt, produziert False Positives, die der Kunde sofort zerpflückt.

## 5. Die Karte

### 5.1 Was die Karte ist [Kernfrage]

*Was ist die Karte?*

- **A) Netzwerk-Topologie**: Subnetze, Hosts, Routen, Segmentgrenzen. Gute Orientierung, zeigt aber weder Fortschritt noch Angriffswege.
- **B) Angriffsgraph**: Kanten zeigen, wie du wohin kamst: Exploit, Credential, Pivot. Direkt die Basis für das Attack-Path-Kapitel im Report.
- **C) Credential-Graph bzw. -Matrix**: User/Secret gegen Host/Service mit Ergebnis. Zeigt Reuse-Chancen und was schon getestet wurde.
- **D) Spezialansichten AD und Web-App**: AD-Struktur und Web-Endpunkte. AD deckt BloodHound bereits sehr gut ab, Web eher als Baum oder Liste statt Graph.
- **E) Ein Modell, umschaltbare Ebenen**: Gemeinsamer Graph, Ansichten als Filter: Topologie, Angriff, Credentials. Mehr UI-Aufwand, aber keine doppelte Datenhaltung.

**Empfehlung:** E als Architektur, gestaffelt umgesetzt. v0.1: CLI-Tabellen (Hosts nach Subnetz, Services, Creds) und der Angriffspfad aus manuell markierten Schlüsselschritten (`ariadne mark foothold|privesc|pivot|loot`). v0.2: Web-UI mit Tabellen, Credential-Matrix und Graph für Pivots und Pfade. D nicht nachbauen: AD über BloodHound, Web als Endpunkt-Baum. Die Karte ist nur eine Sicht, der Wert steckt im Modell darunter.

> **Aus der Praxis:** Graphen werden ab etwa 50 Knoten zum Haarknäuel. Profis arbeiten meist mit Tabellen und Filtern, den Graph nutzt man für Pivots und Angriffspfade. Die Credential-Matrix ist das am meisten unterschätzte Werkzeug im ganzen Engagement.

### 5.2 Host-Status

*Sollen Hosts einen Status haben?*

- **A) Kein Status, nur Fakten**: Alles aus Fakten ableitbar, kein Pflegeaufwand. Aber kein Überblick auf einen Blick, wo du stehst.
- **B) Linearer Status**: Entdeckt, gescannt, Foothold, User, Root/SYSTEM. Einfach, farbcodierbar, passt perfekt zu HTB-Boxen.
- **C) Mehrere Achsen**: Zugriffslevel (keiner, User, Admin, SYSTEM/root) getrennt vom Arbeitsstand (offen, in Arbeit, Sackgasse, erledigt, out of scope).
- **D) Automatisch abgeleitet, manuell übersteuerbar**: Ariadne erkennt Shell, whoami-Output, Admin-Rechte und setzt den Status, du korrigierst bei Bedarf. Spart Pflege, braucht guten Host-Kontext.

**Empfehlung:** C + D, mit einem einzigen Statusmodell für alle Objekte: offen, in Arbeit, Sackgasse (mit Grund, entspricht Rabbit Hole), erledigt, out of scope. Hosts haben zusätzlich die Achse Zugriff: keiner, User, Admin, root/SYSTEM. In v0.1 setzt du den Status per CLI, ab v0.2 schlägt Ariadne ihn bei eindeutigem Beleg vor (z. B. whoami-Output im bestätigten Kontext).

> **Aus der Praxis:** 'Sackgasse' ist nie endgültig. Mit einem Passwort von Host C wird Host A oft plötzlich lösbar. Ariadne sollte Sackgassen wieder vorschlagen, sobald neue Creds oder User auftauchen. Genau das übersieht man nach zehn Stunden.

### 5.3 Segmente und Tunnel

*Müssen Netzsegmente und Tunnel abgebildet werden?*

- **A) Nein, flaches Netz**: Reicht für einzelne HTB-Boxen und Metasploitable2. Scheitert bei Pro Labs, AD-Sets und jedem internen Kundennetz.
- **B) Segmente als Gruppen, ohne Tunnel**: Subnetze werden gruppiert dargestellt. Zeigt Struktur, aber nicht, wie du hinkommst und welcher Output über welchen Pfad lief.
- **C) Segmente plus Tunnel als eigene Objekte**: Tunnel mit Typ (chisel, ligolo-ng, ssh -L/-R/-D), Pivot-Host, Ports, aktiv/inaktiv. Verbindet Segmente als Kanten.
- **D) Volle Routing- und Erreichbarkeitsberechnung**: Ariadne berechnet, was von wo erreichbar ist. Sehr mächtig, für einen Einzelentwickler aber unverhältnismässig aufwendig.

**Empfehlung:** C im Datenmodell ab Tag 1, im MVP-UI minimal. Ohne Tunnel-Objekte kann Ariadne Output über proxychains, ligolo-ng oder Port-Forwards nicht dem richtigen Host zuordnen. Tunnel legst du anfangs manuell an, automatische Erkennung aus chisel- oder ssh-Befehlen kommt später. Loopback-Adressen aus Port-Forwards erzeugen nie automatisch einen Host.

> **Aus der Praxis:** Port-Forwards verfälschen Ziele: Ein Dienst auf 127.0.0.1:8080 gehört eigentlich zum Host hinter dem Tunnel. Zudem funktioniert nmap über proxychains nur als TCP-Connect-Scan (-sT -Pn). Ariadne muss solche Adressen zurückübersetzen.

### 5.4 Zeitachse und Replay

*Wie wichtig ist die Zeitachse?*

- **A) Unwichtig, nur Endzustand**: Am einfachsten. Report-Narrativ, Nachweis und Antworten auf Rückfragen fehlen später komplett.
- **B) Zeitstempel pro Fakt und Befehl**: Chronologische, filterbare Liste. Fällt bei sauberer Provenienz fast gratis ab und reicht für Report und Rückfragen.
- **C) Zustand zu Zeitpunkt X rekonstruieren**: Karte 'zurückspulen' per Event-Log. Ergibt sich fast von selbst, wenn alles append-only gespeichert wird.
- **D) Volles Terminal-Replay**: Sitzung wie ein Video abspielen. Nicht selbst bauen, asciinema-Aufnahmen verlinken genügt.

**Empfehlung:** B im MVP, C durch Design ermöglichen (append-only Event-Log statt Überschreiben), D über asciinema verlinken. Die Zeitachse ist in echten Aufträgen Pflicht: Report-Narrativ, Nachweis gegenüber dem Kunden und Abgleich mit dem Blue Team hängen daran. Zeiten immer in UTC speichern, lokal anzeigen.

> **Aus der Praxis:** Garantiert kommt die Frage vom SOC: 'Waren Sie das um 03:12 Uhr auf dem DC?' Mit Zeit, Quell-IP und Befehl beantwortest du das in einer Minute. Ohne Zeitachse hast du ein echtes Problem, im Extremfall ein rechtliches.

### 5.5 Fakt zur Quelle

*Soll jeder Fakt zu seiner Quelle führen?*

- **A) Nein, nur der Wert**: Einfachste Datenhaltung. Fakten nicht überprüfbar, Fehler nicht auffindbar, im Report kein Nachweis.
- **B) Verweis auf Befehl und Zeitpunkt**: Klick zeigt Befehl, Zeit, Host-Kontext und den ganzen Output. Solide, aber du suchst die relevante Stelle selbst.
- **C) Bis zur exakten Zeile im Rohoutput**: Fundstelle hervorgehoben, bei OCR auch der Bildausschnitt. Mehrere Quellen pro Fakt möglich. Etwas mehr Aufwand im Parser.
- **D) Zusätzlich als Report-Evidence exportierbar**: Befehl, Zeit und Output-Ausschnitt als fertiger Nachweisblock für Report oder Obsidian-Notiz kopierbar.

**Empfehlung:** C + D. Provenienz ist der eigentliche Unterschied zu Notiz-Tools wie Obsidian oder CherryTree. Gespeichert werden Byte-Offset im Rohstrom und Zeile in einer bereinigten Textfassung (ANSI-Farben zuerst auswerten, dann entfernen, Überschreibungen auflösen, z. B. mit pyte). Evidence-Blöcke für den Report fallen damit fast gratis ab.

> **Aus der Praxis:** Die häufigste Report-Qual: nach dem Engagement den exakten Befehl und Output für ein Finding aus Shell-History und Screenshots zusammenkratzen. Wenn Ariadne nur dieses Problem löst, hat es sich bereits gelohnt.

### 5.6 Grösse der Umgebungen

*Wie gross sind die Umgebungen?*

- **A) Einzelhost (HTB-Box, Metasploitable2)**: Ein Host, viele Services. Karte fast trivial, der Wert liegt in Creds, Notizen, Zeitachse und Nachweisen.
- **B) Lab mit 5 bis 20 Hosts**: Pro Labs, OSCP-AD-Set, Schul-Labs. Pivots, AD und Credential-Reuse: genau hier verliert man den Überblick.
- **C) Firmennetz mit Hunderten bis Tausenden Systemen**: Performance, Massenimport, Gruppierung, Tabellen statt Graph. Arbeit nach Service-Gruppen statt pro Host.
- **D) MVP für B, Modell skaliert bis C**: UI und Tests auf Labs optimiert, Datenmodell und Speicher (z. B. SQLite) so gewählt, dass grosse Scans nicht brechen.

**Empfehlung:** D. Teste mit Metasploitable2 und HTB, optimiere die Bedienung für 5 bis 50 Hosts. SQLite verträgt Tausende Hosts problemlos, eine Graph-Ansicht nicht. Plane deshalb früh Gruppierung nach Subnetz und Service sowie eine Tabellenansicht. Grosse Netze kommen meist als nmap- oder masscan-Import, nicht Befehl für Befehl.

> **Aus der Praxis:** Im internen Kundenpentest arbeitest du nach Service-Gruppen, nicht nach Hosts: 'alle SMB ohne Signing', 'alle Tomcat-Manager'. Diese Service-Sicht früh einzuplanen kostet wenig und unterscheidet Ariadne von einem reinen Box-Notizbuch.

## 6. Anzeige und Bedienung

### 6.1 Ort der Karte [Kernfrage]

*Wo soll die Karte angezeigt werden?*

- **A) TUI im Terminal**: Bleibt im Workflow und läuft auch über SSH und tmux. Graphen sind im Terminal aber kaum lesbar, es bleiben eher Listen, Tabellen und Statusansichten.
- **B) Lokale Web-Oberfläche mit interaktivem Graph**: Läuft im Browser auf 127.0.0.1, der Graph z. B. mit Cytoscape.js. Bietet die beste Übersicht, Filter und Zeitachse, kostet aber zusätzlichen Aufwand fürs Frontend.
- **C) Export nach Obsidian (Markdown und Canvas)**: Pro Host oder Service eine Notiz, das Canvas dient als Karte. Passt zu deinem Workflow, ist aber nicht live, und das Canvas-Layout wird schnell unübersichtlich.
- **D) Kombination: Web live, Obsidian als Archiv**: Mit der Web-Ansicht arbeitest du live, Obsidian bekommt einen Export in eine Richtung für Lernnotizen und Nachbereitung. Die Daten liegen massgeblich in Ariadne.
- **E) Eigene Desktop-App (Tauri/Electron)**: Eigene Fenster und offline nutzbar. Für einen Einzelentwickler ist das viel Zusatzaufwand ohne echten Mehrwert gegenüber einer lokalen Web-Oberfläche.

**Empfehlung:** D als Ziel, gestaffelt. v0.1: CLI-Abfragen, tmux-Statuszeile und Markdown-Export in den Projektordner, den du in Obsidian als eigenen Vault öffnest (Obsidian lädt geänderte Dateien selbst neu, das wirkt fast live). v0.2: lokale Web-UI, zuerst Tabellen und Timeline, Graph für Pivots. Export strikt in eine Richtung, an Zwei-Wege-Sync mit Obsidian scheitern viele Hobbyprojekte. TUI höchstens später.

> **Aus der Praxis:** Web-UI nur an 127.0.0.1 binden, zufälliger Port mit Token, Host-Header prüfen (DNS-Rebinding), kein CORS, alle JS-Bibliotheken lokal statt per CDN. Du testest im selben Browser feindliche Web-Apps. Einen Vault mit Kundendaten nie über Obsidian Sync, OneDrive oder iCloud synchronisieren.

### 6.2 Live auf zweitem Bildschirm

*Soll die Ansicht live auf einem zweiten Bildschirm mitlaufen?*

- **A) Live-Ansicht mit automatischer Aktualisierung**: Die Web-Oberfläche aktualisiert sich per WebSocket oder SSE. Neue Hosts, Ports und Credentials erscheinen sofort, ideal mit einem zweiten Monitor.
- **B) Nur auf Abruf**: Du öffnest die Ansicht bei Bedarf oder aktualisierst sie per Befehl. Das ist ruhig, aber unter Druck vergisst man nachzuschauen.
- **C) Kompakte Statusleiste in tmux**: Zähler für Hosts, Credentials und offene Punkte stehen in der tmux-Statuszeile. Das funktioniert auch auf einem einzelnen Laptop-Bildschirm.
- **D) Benachrichtigung nur bei wichtigen Ereignissen**: Eine Desktop-Benachrichtigung (notify-send) kommt nur bei starkem Signal: neue Credentials, neuer Host, neue Admin-Rechte. Alles andere bleibt still.

**Empfehlung:** v0.1: C, die tmux-Statuszeile zeigt Projekt, Profil, Kontext und Logging-Status. Ab v0.2: A (Live-Web-Ansicht auf dem zweiten Bildschirm, anfangs per Polling) + D (Benachrichtigung nur bei neuen Creds, neuem Host oder neuen Admin-Rechten). Mehr Benachrichtigungen schaltest du nach einem Tag ab.

> **Aus der Praxis:** Plane einen Präsentationsmodus ein, der Passwörter und Hashes maskiert. Spätestens beim Screensharing im Kundenmeeting oder in einer beaufsichtigten Prüfung mit Bildschirmfreigabe willst du keine Klartext-Credentials auf dem zweiten Monitor zeigen.

### 6.3 Fragen an die Karte

*Soll man der Karte Fragen stellen können?*

- **A) Vordefinierte Ansichten und Filter**: Klickbare Filter nach Host, Service, Status und Tag sowie fertige Ansichten wie eine Credential-Matrix. Zuverlässig und schnell gebaut.
- **B) Abfragesprache oder SQL**: Eine eigene kleine Filtersyntax oder direktes SQL auf SQLite. Mächtig und exakt, die Syntax muss man aber lernen.
- **C) Normale Sprache, LLM übersetzt in Abfrage**: Das LLM erzeugt Filter oder SQL, Ariadne zeigt die Abfrage an und führt sie deterministisch aus. Das Ergebnis bleibt nachprüfbar.
- **D) Normale Sprache, LLM antwortet direkt**: Das LLM bekommt einen Ausschnitt des Graphen und antwortet frei. Bequem, aber es erfindet Fakten und schickt unter Umständen Credentials in die Cloud.

**Empfehlung:** v0.1: fertige CLI-Ansichten (hosts, services, creds, timeline, search) plus direkter sqlite3-Zugriff als B. v0.2: A als klickbare Filter in der Web-UI. C später über das LLM-Gateway, weil die erzeugte Abfrage sichtbar und prüfbar bleibt. D nie: Eine erfundene Antwort auf «noch nicht probiert» kostet dich Stunden oder einen Lockout.

> **Aus der Praxis:** 'Noch nicht probiert' lässt sich nur beantworten, wenn Ariadne auch Fehlschläge speichert, z. B. '[-]' bei nxc. Genau die verwerfen viele Parser. Eine Matrix aus Credential, Host und Service mit Status ok, fehlgeschlagen oder offen ist im AD-Pentest enorm wertvoll.

### 6.4 Report und Format

*Soll am Ende ein Report entstehen, und in welchem Format?*

- **A) Markdown als Master-Format**: Ein strukturierter Rohbericht mit Hosts, Findings, Zeitachse, Befehlen und Screenshots. Direkt in Obsidian nutzbar und Basis für alle anderen Formate.
- **B) docx oder PDF per Pandoc mit Vorlage**: Wird aus dem Markdown mit eigener Word-Vorlage erzeugt. Gut für die Schule und für kleine Kunden ohne Reporting-Plattform.
- **C) Export nach SysReptor**: Überträgt Findings und Notizen per API oder reptor-CLI. SysReptor gibt es als kostenlose Community-Version zum Selbsthosten.
- **D) Export nach PwnDoc**: Funktioniert ebenfalls über eine API. Lohnt sich nur, wenn dein Arbeitgeber oder dein Team PwnDoc bereits nutzt.
- **E) Vorlage für die Schulabgabe**: Ein Lab-Bericht mit Ziel, Vorgehen, Befehlen, Screenshots und Erkenntnissen. Im Modul Cybersecurity sofort einsetzbar.

**Empfehlung:** A als Kern, daraus E und B per Pandoc. C als erste Plattform-Anbindung später, D nur bei konkretem Bedarf. Ariadne schreibt keinen fertigen Kundenbericht, sondern liefert das Beweismaterial lückenlos: Fakt, Befehl, Output, Zeitpunkt, Screenshot. Bewerten und Formulieren bleibt Sache des Pentesters. Im Profil customer bleibt jeder Export im Projektordner.

> **Aus der Praxis:** Reports scheitern selten am Text, meist an fehlenden Beweisen. Typisch: Shell bekommen, aber kein Screenshot mit whoami, hostname und IP im selben Bild. Ariadne kann genau das prüfen und daran erinnern, solange die Shell noch offen ist.

### 6.5 Eigene Notizen und Tags

*Eigene Notizen, Tags und Markierungen an Objekten?*

- **A) Freie Notizen pro Objekt**: Eine Markdown-Notiz an Host, Service, User oder Credential. Platz für Gedanken, Hypothesen und Kontext.
- **B) Tags, vorgegeben und frei**: Vorgaben wie wichtig, Rabbit Hole, später und erledigt, dazu eigene Tags. In Karte und Abfragen filterbar.
- **C) Status-Workflow pro Objekt**: Zustände wie neu, in Arbeit, ausgeschöpft, Rabbit Hole und out of scope. Der Status bestimmt, welche Vorschläge Ariadne noch anzeigt.
- **D) Als Finding mit Schweregrad markieren**: Das Objekt wird als reportrelevant markiert und mit Schweregrad und Beweisen verknüpft. Das ist die Brücke zum Report.

**Empfehlung:** A + B + C, mit dem einheitlichen Statusmodell aus 5.2. Status, Tags und Kurznotizen setzt du per CLI (später Web-UI), damit auch sie Provenienz haben. Längere Gedanken schreibst du in Obsidian in eine eigene Datei (z. B. `hosts/lame.md`), die den generierten Teil per `![[lame-ariadne]]` einbettet. Generierte Dateien fasst du nie an, sonst überschreibt sie der nächste Export. D kommt mit dem Finding-Objekt (11.4).

> **Aus der Praxis:** Ein Rabbit Hole nie löschen, sondern mit Grund und Zeitpunkt parken. Mit neuen Credentials wird der Dienst von gestern oft zum Einstieg. Dokumentiere auch Negativbefunde ('SMB-Signing geprüft, aktiv'), denn der Kunde will wissen, was getestet wurde.

## 7. Nur beobachten oder auch handeln

### 7.1 Beobachten oder vorschlagen [Kernfrage]

*Nur beobachten und dokumentieren oder auch Vorschläge machen?*

- **A) Nur beobachten und dokumentieren**: Ein reiner Protokollant. Einfach und ohne Fehlalarme, verschenkt aber den grössten Nutzen: Lücken sichtbar zu machen.
- **B) Lückenanzeige pro Objekt**: Zeigt pro Service, was noch nicht geprüft ist, ohne konkrete Befehle. Eine Checkliste direkt neben der Karte.
- **C) Konkrete Vorschläge mit vorbefüllten Befehlen**: 'SMB offen, Shares noch nicht enumeriert' plus ein kopierbarer Befehl mit IP und bekannten Credentials. Ausführen tust du selbst.
- **D) Vorschläge für Angriffspfade**: Verknüpft Fakten zu Pfaden, etwa Credential-Reuse oder Pivot-Routen, ähnlich wie BloodHound. Hoher Nutzen, aber auch hoher Aufwand.

**Empfehlung:** B + C ab v0.3, D später. Die meisten verpassten Findings sind keine Wissenslücken, sondern unter Zeitdruck vergessene Schritte. Ein «noch offen» pro Service fängt genau das ab. Vorschläge immer als Kopiervorlage, nie automatisch ausgeführt, abschaltbar über den Status «erledigt». Im Profil exam komplett aus.

> **Aus der Praxis:** Die Klassiker, an die Ariadne erinnern sollte: kein Full-Port-Scan (-p-), kein UDP-Scan (SNMP auf 161), vHosts nicht geprüft, neue Credentials nicht gegen alle bekannten Dienste getestet. Credential-Reuse ist im Lab wie im echten Netz der häufigste Durchbruch.

### 7.2 Grundlage der Vorschläge

*Worauf basieren die Vorschläge?*

- **A) Feste Regeln und Checklisten als Daten**: YAML-Regeln wie 'Service smb vorhanden, Check share-enum fehlt'. Deterministisch, testbar, erweiterbar und offline nutzbar.
- **B) Nur LLM**: Das LLM liest den Kontext und schlägt vor. Deckt auch seltene Dienste ab, ist aber unberechenbar und schwer reproduzierbar.
- **C) Hybrid: Regeln zuerst, LLM ergänzt optional**: Die Regeln liefern die Basis. Ein LLM ergänzt bei unbekannten Services oder erklärt, klar als 'LLM-Vorschlag' gekennzeichnet.
- **D) Externe Methodik als Regelpakete**: Checklisten nach HackTricks, OWASP WSTG oder eigener Methodik als Pakete einbinden. Gibt Breite, kostet aber Pflegeaufwand.

**Empfehlung:** A mit v0.3, C später über das LLM-Gateway, D als Inspirationsquelle. Eigene Regeln sind nachvollziehbar, und beim Schreiben lernst du die Methodik selbst, ein echter Gewinn für Studium und Zertifizierung. LLM-Vorschläge nur für Dienste ohne Regel und immer gekennzeichnet.

> **Aus der Praxis:** Knüpfe Regeln an Prüfziele, nicht an Tools: Die Share-Enumeration ist erledigt, egal ob per smbclient -L, nxc smb --shares oder enum4linux-ng. Sonst nervt Ariadne mit Vorschlägen, die du längst anders erledigt hast. Auf HackTricks verlinken statt Inhalte kopieren.

### 7.3 Grenze für eigenes Handeln

*Darf Ariadne selbst Befehle ausführen? Wo ist die Grenze?*

- **A) Nie selbst ausführen**: Ariadne beobachtet nur. Maximale Kontrolle und Nachvollziehbarkeit, jeder Schritt bleibt deine bewusste Entscheidung.
- **B) Nur lokale Helfer ohne Netzwerkverkehr**: Abgleich mit searchsploit, Hash-Typ erkennen, Dateien parsen. Kein Paket geht von deinem Rechner ans Ziel.
- **C) Ausführung per Klick mit Bestätigung**: Nach Scope-Check und deinem OK wird der Vorschlag ausgeführt, der Output fliesst zurück. Nur für risikoarme Recon-Schritte.
- **D) Automatische Recon-Ketten**: Ein neuer Host löst automatisch Scans aus, ähnlich AutoRecon. Im Lab schnell, im Kundennetz laut und schwer zu kontrollieren.
- **E) Autonome Angriffe wie Credential-Spraying**: Ariadne testet Credentials und Exploits selbst. Hohes Risiko für Lockouts, Ausfälle und Scope-Verletzungen.

**Empfehlung:** A bis v0.3, danach B: lokale Helfer ohne Netzwerkverkehr (Hash-Typ erkennen ab v0.2, `searchsploit --nmap` ab v0.3, Treffer nur als «Hinweis: Version, nicht verifiziert»). C frühestens nach v0.3 mit Scope-Check und Protokoll, D höchstens als Lab-Modus, E nie. Die Grenze: Alles, was Pakete ans Ziel schickt, braucht deine ausdrückliche Bestätigung. Alles, was Konten sperren oder Dienste beeinträchtigen kann, bleibt Handarbeit.

> **Aus der Praxis:** Ein automatischer Spray gegen ein AD mit Lockout-Schwelle 5 sperrt in Minuten die halbe Belegschaft aus. Vor jedem Spray die Passwort-Policy prüfen, z. B. mit nxc smb <DC> -u <user> -p <pass> --pass-pol. Von Ariadne ausgeführte Befehle als solche kennzeichnen.

### 7.4 Scope-Warnung

*Soll Ariadne bei Zielen ausserhalb des Scopes warnen?*

- **A) Keine Scope-Prüfung**: Einfach und im Lab ausreichend. Im Kundenauftrag fahrlässig, weil Verstösse unbemerkt bleiben.
- **B) Nur passiv markieren**: Hosts ausserhalb des Scopes erscheinen in Karte und Log rot markiert, ohne Unterbrechung. Den Fehler siehst du erst hinterher.
- **C) Warnung vor der Ausführung**: Ein Shell-Hook prüft Ziel-IPs, CIDRs und Hostnamen gegen Scope und Ausschlussliste und warnt, bevor der Befehl läuft.
- **D) Blockieren mit bewusstem Override**: Der Befehl wird angehalten, bis du bestätigst. In zsh geht das sauber über ein accept-line-Widget, preexec allein reicht dafür nicht.
- **E) Scope mit Ausschlüssen und Zeitfenstern**: Pro Engagement ein Scope inklusive Ausschlüssen (z. B. Produktions-DB) und erlaubter Testzeiten. So ist es auftragstauglich.

**Empfehlung:** B ab v0.1, dann C und D als ein Mechanismus: ein zle-Widget, das accept-line umschliesst und den Befehl vor der Ausführung prüft (preexec läuft erst nach Enter und kann nichts mehr aufhalten). Profil lab: nur Warnung, Profil customer: Bestätigung nötig. Widget in v0.2, E (Ausschlüsse, Zeitfenster) mit dem Kundenprofil in v0.3. In der Schweiz ist unbefugtes Eindringen nach Art. 143bis StGB strafbar, ausserhalb des Scopes deckt dich der Auftrag nicht.

> **Aus der Praxis:** Scope-Checks scheitern an Umwegen: Ziele in Dateien (nmap -iL), Hostnamen, die anders auflösen, Pivots über proxychains oder ligolo-ng. Trifft es trotzdem einen Host ausserhalb, sofort mit Zeitpunkt und Befehl dokumentieren und dem Kunden melden.

## 8. Sicherheit und Daten

### 8.1 Projekttrennung pro Auftrag

*Strikt getrennte Projekte pro Auftrag?*

- **A) Eine Datenbank, Projekte nur als Tag**: Einfach zu bauen, projektübergreifende Suche gratis. Aber Daten vermischen sich bei Fehlern, und das Löschen pro Kunde ist mühsam und fehleranfällig.
- **B) Strikt getrennte Workspaces, eigener Ordner pro Projekt**: Eigene DB, Rohlogs und Screenshots pro Projekt. Aktives Projekt wird explizit gewählt. Archivieren und Löschen pro Auftrag mit einem Befehl.
- **C) Workspace plus Scope-Definition pro Projekt**: Pro Projekt IP-Ranges, Domains, Ausschlüsse und Zeitfenster. Ariadne markiert Out-of-Scope-Ziele und warnt, bevor du sie anfasst.
- **D) Separate, kundenfreie Wissensbasis über alle Projekte**: Methodik, Checklisten, eigene Payloads und Parser-Regeln global, aber nie Hosts, Creds oder Kundendaten. Du lernst aus Projekten, ohne Daten zu vermischen.

**Empfehlung:** B + C ab v0.1: ein Ordner pro Projekt mit eigener Datenbank und einer Scope-Datei (IP-Ranges, Domains, Ausschlüsse). In v0.1 markiert Ariadne Ziele ausserhalb des Scopes nur passiv, die aktive Warnung folgt in v0.2 (siehe 7.4). D später (siehe 11.8). Harte Trennung kostet am Anfang wenig, lässt sich aber nachträglich kaum einbauen. In Labs ist ein Projekt pro HTB-Maschine oder Übungsreihe sinnvoll.

> **Aus der Praxis:** Fast jeder Kunde nutzt 192.168.1.0/24 oder 10.0.0.0/24, und HTB vergibt dieselben IPs an verschiedene Maschinen. Ohne harte Trennung verschmelzen Hosts aus verschiedenen Umgebungen zu einem Knoten, inklusive falscher Creds.

### 8.2 Verschlüsselung gespeicherter Daten

*Sollen gespeicherte Daten verschlüsselt sein?*

- **A) Keine eigene Verschlüsselung, Full-Disk-Encryption voraussetzen**: LUKS auf Host bzw. VM schützt bei Diebstahl im ausgeschalteten Zustand. Kein Aufwand im Tool, aber kein Schutz bei laufendem, entsperrtem System oder bei Kopien.
- **B) Verschlüsselter Projekt-Container mit Passphrase**: Das ganze Projekt (DB, Logs, Screenshots) ist verschlüsselt, z. B. mit SQLCipher plus verschlüsselter Dateiablage. Sicher, aber Schlüsselverwaltung und Performance werden dein Problem.
- **C) Nur Secrets-Felder verschlüsseln (Creds, Hashes)**: Wirkt sauber, ist aber trügerisch: Dieselben Passwörter stehen im Klartext in Rohlogs, Screenshots und Notizen.
- **D) Verschlüsselte Exporte und Archive (age oder GPG)**: Ein Projekt wird nach Abschluss als verschlüsseltes Archiv abgelegt oder übergeben. Einfach umzusetzen, deckt Aufbewahrung und Datentransfer ab.

**Empfehlung:** v0.1: A, beim ersten Projekt einmal fragen, ob Platte bzw. VM-Datei verschlüsselt sind. Eine automatische LUKS-Prüfung sieht aus der VM die Verschlüsselung des Host-Rechners nicht und warnt falsch. D (age-Archive) und ein Schlüssel pro Projekt für Crypto-Shredding kommen mit dem Kundenprofil in v0.3, B als spätere Option. Finger weg von C. Bis v0.3 gehören keine echten Kundendaten in Ariadne.

> **Aus der Praxis:** Mit einem Schlüssel pro Projekt ist Crypto-Shredding möglich: Schlüssel löschen, Daten unlesbar. Kunden verlangen nach Auftragsende oft einen Löschnachweis. Und denk an Backups: Ein unverschlüsseltes Backup des Home-Ordners hebelt alles aus.

### 8.3 Eigene Secrets herausfiltern

*Eigene Geheimnisse aus dem Log filtern?*

- **A) Unwichtig, alles ungefiltert loggen**: Null Aufwand, bis dein sudo-Passwort oder API-Key im Report-Anhang, in einem Screenshot oder im Prompt an ein Cloud-LLM landet.
- **B) Redaction vor dem Speichern per Muster und Liste**: Bekannte eigene Secrets (Liste im Keyring) und typische Formate wie API-Keys werden vor dem Schreiben ersetzt. Eingaben bei ausgeschaltetem Terminal-Echo werden grundsätzlich verworfen.
- **C) Manueller Pause-Schalter für sensible Momente**: Ein Befehl oder Tastenkürzel pausiert die Aufzeichnung sichtbar. Einfach und robust, aber du musst daran denken.
- **D) Eigene und erbeutete Secrets klar unterscheiden**: Creds vom Ziel sollen gerade erfasst werden. Die Redaction darf nur deine eigenen treffen, sonst filterst du Funde weg.

**Empfehlung:** Hohe Priorität: B (eingeschränkt) + C + D. Vor dem Schreiben nur exakte Treffer aus deiner eigenen Secret-Liste ersetzen (z. B. `[REDACTED:own:openai]`), keine generischen Muster, sonst vernichtest du Funde vom Ziel. Muster dienen nur als Warnung vor Exporten und LLM-Aufrufen. Passworteingaben bei ausgeschaltetem Echo landen gar nicht im Log, weil nur der Output erfasst wird. Nachträgliches Schwärzen per `ariadne redact` ist die einzige erlaubte Änderung am Rohlog und wird protokolliert.

> **Aus der Praxis:** Klassiker: export OPENAI_API_KEY=... im Terminal, oder du arbeitest nebenbei mit Firmen-Creds deines Arbeitgebers. Beides landet sonst in Logs und eventuell im LLM-Kontext. Auch die Shell-History (~/.zsh_history) enthält solche Zeilen.

### 8.4 Prüfungsmodus für Zertifizierungen

*Braucht es einen Prüfungsmodus?*

- **A) Kein Modus, Funktionen einzeln manuell abschalten**: Kein Entwicklungsaufwand, aber im Prüfungsstress vergisst man einen Schalter. Du kannst nicht nachweisen, was aktiv war.
- **B) Fester Prüfungsmodus: nur Logging, Parser, Notizen**: LLM, Vorschläge und jede Netzwerkverbindung nach aussen sind hart deaktiviert. Karte, Zeitachse und Notizen bleiben. Klar kommunizierbar.
- **C) Policy-Profile pro Projekt: exam, lab, customer**: Jedes Projekt hat ein Profil, das Funktionen erlaubt oder sperrt. Der Prüfungsmodus ist ein Preset, Kundenprofile sperren z. B. Cloud-LLM.
- **D) Separate Lite-Version ganz ohne LLM-Code**: Maximale Sicherheit gegenüber Prüfern, aber doppelte Pflege. Für einen Einzelentwickler unnötig aufwendig.

**Empfehlung:** C mit B als erstem Preset. Profile lösen zwei Probleme auf einmal: Prüfungsregeln und Kundenvorgaben wie ein Verbot von Cloud-LLMs. Das aktive Profil gehört sichtbar in den Prompt und in die Projekt-Metadaten, damit du nachweisen kannst, was lief. Im Prüfungsmodus sind Vorschläge komplett aus, auch regelbasierte.

> **Aus der Praxis:** Der OSCP-Exam-Guide verbietet u. a. AI-Chatbots/LLMs, automatische Exploitation-Tools wie sqlmap und Funktionen anderer Tools, die Verbotenes nutzen. Die Regeln ändern sich, also vor jeder Prüfung den aktuellen Guide lesen.

## 9. Technik

### 9.1 Programmiersprache

*Welche Programmiersprache?*

- **A) Python**: Schnellster Weg zum MVP. pty-Modul in der Standardbibliothek, viele Pentest-Tools sind selbst in Python geschrieben (Impacket, NetExec, Certipy), dazu LLM-SDKs. Verteilung etwas mühsamer.
- **B) Go**: Ein statisches Binary, gute Nebenläufigkeit für Watcher, creack/pty für PTYs. Weniger fertige Parser-Bibliotheken, mehr Handarbeit.
- **C) Rust**: Schnell und robust, aber steile Lernkurve. Neben Studium und Job ist das Risiko gross, nie fertig zu werden.
- **D) TypeScript**: Stark für eine Web- oder Electron-Oberfläche, schwach für systemnahe Teile wie PTY-Logging und Shell-Hooks.
- **E) Python-Kern, Oberfläche später als lokale Web-App**: Python sammelt, parst und speichert, die Karte läuft im Browser gegen eine lokale API. Kern und UI sind sauber getrennt.

**Empfehlung:** A, später ausgebaut zu E. Parser schreibt man in Python am schnellsten, ein grosser Teil deiner Kali-Tools ist darin geschrieben (Impacket, NetExec, Certipy), und bei Terminal-Text ist Performance kein Engpass. Nur wenn du Go schon sicher beherrschst, ist B wegen der einfachen Verteilung eine echte Alternative.

> **Aus der Praxis:** Der Engpass ist nie die Sprache, sondern die Pflege von Dutzenden Parsern über Tool-Versionen hinweg. Wähle die Sprache, in der du einen kaputten Parser um 2 Uhr nachts am schnellsten reparierst.

### 9.2 Zielsystem und Offline-Betrieb

*Welche Zielsysteme, und muss es offline laufen?*

- **A) Nur Kali als offizielle Plattform**: Kleinster Testaufwand, passt zu Schule und OSCP. Bindet dich aber an Kali-Eigenheiten wie Rolling Releases.
- **B) Debian-basierte Distros: Kali, Parrot, Ubuntu**: Kali als Referenz, der Rest best effort. Kaum Mehraufwand, wenn du Pfade und Shells (zsh, bash) sauber abstrahierst.
- **C) Jedes Linux, inklusive Arch und BlackArch**: Mehr potenzielle Nutzer, aber mehr Paket- und Pfadvarianten. Lohnt sich erst, wenn andere das Tool verwenden.
- **D) Offline-Pflicht: alles läuft ohne Internet**: Keine Funktion darf Internet voraussetzen, das LLM läuft nur lokal (z. B. Ollama) oder ist aus. Wichtig für Prüfungen und interne Kundennetze.
- **E) Headless-Betrieb auf Jumpbox oder VPS**: Der Collector läuft per SSH ohne GUI, die Ansicht lokal oder im Terminal. Nötig, wenn du von einem Angriffshost aus arbeitest.

**Empfehlung:** B + D, E vorbereiten. Kali ist dein Alltag, aber zsh und bash müssen beide funktionieren (Kali nutzt standardmässig zsh). Offline ist nicht verhandelbar: Prüfungsumgebungen, isolierte Lab-VMs und interne Kundennetze haben oft kein Internet. Trennst du Collector und Ansicht früh, bekommst du Headless später fast gratis.

> **Aus der Praxis:** Bei internen Pentests sitzt du oft auf einem Kundengerät oder einer Pentest-Box im Kundennetz, ohne Internet und ohne GUI. Wer dann erst Pakete nachladen will, steht. Plane ein Offline-Installationspaket von Anfang an ein.

### 9.3 Datenspeicherung

*Wie werden die Daten gespeichert?*

- **A) SQLite als einzige Datenbank**: Eine Datei pro Projekt, Transaktionen, Volltextsuche (FTS5), kein Server. Der Graph liegt in Knoten- und Kanten-Tabellen, Abfragen laufen per rekursivem SQL.
- **B) Neo4j wie bei BloodHound**: Mächtige Graph-Abfragen mit Cypher. Aber ein Java-Server mit hohem Ressourcenbedarf in der VM, dazu aufwendiger Betrieb und Backup pro Projekt.
- **C) Dateien (JSON/Markdown) mit Git versioniert**: Lesbar, diffbar, Obsidian-tauglich. Aber schwache Abfragen, Konflikte beim parallelen Schreiben, und Secrets bleiben für immer in der Git-History.
- **D) Hybrid: SQLite als Wahrheit, Markdown-Export nach Obsidian**: Rohereignisse und Fakten mit Provenienz liegen in SQLite, Ariadne erzeugt daraus Notizen pro Host für deinen Vault. Das Beste aus beiden Welten.

**Empfehlung:** D, mit drei Schichten ab Tag 1: (1) Rohereignisse unveränderlich, (2) Fakten als neu berechenbare Behauptungen mit Quelle, (3) Nutzerentscheidungen (bestätigen, Kontext, Status, Notizen) als eigene Events, die nach jedem Reparse erneut angewendet werden. Sonst löscht jeder Parser-Fix deine Arbeit. SQLite trägt Tausende Hosts, ist eine Datei pro Projekt und braucht keinen Server. Graph-Analysen bei Bedarf im Speicher (NetworkX), kein eigenes Neo4j.

> **Aus der Praxis:** Speichere Rohereignisse unveränderlich (append-only) und Fakten getrennt davon. Wird ein Parser besser, spielst du die alten Logs neu ein und bekommst sauberere Fakten, ohne das Engagement zu wiederholen. Das rettet dich öfter als jede Datenbankwahl.

### 9.4 Plugin-System für Parser

*Plugin-System für Parser?*

- **A) Kein Plugin-System, Parser fest im Kern**: Am schnellsten gestartet. Nachrüsten ist später aufwendig, und jeder neue Parser erfordert ein Release.
- **B) Einfache Parser-Schnittstelle plus Ordner-Registry**: Ein Parser ist eine Klasse mit can_parse() und parse(). Eingebaute und eigene Parser im Config-Ordner nutzen dieselbe Schnittstelle.
- **C) Deklarative Parser als YAML mit Regex**: Einfache Tools lassen sich ohne Code ergänzen. Gut für einzeilige Ausgaben, stösst bei mehrzeiligen oder verschachtelten Ausgaben schnell an Grenzen.
- **D) Vollständiges Plugin-Ökosystem mit Versionen und Marketplace**: Professionell, aber Monate Aufwand. Fremder Plugin-Code läuft mit deinen Rechten und sieht alle Kundendaten.

**Empfehlung:** B von Tag 1, C später. Wenn alle eingebauten Parser dieselbe Schnittstelle nutzen, ist das Plugin-System gratis. Pflicht pro Parser: Beispiel-Output plus erwartete Fakten als Test. Setze bevorzugt auf maschinenlesbare Formate (nmap -oX, ffuf -of json) und nutze Terminal-Text nur als Fallback.

> **Aus der Praxis:** Tools ändern ihre Ausgabe ständig: CrackMapExec wurde zu NetExec, Farben und Spalten wechseln zwischen Versionen. Ohne Golden-Tests mit echten Beispiel-Outputs brechen Parser still, und du merkst es erst, wenn im Report ein Host fehlt.

### 9.5 Installation und Verteilung

*Wie wird es installiert?*

- **A) pipx-Paket aus PyPI oder Git**: Standardweg für Python-CLIs auf Kali, mit isolierter Umgebung und einfachen Updates. Braucht beim Installieren Internet oder lokale Wheels.
- **B) Einzelnes Binary oder zipapp**: Mit Go nativ, mit Python über PyInstaller oder shiv. Ideal für Offline-VMs: Datei kopieren, fertig.
- **C) Docker-Container**: Saubere Isolation, aber Shell-Hooks, PTY-Logging und Ordner-Watcher müssen auf dem Host laufen. Für den Collector ungeeignet.
- **D) Debian-Paket (.deb), langfristig im Kali-Repo**: Für Kali-Nutzer am bequemsten, aber Paketierung und Abhängigkeiten zu pflegen ist Arbeit. Erst mit einer stabilen Version sinnvoll.

**Empfehlung:** A im MVP, ergänzt um ein Offline-Bundle (Wheels oder zipapp) für Prüfungs- und Kunden-VMs. Dazu ein Befehl wie ariadne init zsh, der den Shell-Hook einrichtet. Docker nur für optionale Zusatzdienste wie ein lokales LLM. Ein .deb erst, wenn das Tool stabil ist.

> **Aus der Praxis:** Kali blockiert ein systemweites pip install wegen PEP 668 (externally-managed-environment), deshalb pipx. Der Paketname ariadne ist auf PyPI schon durch eine GraphQL-Bibliothek belegt. Nimm z. B. ariadne-recon, der Befehl kann trotzdem ariadne heissen.

## 10. Umfang und Rahmen

### 10.1 Umfang Version 0.1 [Kernfrage]

*Was muss Version 0.1 können, damit du sie wirklich benutzt?*

- **A) Dein Vorschlag: zsh-Log, nmap, Karte**: Fokussiert und machbar. Risiko: Eine Karte ohne Zeitachse zeigt nur den Zustand, nicht den Weg dorthin.
- **B) Doku zuerst: Log, Timeline, Obsidian-Export**: Sofort nützlich für Writeups und Schulreports, passt zu deinem Obsidian-Workflow. Weniger spektakulär, aber täglicher Nutzen.
- **C) Nur Datenkern ohne Oberfläche**: Erfassen, Parser, SQLite, Abfragen per CLI. Saubere Basis, aber du nutzt es kaum, also fehlt dir das Feedback.
- **D) Breit: PTY, OCR, viele Parser, LLM**: Beeindruckend auf dem Papier. In der Praxis lauter halbfertige Teile, nichts davon zuverlässig, und das Projekt schläft ein.

**Empfehlung:** Weder A noch B allein, sondern ein schmaler Schnitt durch alles (siehe Roadmap): Projekt-CLI mit Scope und Profil, zsh-Hook plus tmux pipe-pane (Befehl und Output), Kontext per tmux-Taste, SQLite mit drei Schichten, nmap-XML-Parser plus Regex-Netz mit Inbox, `cred add` und `mark`, CLI-Ansichten, Markdown-Export mit Angriffspfad. Kein LLM, kein OCR, keine Web-UI. Erfolgskriterium: eine HTB-Box mit Shell auf dem Ziel komplett damit gelöst und lückenlos dokumentiert.

> **Aus der Praxis:** Die zsh-Hooks preexec und precmd sehen den Befehl, nicht den Output. Den Output bekommst du nur über PTY-Logging (script, tmux pipe-pane). Entscheide früh, ob v0.1 Outputs braucht. Für nmap reicht -oX.

### 10.2 Zeitrahmen und Kapazität

*Zeitrahmen und Stunden pro Woche?*

- **A) 3 bis 5 Stunden pro Woche**: Realistisch neben Vollzeitjob und HF. v0.1 in etwa drei Monaten, wenn der Umfang strikt bleibt.
- **B) 8 bis 10 Stunden pro Woche**: Nur machbar, wenn es als Schulprojekt zählt oder Arbeitszeit dafür da ist. v0.1 in sechs bis acht Wochen.
- **C) Kurzer Intensiv-Sprint in den Ferien**: Ein bis zwei Wochen fast Vollzeit für den Kern, danach Pflege nebenher. Gut für Architekturarbeit, die ungestörte Konzentration braucht.
- **D) Ohne festen Rahmen, wenn Zeit bleibt**: Kein Druck, aber meist Stillstand nach dem ersten Prüfungsstress. Häufigster Grund, warum Nebenprojekte sterben.

**Empfehlung:** A als Basis: fixer Wochenslot im Kalender, Iterationen von zwei Wochen. C zusätzlich, falls Ferien drinliegen, für Datenmodell und Hook. v0.1 ehrlich auf 50 bis 70 Stunden schätzen, bei 4 Stunden pro Woche also rund vier Monate. In den Wochen 1 bis 3 nur Projekt, Hook und Rohlog bauen, damit du ab Woche 3 selbst damit arbeiten kannst. D vermeiden.

> **Aus der Praxis:** Regel für den Eigengebrauch: Ab Woche 3 jede HTB-Box und jede Schulübung nur noch mit Ariadne, auch wenn es hakt. Die Liste der Ärgernisse ist dein Backlog. Was du nie vermisst, brauchst du nicht.

### 10.3 Open Source und Lizenz

*Open Source oder privat?*

- **A) Privat, kein öffentliches Repo**: Volle Freiheit, kein Support-Druck. Dafür kein Portfolio-Effekt und kein Feedback aus der Community zu Parsern.
- **B) Open Source, permissiv (MIT, Apache-2.0)**: Maximale Verbreitung, firmenfreundlich. Andere dürfen geschlossene kommerzielle Versionen bauen. Apache-2.0 enthält zusätzlich eine Patentklausel.
- **C) Open Source, Copyleft (GPL-3.0, AGPL-3.0)**: Abgeleitete Werke bleiben offen. AGPL greift auch beim Betrieb als Webdienst. Manche Firmen meiden AGPL-Software.
- **D) Erst privat, ab v0.1 öffentlich**: Zeit zum Aufräumen, Repo frei von Lab- und Testdaten. Lizenz bewusst später wählen, aber vor dem ersten fremden Beitrag.

**Empfehlung:** D, danach Apache-2.0 oder AGPL-3.0. Apache-2.0, wenn Verbreitung und Bewerbungsportfolio zählen. AGPL-3.0, wenn niemand eine geschlossene SaaS daraus machen soll. Leg die Lizenz vor dem ersten fremden Pull Request fest, sonst brauchst du später die Zustimmung aller Beitragenden. Echte Outputs nie ins Repo, Testdaten nur aus Labs.

> **Aus der Praxis:** Entwickelst du in der Arbeitszeit oder für Kunden deines Arbeitgebers, gehören die Rechte nach Art. 17 URG unter Umständen dem Arbeitgeber. Klär das schriftlich, bevor du veröffentlichst.

### 10.4 Team und Projektmethode

*Allein oder mit anderen? Schulprojekt?*

- **A) Allein, Freizeitprojekt, leichtes Kanban**: Schnelle Entscheidungen, keine Abgabezwänge. Risiko: Niemand hält dich auf Kurs, und der Umfang wächst unbemerkt.
- **B) Schulprojekt nach HERMES 2022**: Verbindliche Meilensteine, Doku zählt mit. Mehr Aufwand (Projektauftrag, Konzept, Testprotokoll), dafür Struktur und Feedback. HERMES erlaubt auch agile Entwicklung.
- **C) Gruppenarbeit im Studium (2 bis 4)**: Mehr Kapazität, aber Abstimmungsaufwand. Die Kernarchitektur leidet oft unter Kompromissen und ungleicher Motivation.
- **D) Mit Arbeitgeber als internes Tool**: Zugang zu echten Anforderungen, eventuell Arbeitszeit. Aber Rechte liegen womöglich beim Arbeitgeber, und Kundendaten werden ein Thema.

**Empfehlung:** A als Standard. B lohnt sich, falls eine Projekt- oder Diplomarbeit ansteht: dann HERMES mit agiler Entwicklung, und die Arbeit zählt doppelt. Den Kern allein bauen, Mitstreiter nur für klar abgegrenzte Parser holen. D erst, wenn Rechte und Datenhaltung schriftlich geklärt sind.

> **Aus der Praxis:** Parser sind der ideale Einstieg für Mitentwickler: klare Schnittstelle (Datei rein, Fakten mit Provenienz raus), testbar mit Beispiel-Outputs. So bindest du Mitstudierende ein, ohne den Kern aus der Hand zu geben.

## 11. Was ein Senior zusätzlich fragen würde

Diese Fragen fehlten im ersten Katalog. In echten Aufträgen entscheiden sie oft darüber, ob ein Pentest sauber abgeschlossen werden kann.

### 11.1 Artefakte auf Zielsystemen für das Cleanup erfassen?

- **A) Nein, Cleanup aus dem Gedächtnis**: Kein Aufwand. Nach drei Tagen weiss niemand mehr, welche Dateien, Accounts und Dienste auf welchem Host liegen. Reste bleiben beim Kunden.
- **B) Manuell per Befehl erfassen**: `ariadne artifact add /tmp/linpeas.sh` im aktuellen Host-Kontext. Zuverlässig, wenn man es tut, unter Druck aber oft vergessen.
- **C) Automatische Kandidaten aus Befehlen**: Erkennt upload in evil-winrm und Meterpreter, wget/curl -o auf dem Ziel, useradd, net user /add, schtasks /create, authorized_keys. Landet in der Inbox.
- **D) Cleanup-Liste pro Host mit Status**: Pro Artefakt: angelegt, entfernt, verifiziert oder an Kunde übergeben. Export als Report-Anhang «Hinterlassene Artefakte».
- **E) Auch Änderungen an AD-Objekten erfassen**: Neue Computerkonten (impacket-addcomputer), RBCD, Shadow Credentials, Gruppenmitgliedschaften, ausgestellte Zertifikate. Fallen bei reinem Datei-Cleanup durch.

**Empfehlung:** B im MVP, C + D direkt danach, E mit den AD-Parsern. Jedes Artefakt hängt am Host-Kontext und am erzeugenden Befehl, so entfernst du es gezielt. Was du nicht entfernen kannst oder darfst, gehört mit Pfad und Zeitpunkt in den Report. Im Lab übst du damit die Disziplin, die im Kundenauftrag Pflicht ist.

> **Aus der Praxis:** impacket-psexec lädt ein Binary auf eine beschreibbare Freigabe (meist ADMIN$), legt einen Dienst an und räumt nur bei sauberem Beenden auf. Per ADCS ausgestellte Zertifikate bleiben bis zum Ablauf gültig: nicht löschbar, nur durch den Kunden widerrufbar.

### 11.2 Aktivitätsprotokoll mit Quell-IP für Kunde und SOC?

- **A) Rohlog reicht, bei Bedarf durchsuchen**: Alle Daten sind da, aber die Antwort an das SOC dauert Stunden. Quell-IP und Ziel stehen nicht strukturiert drin.
- **B) Strukturierter Export pro Aktion**: UTC-Zeit, Operator, Quell-IP, Ziel, Tool, Befehl, Ergebnis als CSV oder Markdown. Felder angelehnt an das Ghostwriter-Oplog.
- **C) Quell-IP automatisch pro Befehl ermitteln**: Interface und Absender-IP über `ip route get <ziel>`, dazu VPN, Jumpbox oder Pivot-Host. Kali hat oft mehrere IPs gleichzeitig.
- **D) Tageszusammenfassung für den Kunden**: Pro Tag getestete Systeme, Zeitfenster und auffällige Aktionen wie Scans oder Sprays. Viele Kunden verlangen einen täglichen Status.
- **E) Live-Freigabe an das Blue Team**: Das SOC sieht Aktionen in Echtzeit, ideal für Purple Teaming. Braucht Server und Datenfreigabe, widerspricht local-first.

**Empfehlung:** B + C, D als Vorlage, E nicht. Die Quell-IP ist der Schlüssel zum Abgleich mit SOC-Alarmen, und genau sie fehlt in fast jedem selbstgebauten Log. Ariadne ermittelt sie automatisch, inklusive der Tunnel aus 5.3. Den Export nach Zeitraum und Host filterbar machen, dann beantwortest du Rückfragen in Minuten.

> **Aus der Praxis:** Über einen Pivot sieht das SOC die IP des Pivot-Hosts, nicht deine. Gib dem Kunden vor Testbeginn deine Quell-IPs bekannt und protokolliere jeden Wechsel (neues VPN, anderer Jumphost). Sonst wird dein Scan als echter Angriff eskaliert.

### 11.3 Wie bleiben Beweise unverfälscht und zeitlich korrekt?

- **A) Keine besonderen Massnahmen**: Rohdaten liegen als normale Dateien. Im Streitfall kannst du nicht belegen, dass nichts nachträglich verändert wurde.
- **B) Append-only plus SHA-256 pro Rohdatei**: Jede Rohdatei und jeder Screenshot wird beim Einlesen gehasht. Einfach, deckt nachträgliche Änderungen an einzelnen Dateien auf.
- **C) Hash-Kette über alle Events**: Jedes Event enthält den Hash seines Vorgängers. Gelöschte oder veränderte Einträge werden erkennbar, ähnlich einem Audit-Log.
- **D) Externer Zeitstempel oder Signatur**: Tagesabschluss per RFC-3161-Zeitstempeldienst oder Signatur mit eigenem Schlüssel. Stärkster Nachweis, der Zeitstempeldienst braucht aber Internet.
- **E) Zeitbasis prüfen und protokollieren**: Beim Start NTP-Status, Zeitzone und Abweichung erfassen (`timedatectl`). Zeitsprünge durch ntpdate oder Snapshot-Restore werden markiert.

**Empfehlung:** B + C + E im Design, D optional zum Projektabschluss. Die Hash-Kette kostet wenig, wenn Events ohnehin append-only sind. Ihren letzten Hash aber ausserhalb ablegen (Report, Mail an Kunden), sonst lässt sich die Kette unbemerkt neu berechnen. Noch wichtiger ist die richtige Uhrzeit: Ein Log mit falscher Zeit ist für den SOC-Abgleich wertlos.

> **Aus der Praxis:** In HTB-AD-Boxen stellen viele wegen «KRB_AP_ERR_SKEW» die Kali-Uhr per ntpdate auf den DC. Damit verschieben sich alle Zeitstempel. Besser faketime pro Befehl nutzen, und Ariadne erkennt und protokolliert jeden Zeitsprung.

### 11.4 Wie wird aus Fakten ein Finding?

- **A) Gar nicht, Findings erst im Report**: Ariadne liefert nur Fakten und Belege, bewertet wird in SysReptor oder Word. Die Verknüpfung zu den Belegen geht dabei verloren.
- **B) Markierung an einem einzelnen Fakt**: Schnell, aber ein Finding betrifft oft viele Hosts. «SMB-Signing nicht erzwungen» auf 40 Hosts wären dann 40 Findings.
- **C) Eigenes Finding-Objekt mit Verknüpfungen**: Titel, Beschreibung, betroffene Assets, Belege (Fakten, Befehle, Screenshots), Bewertung, Empfehlung, Status. Ein Finding, viele Hosts.
- **D) Bewertung nach CVSS oder Risikomatrix**: CVSS 3.1 oder 4.0 für Vergleichbarkeit, dazu Kontext aus Eintrittswahrscheinlichkeit und Auswirkung. Schule und HTB brauchen meist nur einen Schweregrad.
- **E) Vorlagen-Bibliothek und Retest-Status**: Wiederkehrende Findings mit Text und Empfehlung als Vorlage. Retest-Status (offen, behoben, teilweise) für den Nachtest Monate später.

**Empfehlung:** C als Datenmodell, D mit einfachem Schweregrad starten, E später. Die Trennung ist zentral: Fakten sammelt Ariadne automatisch, ein Finding entsteht nur durch dein Urteil. Angriffspfade sind oft eigene Findings, weil erst die Kette aus mehreren mittleren Schwächen kritisch wird. Der Export nach SysReptor läuft dann pro Finding samt Belegen.

> **Aus der Praxis:** «Port 445 offen» ist ein Fakt, «SMB-Signing nicht erzwungen, NTLM-Relay möglich» ein Finding. Scanner-Treffer ungeprüft als Finding zu übernehmen ist die Hauptquelle für False Positives, die dem Kunden das Vertrauen in den ganzen Report nehmen.

### 11.5 Was tun bei Notfall, Stopp oder kritischem Fund?

- **A) Nicht Aufgabe des Tools**: Notfälle löst man per Telefon. Aber genau dann fehlen Kontaktdaten, Zeitpunkte und die Liste der eigenen Aktionen.
- **B) Notfallkontakte und Stopp-Kriterien im Projekt**: Ansprechpartner, Erreichbarkeit, Eskalationsweg und vereinbarte Abbruchgründe aus den RoE. `ariadne contacts` zeigt sie sofort an.
- **C) Incident-Export für Host und Zeitraum**: Alle eigenen Aktionen gegen Host X seit Zeitpunkt Y: Befehl, Quell-IP, Ergebnis, Artefakte. Beantwortet «Wart ihr das?» in Minuten.
- **D) Stopp-Modus mit Zugangsinventar**: `ariadne stop` sperrt per Scope-Hook alle Ziele, das Logging läuft weiter. Listet offene Shells, Listener, Tunnel und Artefakte zum Abbauen.
- **E) Fremde Kompromittierung als eigener Status**: Unbekannte Webshells, fremde Accounts, Spuren echter Angreifer. Markiert als «nicht von uns», sofort zu melden, nicht weiter anfassen.

**Empfehlung:** B + C früh, D zusammen mit dem Scope-Hook aus 7.4, E als fester Status. C ist das wichtigste Werkzeug: Fällt ein Server aus, will der Kunde sofort wissen, was du dort getan hast. Mit Provenienz und Aktivitätsprotokoll (11.2) ist der Export fast gratis. Im Profil «customer» sollte ein Projekt ohne Notfallkontakte gar nicht starten.

> **Aus der Praxis:** Findest du Spuren eines echten Angreifers: Testen an diesem System stoppen, nichts löschen oder ändern, sofort den Kunden informieren. Deine Logs werden dann Teil der Forensik und müssen deine Aktionen sauber von seinen trennen.

### 11.6 Lockout-Grenzen und erlaubte Techniken überwachen?

- **A) Nein, der Pentester passt selbst auf**: Kein Aufwand. Im Team oder nach zehn Stunden verliert man die Zählung, und ein Spray sperrt produktive Konten.
- **B) Passwort-Policy pro Domain erfassen**: Schwelle, Beobachtungsfenster und Sperrdauer aus der Ausgabe von nxc --pass-pol parsen oder manuell eintragen. Grundlage für jede Warnung.
- **C) Fehlversuche pro Konto zählen**: Abgeleitet aus nxc, hydra, kerbrute und Co.: Userliste mal Passwortliste, Zeitpunkt, Ziel. Warnung, bevor die Schwelle im Fenster erreicht ist.
- **D) RoE-Regeln als Daten**: Verbotene Techniken (DoS, Phishing, Exploits auf Produktion) und Höchstraten pro Projekt. Ariadne warnt, wenn ein Befehl dagegen verstösst.
- **E) Blockieren bei Überschreitung**: Wie der Scope-Block in 7.4 per zsh-Widget. Sicher, aber nur so gut wie die Erkennung der Tools.

**Empfehlung:** B + C für AD-Labs und Kundenaufträge, D als Warnung, E pro Projekt zuschaltbar. Die Zählung bleibt eine Schätzung, weil Ariadne nur sieht, was in deinen Terminals läuft. Deshalb mit Sicherheitsabstand warnen, etwa bei Schwelle minus zwei. Im Team zählen die Versuche aller Operatoren zusammen, das Datenmodell aus 1.3 trägt das bereits.

> **Aus der Praxis:** nxc testet ohne --no-bruteforce jede Kombination aus User- und Passwortliste. --pass-pol zeigt nur die Default Domain Policy, Fine-Grained Password Policies können strengere Schwellen haben. Auch kerbrute passwordspray erhöht den Fehlversuchszähler.

### 11.7 Hypothesen, Versuche und Testabdeckung festhalten?

- **A) Nur Freitext in Notizen**: Flexibel, aber nicht auswertbar. Nach der Pause weisst du nicht mehr, welche Idee widerlegt und welche nur angefangen war.
- **B) Hypothese als eigenes Objekt**: Vermutung («SQLi in /search»), Bezug zu Host oder Service, Status offen, bestätigt oder widerlegt, verknüpfte Befehle als Beleg.
- **C) Timebox pro Hypothese**: Zeitbudget, z. B. 45 Minuten, mit dezenter Erinnerung. Gegen das klassische Rabbit Hole, besonders unter Prüfungsdruck.
- **D) Abdeckungsbericht für den Report**: Was wurde geprüft, was nicht und warum: Zeit, nicht erreichbar, ausgeschlossen. Grundlage für das Kapitel Einschränkungen.

**Empfehlung:** B + D, C als Option. Ergänzt 5.2 und 6.5: Dort steht der Zustand eines Objekts, hier die Idee dahinter. Widerlegte Hypothesen sind Negativbefunde, die der Kunde sehen will («getestet, nicht verwundbar»). Zusammen mit den Checklisten aus 7.1 ergibt sich der Abdeckungsbericht fast automatisch.

> **Aus der Praxis:** Das Kapitel Einschränkungen schützt dich: Findet ein echter Angreifer später etwas, das du aus Zeitgründen nicht testen konntest, ist das dokumentiert und dem Kunden mitgeteilt. Ohne Nachweis heisst es: «Das habt ihr übersehen.»

### 11.8 Wie fliesst Wissen sicher in spätere Projekte?

- **A) Gar nicht, jedes Projekt startet leer**: Maximale Trennung. Du löst dieselben Probleme immer wieder neu und lernst weniger aus jeder Box.
- **B) Befehlsbibliothek aus erfolgreichen Befehlen**: Ariadne ersetzt IPs, Hosts, User und Passwörter durch Platzhalter ({RHOST}, {USER}) und schlägt den Befehl zur Aufnahme vor.
- **C) Finding-Vorlagen und Regeln zurückführen**: Neue Finding-Texte und Checklisten-Regeln (7.2) aus dem Projekt in die globale Basis übernehmen, ohne Kundendetails.
- **D) Projektübergreifende Suche in Rohdaten**: «Wo hatte ich das schon mal?» über alle Projekte. Im Lab praktisch, bei Kundenprojekten ein Bruch der Trennung aus 8.1.
- **E) Retrospektive pro Projekt nach Obsidian**: Kurzes Lessons Learned: was funktionierte, was Zeit kostete, was in die Methodik soll. Ideal als Abschluss eines Writeups.

**Empfehlung:** B + C + E, D nur für Lab- und HTB-Projekte. Konkretisiert 8.1 D: Wissen fliesst nur über einen bewussten Schritt mit Vorschau in die globale Basis, nie automatisch. Die Platzhalter-Ersetzung nutzt die bekannten Fakten des Projekts, den Rest prüfst du. So wächst über Labs und HTB deine eigene Methodik.

> **Aus der Praxis:** Klassisches Leck: Die Befehlsbibliothek enthält noch -p 'Firma2024!' oder die Kundendomain. Deshalb vor der Übernahme gegen alle Fakten des Projekts abgleichen. Writeups aktiver HTB-Maschinen nicht veröffentlichen, die HTB-Regeln erlauben das nur für retired Boxen.

## Was nur du beantworten kannst

Fast alles oben lässt sich aus Erfahrung entscheiden. Diese Punkte hängen aber an dir:

1. **Nutzt du tmux, oder bist du bereit, es dir anzugewöhnen?** Davon hängt die ganze Erfassung ab (Grundsatzentscheid 1).
2. **Welche Sprache kannst du wirklich gut?** Die Empfehlung ist Python. Go ist nur sinnvoll, wenn du es schon sicher beherrschst (9.1).
3. **Wie viele Stunden pro Woche hast du realistisch?** (10.2)
4. **Soll es ein Schul- oder Diplomprojekt werden, oder spielt dein Arbeitgeber eine Rolle?** Das beeinflusst Methodik, Rechte und Lizenz (10.3, 10.4).
5. **Stehen echte Kundenaufträge in Sicht, oder bleibt es vorerst bei Labs, HTB und Schule?** Das bestimmt, wie früh v0.3 kommen muss (1.1).
6. **Strebst du eine Zertifizierung an, und wenn ja, welche?** Das bestimmt den Prüfungsmodus (8.4).

## Quellen für geprüfte Fakten

- OffSec OSCP Exam Guide (Verbot von AI-Chatbots/LLMs und automatischer Exploitation): https://help.offsec.com/hc/en-us/articles/360040165632
- Faraday, Befehls-Provenienz im Datenmodell: https://github.com/infobyte/faraday und https://github.com/infobyte/faraday-cli
- BloodHound CE v8 mit OpenGraph: https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph/
- PentestGPT v1.0 als autonomer Agent: https://github.com/GreyDGL/PentestGPT
- bloodhound-ce-python für BloodHound CE: https://www.kali.org/tools/bloodhound-ce-python/

