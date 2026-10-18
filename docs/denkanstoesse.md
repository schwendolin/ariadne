# Denkanstösse aus Regeln (v0.1)

> Stand 2026-10-18, Bau v0.1-Oberfläche, Teil «regeln». Grundlage: Architektur 6.1 und 6.3, E10, E13, E64,
> E68, `docs/web-api.md` 18.6, Design v0.1 (Spalte «Als Nächstes», D1 bis D3). Code: `src/ariadne/rules/`,
> Route `src/ariadne/web/api/suggestions.py`, Tests `tests/rules/`, erwartete Ausgaben `tests/golden/rules/`.

## 1 Grundsätze

* Regeln laufen über der Projektion in `derived.db`, nur lesend, im Thread der Auswertung, jede Abfrage mit
  eigener Grenze. Sie erzeugen nur Vorschläge, nie Fakten.
* **Ariadne führt nie etwas aus (E10).** Es gibt keinen Ausführen-Weg. Vorlagen sind Text zum Kopieren
  («Kopieren · Mac»); Werkzeugwissen steht nur in der Befehlsbibliothek (`templates.py`) und in den
  Erkennern (`commands.py`), nie in den Regeln.
* Zieldaten sind feindlich (E13): Jeder Wert aus Zieldaten wird sichtbar gemacht (`<ESC>`, `<U+202E>`, wie
  `term_safe`, ohne Kürzung), bekannte Secret-Werte stehen als `••••••••`, und Platzhalter in Befehlen
  gehen nur durch den Kontext-Encoder ihres Typs (E68).
* Ruhe zuerst: Eine Regel feuert nur, wenn die Prüfung noch nicht gemacht ist. Was ein aufgenommener Befehl
  schon geprüft hat, verschwindet ohne Klick («Erledigt-Erkennung»).

## 2 Schnittstelle

`ariadne.rules.api` (Signaturen fest, Vertrag 4.2):

| Funktion | Zweck |
|---|---|
| `suggestions(conn, *, profile, state="open", limit=50) -> (list, truncated)` | `Suggestion`-Objekte nach web-api.md 18.6, sortiert nach Priorität der Regel, dann Host (Adressen numerisch), dann Port |
| `open_count(conn, *, profile) -> int` | Zahl offener Denkanstösse (SSE-Ereignis `suggestion`) |
| `check_decision(conn, kind, header, *, profile)` | Prüft `d.suggestion.done` und `d.suggestion.dismiss` vor dem Schreiben; wirft `RuleRefError("basis_required" \| "conflict")` |
| `STUB = False` | die Engine läuft; `/next` meldet `suggestions_available: true` |

Route `GET /api/v1/p/{pid}/suggestions?state=open|done|dismissed|all` (höchstens 200, `{suggestions,
truncated}`, 422 bei anderem `state`). `/next` liefert die ersten 50 offenen.

## 3 Schlüssel, Anlass, Zustand

* **`suggestion_key`** = `sg:` + 24 Hex aus SHA-256 über Regel-ID und die sortierten natürlichen Schlüssel
  (Dienst-Kennung `svc:ip:default/10.10.10.3|tcp/21`, Host-Kennung, bei SMB auf Hostebene zusätzlich
  `class:smb`). Er übersteht Reparse, weil die Kennungen natürliche Schlüssel sind.
* **Nebenschlüssel (Merge):** Derselbe Hash über jede andere Kennung des Subjekts (IP, Name, MAC …). Ein
  Entscheid auf einen Nebenschlüssel gilt; so bleibt ein verworfener Denkanstoss nach einem Merge verworfen,
  auch wenn die Entität jetzt eine andere stärkste Kennung trägt.
* **`basis`** = 16 Hex aus den auslösenden Werten (je Regel unten). Ein neuer Beleg für denselben Wert
  (dieselbe Version noch einmal gescannt) ändert `basis` nicht, ein neuer Wert schon.
* **Zustand** aus den aktiven Entscheiden in der Tabelle `decision` (Kopie des Journals, darum übersteht er
  Reparse). Widerrufene Entscheide (`d.revoke`, auch verschachtelt) zählen nicht.
  * `d.suggestion.dismiss` verwirft für immer (auch nach neuem Anlass, Reparse, Merge).
  * `d.suggestion.done` gilt, solange `basis` gleich ist; sonst ist der Denkanstoss wieder offen.
* **`check_decision`:** `done` ohne `basis` ergibt 422 `basis_required`; unbekannter Schlüssel (auch über
  Nebenschlüssel) 409 `conflict`; `done` mit veralteter `basis` oder auf einen schon erledigten oder
  verworfenen Denkanstoss 409 (die Oberfläche zeigt «In einem anderen Tab entschieden»); `dismiss` auf einen
  schon verworfenen 409, auf einen erledigten erlaubt.

## 4 Was zählt (für alle Regeln)

* Werte nur im Zustand `auto` oder `confirmed`, nicht abgelöst, keine Secrets; Vorschläge, verworfene Werte
  und stille Heuristiken lösen nichts aus. Ein einwertiges Prädikat mit zwei gültigen Werten (offener
  Widerspruch) gilt als unbekannt.
* Hosts im Scope, nicht im Nebel, nicht als Sackgasse, erledigt oder ausserhalb markiert (`d.status.work`);
  eigene Adressen von Kali sind nie Hosts. Dienste im Scope mit Zustand `open`, Arbeitsstand wie bei Hosts.
* **Erledigt-Erkennung** in drei Stufen, die erste passende genügt:
  1. die Skriptausgabe steht schon als Wert da (`service.script` bzw. `host.script`, etwa `ftp-anon`);
  2. ein **beobachtender** nmap-Lauf (einer, der den Dienst bzw. Host gesehen hat) hat das Skript
     ausgeführt, auch ohne Ausgabe: `-sC`, `-A`, `--script` mit Namen, Kategorie (`default`, `auth`, `vuln` …)
     oder Muster (`smb-*`); `--script` mit `not` zählt vorsichtshalber nicht. Für Dateien (nmap-XML) gelten
     die Optionen des Befehls, der sie geschrieben hat;
  3. ein aufgenommener Befehl mit einem passenden Werkzeug nennt den Host (IP, Name, Netz `a.b.c.0/24`,
     Bereich `a.b.c.10-20`) und, wo es um einen Dienst geht, den Port (`-p 2121`, `-P 3306`, `-s 8180` bei
     hydra, `host:8180`, Zahl direkt hinter dem Ziel) oder ohne Port einen Standardport des Werkzeugs.
* Befehle aus misstrauten Einheiten (`d.unit.distrust`) zählen nicht. Befehle kommen im echten `derived.db`
  aus `unit` (jeder Befehl, auch ohne Parser-Treffer), in Projektionen ohne Einheiten-Tabellen aus `obs_unit`.

## 5 Regelkatalog

Prüfziele (Architektur 6.1) sind stabil; neu in v0.1: `PZ-SMB-SHARES`, `PZ-NFS-EXPORTS`, `PZ-PORTS-TCP`,
`PZ-PORTS-UDP`, `PZ-CRED-DEFAULT`, `PZ-SMTP-USER`, `PZ-DB-ZUGRIFF`.

| Regel | Prüfziel | Art | Prio | Subjekt |
|---|---|---|---|---|
| R-ANON-ZUGRIFF | PZ-AUTH-ANON | goal | 10 | FTP-Dienst; SMB pro Host |
| R-VERSION-RECHERCHE | PZ-VULN-RECHERCHE | goal | 20 | Dienst (gleiche Suche auf einem Host einmal) |
| R-SMB-SHARES | PZ-SMB-SHARES | goal | 30 | Host |
| R-NFS-EXPORTS | PZ-NFS-EXPORTS | goal | 31 | Host |
| R-WEB-INHALT | PZ-WEB-INHALT | goal | 40 | Webdienst |
| R-STANDARD-CREDS | PZ-CRED-DEFAULT | question | 50 | Dienst (Tomcat, VNC, Telnet, SNMP) |
| R-DB-ZUGRIFF | PZ-DB-ZUGRIFF | question | 51 | Datenbankdienst |
| R-SMTP-USER | PZ-SMTP-USER | question | 60 | SMTP-Dienst |
| R-FULL-PORTSCAN | PZ-PORTS-TCP | goal | 70 | Host |
| R-UDP-SCAN | PZ-PORTS-UDP | goal | 80 | Host |

### R-ANON-ZUGRIFF «Unauthentisierten Zugriff auf 192.168.56.101:21 prüfen»

* **Auslöser FTP:** offener Dienst `ftp`, `ftps`, `ssl/ftp` (ohne Namen: Produkt mit «ftpd»). Begründung
  «FTP-Dienst ohne geprüfte anonyme Anmeldung». Anlass: Klasse und Produkt.
* **Auslöser SMB (pro Host, Schlüssel mit `class:smb`):** `netbios-ssn`, `microsoft-ds`, `smb`, `cifs`
  (ohne Namen: 139/445). Begründung «SMB-Dienst ohne geprüfte Null-Session».
* **Erledigt FTP:** Skript `ftp-anon` (Ausgabe oder beobachtender Lauf mit `-sC`; nmap gibt bei verbotenem
  Login nichts aus, darum zählt der Lauf), `ftp`/`lftp`/`ncftp` gegen Host und Port, `curl`/`wget ftp://…`,
  `nxc ftp`. **Erledigt SMB:** `smb-security-mode`, `smb-os-discovery`, `smb-enum-shares`, `smb-enum-users`
  (alle versuchen eine anonyme Sitzung), `smbclient`, `rpcclient`, `smbmap`, `enum4linux(-ng)`, `nxc smb`.
* **NFS** prüft R-NFS-EXPORTS: Bei NFSv3 ist die Liste der Exporte mit den erlaubten Clients die Prüfung auf
  Zugriff ohne Anmeldung; ein zweiter Denkanstoss für denselben Dienst wäre nur Rauschen.
* **Lernstufen:** «Welche Daten gibt dieser Dienst ohne Anmeldung preis?» – «Viele vsftpd-Installationen
  erlauben Gast- oder anonyme Logins.» (Produkt nur, wenn es harmloser Text `[A-Za-z0-9 ._+-]` ist, sonst
  «Viele FTP-Server …»).
* **Vorlagen:** `nmap -p {port} --script ftp-anon {ip}`, `ftp {ip} {port}`; SMB:
  `rpcclient -U '' -N {ip}`, `nxc smb {ip} -u '' -p ''`.

### R-VERSION-RECHERCHE «Version recherchieren: vsftpd 2.3.4 (192.168.56.101:21)»

* **Auslöser:** Produkt und genaue Version (erstes Wort wie `2.3.4`, `4.7p1`; keine Bereiche `3.X - 4.X`,
  `8.3.0 - 8.3.7`). Bei Samba mit Bereich gilt die Version aus `smb-os-discovery` (`Samba 3.0.20-Debian`).
  Gleiche Suche auf demselben Host (139 und 445) ergibt einen Denkanstoss; Subjekt ist bei SMB Port 445.
* **Suchbegriffe:** Produkt mit `/` und Leerzeichen getrennt, ohne allgemeine Wörter (`httpd`, `smbd`,
  `smtpd`, `daemon`, `server`, `engine`, `service`), Version ohne Distributions-Anhang (`5.0.51a-3ubuntu5`
  wird `5.0.51a`). Nicht druckbares ASCII bleibt unverändert, damit der Encoder es sperrt.
* **Erledigt:** `searchsploit` mit dem ersten Wort des Produkts (auch ohne Ziel-Adresse); beobachtender
  nmap-Lauf mit `vulners` oder Kategorie `vuln`.
* **Anlass:** Produkt und Version. **Vorlage:** `searchsploit {produkt} {version}`.
* **Beleg:** der Versionswert (bei Samba die Zeilen von `smb-os-discovery`) und das Produkt.

### R-SMB-SHARES «SMB-Shares auf 192.168.56.101 auflisten»

* **Auslöser:** Host mit SMB-Dienst. Begründung «SMB auf Port 139, 445 ohne Liste der Shares», Anlass: Ports.
* **Erledigt:** `smb-enum-shares`, `smbclient -L`, `smbmap`, `enum4linux(-ng)`, `nxc smb … --shares`.
* **Vorlagen:** `smbclient -N -L //{ip}`, `smbmap -H {ip}`, `nmap -p {port} --script smb-enum-shares {ip}`.

### R-NFS-EXPORTS «NFS-Exporte von 192.168.56.101 auflisten»

* **Auslöser:** `nfs`, `mountd`, `nfs_acl` oder Port 2049. **Erledigt:** `nfs-showmount`, `nfs-ls`,
  `showmount`, `mount … nfs …` gegen den Host, `nxc nfs`.
* **Vorlagen:** `showmount -e {ip}`, `nmap -p 111 --script nfs-showmount {ip}`.

### R-WEB-INHALT «Webinhalt auf 192.168.56.101:8180 untersuchen»

* **Auslöser:** Webdienst (`http*`, `*/http`, ohne `ajp13`, `http-rpc-epmap`). Schema `https` bei Tunnel
  `ssl`, `https`, `ssl/…`.
* **Erledigt:** `http-enum`; `gobuster`, `feroxbuster`, `dirb`, `dirsearch`, `ffuf`, `wfuzz`, `nikto`,
  `whatweb`, `wpscan`, `curl`, `wget`, `httpx`, `katana`, `hakrawler`, `eyewitness`, `aquatone` gegen Host und
  Port (ohne Port: 80 bzw. 443).
* **Vorlagen:** `curl -i {url}`, `whatweb {url}`, `gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt`,
  `nikto -h {url}` mit `{url}` = `http://IP:PORT/` (IPv6 ergibt keine Vorlage, weil Klammern Glob-Zeichen sind).

### R-STANDARD-CREDS «Gibt es auf 192.168.56.101:8180 Standardkonten?» (als Frage)

* **Klassen:** Tomcat (Webdienst mit Produkt Tomcat oder Coyote), VNC, Telnet, SNMP.
* **Erledigt:** `http-default-accounts`, `vnc-brute`, `telnet-brute`, `snmp-brute`; `hydra`, `medusa`,
  `ncrack`, `patator`, `nxc`, dazu `vncviewer`, `telnet`, `snmpwalk`, `onesixtyone` … gegen Host und Port.
* **Vorlagen nur im Profil lab** (Architektur 6.4 Punkt 8: Regeln, die Anmeldeversuche nahelegen, brauchen
  im Kundenprofil eine Bestätigung): `nmap -p {port} --script http-default-accounts {ip}`,
  `vncviewer {ip}::{port}`, `telnet {ip} {port}`, `snmpwalk -v2c -c public {ip}:{port}`.

### R-DB-ZUGRIFF «Lässt die Datenbank auf 192.168.56.101:3306 eine Anmeldung zu?» (als Frage)

* **Klassen:** MySQL, PostgreSQL, MS-SQL, Oracle, MongoDB, Redis (nach Dienstname).
* **Erledigt:** `mysql-empty-password`, `mysql-brute`, `pgsql-brute`, `ms-sql-empty-password`, `redis-info`,
  `mongodb-info`; Clients (`mysql`, `psql`, `mssqlclient`, `redis-cli`, `mongosh` …) und Brute-Force-Werkzeuge
  gegen Host und Port (ohne Port: Standardport der Datenbank).
* **Vorlagen nur im Profil lab:** `mysql -h {ip} -P {port} -u root --skip-ssl`,
  `nmap -p {port} --script mysql-empty-password {ip}`, `psql -h {ip} -p {port} -U postgres`,
  `nmap -p {port} --script ms-sql-empty-password {ip}`, `redis-cli -h {ip} -p {port} info`,
  `nmap -p {port} --script mongodb-info {ip}`; Oracle ohne Vorlage.

### R-SMTP-USER «Lassen sich über SMTP auf 192.168.56.101:25 Benutzer ermitteln?» (als Frage)

* **Auslöser:** `smtp`, `smtps`, `submission`. **Erledigt:** `smtp-enum-users`, `smtp-user-enum`, `ismtp`.
* **Vorlagen:** `smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t {ip} -p {port}`,
  `nmap -p {port} --script smtp-enum-users {ip}`.

### R-FULL-PORTSCAN «Alle TCP-Ports von 192.168.56.101 scannen»

* **Auslöser:** Host mit mindestens einem TCP-Dienst mit Zustand (er wurde gescannt).
* **Erledigt:** beobachtender oder auf Host, Netz oder Bereich zielender Lauf mit allen Ports: nmap `-p-`,
  `-p 1-65535`, `-p0-65535`, `--top-ports 65535`; masscan/naabu mit vollem Bereich; rustscan ohne Port-Angabe.
* **Vorlage:** `nmap -p- -T4 {ip}` (IPv6: `nmap -6 …`). **Beleg:** «Host is up».

### R-UDP-SCAN «UDP-Ports von 192.168.56.101 scannen»

* **Auslöser:** Host mit TCP-Diensten und ohne bekannten UDP-Dienst.
* **Erledigt:** nmap mit `-sU` (auch `-sSU`, `-p U:…`), `unicornscan -mU`, `udpx` gegen Host, Netz oder Bereich.
* **Vorlage:** `sudo nmap -sU --top-ports 100 {ip}` (braucht root; Kali-Benutzer ist kein root).

## 6 Befehlsvorlagen und Kontext-Encoder (E68)

Vorlagen haben nur typisierte Platzhalter. Ein **Lint beim Laden** prüft jede Vorlage (druckbares ASCII,
einzelne Leerzeichen, bekannte Slots, fester Text ohne Shell-Metazeichen ausser `''`, `words` allein als
Wort, Werkzeug am Anfang). Gerendert wird nur, wenn jeder Wert seinen Encoder besteht; danach prüft
`shlex.split` noch einmal, dass der Befehl genau in die erwarteten Wörter zerfällt. Kein Befehl endet mit
einem Zeilenumbruch.

| Typ | erlaubt | Sperrgrund sonst |
|---|---|---|
| `ip` | `ipaddress`, kanonisch, ohne Zonen-ID, Scope-Urteil `in` (eigene Adressen nie) | `invalid`, `out_of_scope` |
| `port` | 1 bis 65535, dezimal ohne führende Null | `invalid` |
| `hostname` | ASCII-Labels `[A-Za-z0-9-]`, kein `-` am Rand, Name im Scope | `invalid`, `out_of_scope` |
| `cidr` | kanonisches Netz, im Scope (ohne Scope-Prüfung: gesperrt) | `invalid`, `out_of_scope` |
| `url` | `http`/`https`, ohne Benutzer, Zeichen `[A-Za-z0-9._:/@=%+-]`, Host im Scope, kein IPv6 | `invalid`, `shell_meta`, `out_of_scope` |
| `word` | `[A-Za-z0-9._+-]{1,64}`, nicht mit `-` beginnend | `invalid` |
| `words` | bis 6 solche Wörter, getrennt durch je ein Leerzeichen | `invalid`, `shell_meta` |
| `path` | absolut `[A-Za-z0-9._/+-]`, ohne `..` | `invalid` |
| `user` | `[A-Za-z0-9._-]{1,64}`, nicht mit `-` beginnend | `invalid` |
| `share` | `[A-Za-z0-9._-]`, `$` nur am Ende (`C$`, `IPC$`) | `invalid`, `shell_meta` |

Reihenfolge der Prüfung: Zeilenumbruch (`newline`) vor Steuerzeichen (`control`) vor Nicht-ASCII
(`non_ascii`) vor Shell-Metazeichen (`shell_meta`: Anführungszeichen, Backtick, `$ ; & | < > ( ) { } [ ] * ? ! \ #`,
dazu `~` und `^` als Glob-Operatoren der zsh, Leerraum an falscher Stelle) vor Typfehler (`invalid`) vor
Scope (`out_of_scope`). Strenger als web-api.md 18.6: `~` in URLs, führender Bindestrich (Option) bei
`word`, `words`, `user`, `share`, `$` mitten in `share`, IPv6 in URLs.

Ist ein Wert gesperrt, gibt es keinen Befehl (`rendered: false`, `command: null`, `parts: []`), nur die
Einzelwerte (Werkzeug zuerst, `target: false`), und der Denkanstoss trägt bei `shell_meta`, `control` oder
`newline` das Kennzeichen `injection_suspect`. Die Oberfläche zeigt «Enthält Shell-Sonderzeichen. Keine
fertige Vorlage.» (D2-Variante im Design).

## 7 Belege

Bis 5 Belege je Denkanstoss (`EvidenceRef`): Claim, Einheit (Befehle vor Dateien, älteste zuerst, ohne
misstraute Quellen) und Zeilen. Zeilen zählen wie die Belegansicht (`unit_line.pos`, 0-basiert); das Label
nennt sie 1-basiert wie die Anzeige (`LogLine` zeigt `n + 1`): «nmap -sV · 14:02 · Zeile 6». Im Label
stehen das Werkzeug und höchstens zwei kurze Optionen ohne Ausgabe-Optionen (`-oA`, `-v`), bekannte Secrets
maskiert; die Uhrzeit ist die Lokalzeit des Daemons. Zwei Werte aus derselben Zeile ergeben einen Beleg.

## 8 Leistung

Die Engine liest die Projektion pro Anfrage (Hosts, Dienste, Kennungen, gültige Werte, Beobachter über
`first_unit`/`last_unit` und bei mehr als zwei Quellen gezielt aus `claim_source`, Befehle) und hält einen
**Schnappschuss** (Fakten und sortierte Kandidaten), solange sich die Projektion nicht ändert (neue
Generation mit Zeitstempel, Schreibzähler der Verbindung, neue Einheit, neues Secret). Der Zustand kommt bei
jedem Aufruf frisch aus den Entscheiden. Titel, Begründung, Belege und Vorlagen entstehen nur für die
ausgelieferten Einträge.

Gemessen (`tests/rules/test_performance.py`, 500 Hosts, 5000 Dienste, 9000 Denkanstösse, CPU-Zeit im
Testcontainer, in dem `sum(range(10**7))` 95 bis 135 ms braucht): warm (`/next` ohne Änderung) 13 bis 20 ms,
`open_count` warm 2 bis 3 ms; kalt (erster Aufruf nach einer Neuauswertung) 175 bis 260 ms. Der Test prüft
warm absolut unter 200 ms und kalt normiert auf die gemessene Rechenleistung.

## 9 Tests

| Datei | Inhalt |
|---|---|
| `test_golden.py` | MS2 (`-sV -sC`, Text und XML), MS2 nur `-sV` (Fall des Designs), Lame, feindlicher Host; Kurzform im Test, volle Ausgabe in `tests/golden/rules/*.json` (`--update-golden`); Form nach 18.6; jede gerenderte Vorlage in bash, dash, zsh und zsh mit `extendedglob` |
| `test_encoders.py` | jeder Typ, jeder Sperrgrund, Reihenfolge, feindlicher Korpus, Hypothesis |
| `test_templates.py` | Lint, Rendern, echte Shells, Hypothesis über Produkt, Version, IP und Port |
| `test_hostile_engine.py` | Hypothesis durch die ganze Engine: nichts Unsichtbares, Befehle zerfallen exakt |
| `test_state.py` | verwerfen, erledigt mit `basis`, neuer Anlass, Widerruf, Reparse, Merge, `check_decision` |
| `test_coverage.py` | Erledigt-Erkennung je Regel, andere Hosts, Ports, misstraute Befehle, Sackgasse, Nebel, Profil customer, Secrets |
| `test_performance.py` | 500 Hosts; Schnappschuss folgt neuen Befehlen |
| `test_route.py` | Route mit echtem Daemon, 422, feindlicher Ausgang, Belegzeile wie in der Belegansicht, Reparse |

## 10 Grenzen von v0.1

* Kein Prüfziel-Status (`d.goal.status` bleibt 501 bis v0.2), keine KI-Denkanstösse (`origin: 'ai'`).
* Keine Lockout-Zähler bei Anmelde-Vorlagen (Architektur 6.4 Punkt 8); im Profil customer gibt es dafür keine
  Vorlagen.
* Die Erkenner lesen Befehlszeilen, nicht deren Ergebnis: Ein abgebrochener `showmount` zählt als erledigt.
  Wer den Denkanstoss trotzdem will, nimmt «Rückgängig pro Befehl» oder lässt ihn offen.
* Importierte nmap-XML-Dateien ohne Befehl (`ariadne import`) haben keine bekannten Optionen; nur ihre
  Skriptausgaben zählen.
* Suchbegriffe für `searchsploit` sind einfache Ableitungen aus nmap-Produktnamen; Treffer sind nicht
  garantiert (etwa «Apache Tomcat Coyote JSP 1.1»).
