# Anleitung: das Ariadne-Dashboard auf dem Mac (Weg B)

Am Ende dieser Anleitung öffnest du auf dem Mac `ariadne-mac start`, und im normalen Browser des Macs erscheint das Dashboard deiner Kali in SmartLearn. Die Passphrase tippst du dabei im Terminal des Macs, nicht in der Webkonsole. Nach der Session sichert `ariadne-mac stop` alles verschlüsselt auf den Mac.

So funktioniert es in einem Satz: Tailscale verbindet Mac und Kali, darin läuft SSH, und SSH trägt den Port `127.0.0.1:7330` der Kali auf den `127.0.0.1:7330` des Macs. Ariadne selbst lauscht weiter nur auf Loopback der Kali (E89). Warum das so gebaut ist, steht im [Konzept Fernzugriff](konzept-fernzugriff.md); hier geht es nur ums Tun.

Der SSH-Schlüssel des Macs kann genau das und nicht mehr: den Tunnel zu Port 7330 und diese sieben Befehle. Eine Shell bekommt er nie (E94, R11).

| Befehl | was er tut |
|---|---|
| `code` | holt einen Einmal-Code für das Dashboard und hält die Verbindung, die den Tunnel trägt |
| `unlock` | entsperrt Ariadne (Passphrase im Mac-Terminal, braucht `ssh -t`); ein aktives Projekt öffnet sich gleich mit (E101) |
| `lock` | sperrt Ariadne; das Projekt bleibt aktiv (E103) |
| `revoke` | beendet alle Anmeldungen im Dashboard |
| `backup` | schreibt die verschlüsselte Sicherung auf stdout |
| `restore` | spielt eine Sicherung zurück, nur in eine Kali ohne Operator-Tresor |
| `check` | zeigt `ariadne remote check` der Kali |

Alles andere, auch `scp`, `sftp` und `ssh kali-sl id`, lehnt die Kali mit «Abgelehnt» ab. Verwalten (Pakete, Konfiguration) tust du weiter über die Webkonsole.

> **Stand 2026-10-17.** Server, Anmeldung, Tunnel, Sicherung und alle Befehle dieser Anleitung sind gebaut und Ende zu Ende getestet (unter Linux; macOS selbst und die echte SmartLearn-Kali sind noch nicht geprüft). Die Oberfläche im Browser ist noch der erste Entwurf und zeigt darum noch nicht alles richtig an; die Oberfläche nach dem Design v0.1 folgt. Bis dahin zeigt dir `ariadne status` und `ariadne show …` in der Kali dasselbe.

## 0 Bevor du anfängst

- **Erlaubnis.** Tailscale nur mit der schriftlichen Erlaubnis der Schule (E90, offener Punkt O10). Lege die Antwort ab.
- **Kali:** eigenes Passwort gesetzt (`passwd`), Ariadne installiert (`pipx install …`), `ariadne setup` und `ariadne init` gemacht. Das Paket `openssh-server` muss da sein: `sudo apt install openssh-server age`.
- **Mac:** FileVault an (`fdesetup status` zeigt `FileVault is On.`), [Homebrew](https://brew.sh) installiert.
- **Webkonsole** in Chrome oder Safari, in einem Profil ohne Erweiterungen. Nie Firefox, dort kommen Tasten doppelt an.

Die Befehle unten nehmen `kali` als deinen Benutzer in der Kali. Heisst er anders (`whoami` zeigt es), setzt du deinen Namen ein.

## 1 Tailscale auf dem Mac

1. Konto auf tailscale.com anlegen und beim Login-Anbieter (GitHub, Google, Apple) MFA einschalten.
2. Tailscale für macOS installieren und anmelden. In den Einstellungen «Allow incoming connections» ausschalten.
3. **Bevor die Kali beitritt**, in der Admin-Konsole unter «Access controls» die Policy ersetzen. Ein neues Tailnet erlaubt zuerst alles; die Kali soll den Mac aber nie erreichen.

```json
{
  "tagOwners": { "tag:kali-lab": ["autogroup:admin"] },
  "hosts":     { "mac": "100.x.y.z" },
  "grants": [
    { "src": ["mac"], "dst": ["tag:kali-lab"], "ip": ["tcp:22"] }
  ]
}
```

`100.x.y.z` ist die Tailscale-Adresse deines Macs (Menü von Tailscale oder `tailscale ip -4`). Die Policy hat bewusst kein `ssh` (kein Tailscale SSH) und kein `nodeAttrs` (kein Funnel).

## 2 Tailscale in der Kali

```bash
curl -fsSL https://tailscale.com/install.sh -o ts-install.sh && less ts-install.sh
sh ts-install.sh
```

Das Skript erst lesen, dann starten. Es installiert das Paket `tailscale`.

```bash
echo 'FLAGS="--no-logs-no-support"' | sudo tee -a /etc/default/tailscaled
sudo systemctl restart tailscaled
sudo tailscale up --ssh=false --accept-dns=false --accept-routes=false --advertise-tags=tag:kali-lab --qr
```

Die erste Zeile schaltet die Client-Logs an Tailscale ab. `--qr` zeigt den Anmeldelink als QR-Code fürs Handy. **Nie** `--advertise-routes` oder `--advertise-exit-node`: Damit öffnest du das Lab-Netz der Schule in dein Tailnet.

```bash
tailscale ip -4
tailscale debug prefs | grep -E '"(AdvertiseRoutes|ExitNodeID|RunSSH)"'
```

Die Adresse (`100.…`) brauchst du gleich auf dem Mac. In den Prefs erwartest du `null`, `""` und `false`.

## 3 Schlüssel auf dem Mac

```bash
ssh-keygen -t ed25519 -a 100 -f ~/.ssh/id_ed25519_kali_sl -C mac-kali-smartlearn
```

Erzeugt den Schlüssel für die Kali. Gib eine Passphrase ein; `ariadne-mac` startet ohne sie gar nicht. Lege den Schlüssel **nicht** in den Schlüsselbund (kein `--apple-use-keychain`, kein `UseKeychain yes`), sonst kann jedes Programm auf dem Mac ihn ohne Passphrase benutzen.

Die Datei `~/.ssh/id_ed25519_kali_sl.pub` muss in die Kali. Am einfachsten über dein GitHub-Konto (Schlüssel dort hinterlegen, in der Kali `curl -fsS https://github.com/DEIN-NAME.keys`), sonst über die Datei-Übertragung von SmartLearn oder Abtippen. Speichere sie in der Kali als `~/mac.pub`.

## 4 Sicherungsschlüssel auf dem Mac

```bash
brew install age
install -d -m 700 ~/.config/ariadne-backup ~/Ariadne-Backups
age-keygen | age -p -o ~/.config/ariadne-backup/mac.key.age
```

Die letzte Zeile erzeugt den Mac-Schlüssel und verschlüsselt ihn sofort mit einer Passphrase. Sie zeigt `Public key: age1…`; diese Zeile brauchst du in Schritt 5.

```bash
age-keygen
```

Das ist der **Recovery-Schlüssel**: nur anzeigen, nie speichern. Drucke beide Zeilen aus (`AGE-SECRET-KEY-…` und `# public key: age1…`) oder lege sie in den Passwortmanager. Mit ihm kommst du an deine Sicherungen, wenn der Mac weg ist.

`~/Ariadne-Backups` liegt bewusst nicht im Schreibtisch, in Dokumente oder unter `~/Library/CloudStorage`. `ariadne-mac` verweigert solche Ordner (R13), weil iCloud oder OneDrive sie sonst mitnehmen.

## 5 Die Kali einrichten: kali-setup.sh

Das Skript liegt im Repository unter `packaging/smartlearn/kali-setup.sh`. Hole es in die Kali (`git clone` oder Datei-Übertragung) und starte es **in der Webkonsole**:

```bash
sudo sh kali-setup.sh --weg b --key ~/mac.pub --recipient age1…MAC --recipient age1…RECOVERY
```

`--recipient` zweimal: der öffentliche Mac-Schlüssel aus Schritt 4 und der öffentliche Recovery-Schlüssel. Das Skript arbeitet in Schritten und zeigt bei jedem, was es ändern will, als Diff. Erst mit `j` schreibt es:

1. **Hostkeys:** Es löscht die Hostkeys der Vorlage und erzeugt einen neuen ed25519-Hostkey. Der Fingerprint (`SHA256:…`) erscheint am Bildschirm. **Notiere ihn** (Handy, Papier), du vergleichst ihn gleich auf dem Mac.
2. **sshd-Einstellungen** in `/etc/ssh/sshd_config.d/10-ariadne.conf`: nur Schlüssel, kein root, Anmeldung nur aus dem Tailnet (`AllowUsers kali@100.64.0.0/10`), Weiterleitung nur zu `127.0.0.1:7330`.
3. **Filter für Port 22:** nur über `tailscale0`. sshd startet nur, wenn der Filter geladen ist.
4. **authorized_keys** mit genau einer Zeile: `restrict,pty,port-forwarding,permitopen="127.0.0.1:7330",command=".../ariadne remote serve" ssh-ed25519 …`
5. **Empfänger der Sicherung** nach `~/.config/ariadne/backup-recipients.txt`.
6. **linger:** Dein Benutzer-Runtime-Ordner besteht ab dem Start der VM. Sonst findet der Mac den Daemon erst, wenn du dich in der Kali angemeldet hast.
7. **Prüfen und aktivieren** (im Skript «8», die «7» gibt es nur bei Weg C): `sshd -t`; ist `ssh.socket` an, fragt es, ob es ihn abschalten soll (sonst umginge die Socket-Aktivierung den Filter); dann fragt es, ob es Filter und sshd starten soll.

Ein zweiter Lauf mit denselben Angaben ändert nichts («Fertig: 0 Änderungen.»). `--dry-run` zeigt nur, was passieren würde. `--help` zeigt alle Optionen. Läuft die Web-Oberfläche in der Kali nicht auf Port 7330 (`[ui] port` in `~/.config/ariadne/config.toml`), gibst du denselben Port mit `--port N` an und setzt auf dem Mac `export ARIADNE_MAC_PORT=N`; Mac und Kali müssen denselben Port nehmen, sonst lehnt die Kali die Anfragen ab (421).

Danach prüfen:

```bash
ariadne remote check --full
```

Fragt einmal nach dem sudo-Passwort und zeigt jede Prüfung mit `[ok]`, `[--]` (Warnung) oder `[!!]` (Fehler). Solange ein `[!!]` dasteht, gibt die Kali dem Mac keinen Code. Eine Warnung zu OpenSSH unter 9.8 ist kein Abbruch, die Kali bekommt das Update mit `apt`.

**Andere Wege.** Weg A (offizieller Weg der Schule) geht mit `--weg a --allow 'ip saddr NETZ/MASKE'`, Weg C (eigener Server) mit `--weg c --server tunnel@DEIN-SERVER`; Details im Konzept 4.3 und 4.5.

## 6 ariadne-mac einrichten

Kopiere `packaging/mac/ariadne-mac` aus dem Repository auf den Mac:

```bash
install -d ~/bin && install -m 755 ariadne-mac ~/bin/ariadne-mac
```

Liegt `~/bin` noch nicht im `PATH`, trägst du `path=(~/bin $path)` in `~/.zshrc` ein.

Dann die SSH-Konfiguration nur für die Kali, als eigene Datei `~/.ssh/ariadne.conf`:

```text
Host kali-sl
  HostName 100.a.b.c
  User kali
  IdentityFile ~/.ssh/id_ed25519_kali_sl
  IdentitiesOnly yes
  AddKeysToAgent 4h
  HostKeyAlias kali-smartlearn
  HostKeyAlgorithms ssh-ed25519
  StrictHostKeyChecking yes
  ControlMaster no
  ControlPath none
  ForwardAgent no
  ForwardX11 no
  ServerAliveInterval 15
  ServerAliveCountMax 3
```

`HostName` ist die Tailscale-Adresse der Kali aus Schritt 2, `User` dein Benutzer in der Kali. `ariadne-mac` liest nur diese Datei (`ssh -F ~/.ssh/ariadne.conf`), deine übrige SSH-Konfiguration spielt keine Rolle. Willst du auch von Hand `ssh kali-sl …` tippen, setzt du ganz oben in `~/.ssh/config` die Zeile `Include ariadne.conf`.

**Erster Login, einmal mit Rückfrage:**

```bash
ssh -F ~/.ssh/ariadne.conf -o StrictHostKeyChecking=ask kali-sl check
```

SSH zeigt den Fingerprint des Hostkeys. Nur wenn er Zeichen für Zeichen mit dem aus Schritt 5 übereinstimmt, tippst du `yes`. Weicht er ab, brichst du ab: Dann redest du nicht mit deiner Kali. Danach erscheint die Prüfung der Kali.

```bash
ariadne-mac check
```

Prüft den Mac (FileVault, Schlüssel mit Passphrase, Hostkey bekannt, `StrictHostKeyChecking yes`, Port 7330 frei, Sicherungsordner, Sicherungsschlüssel verschlüsselt) und danach die Kali.

## 7 Alltag

**Session beginnen.** In der Kali wie immer `ariadne start …` in der Webkonsole. Ist die Kali neu gestartet und das Projekt noch aktiv, geht es auch vom Mac aus:

```bash
ariadne-mac unlock
```

Fragt nach der Passphrase von Ariadne, im Terminal des Macs. Das aktive Projekt öffnet sich und die Aufnahme läuft wieder (E101, E102).

**Dashboard öffnen:**

```bash
ariadne-mac start
```

Prüft den Mac, baut **eine** SSH-Verbindung auf, die den Code holt und den Tunnel trägt, prüft, dass Port 7330 jetzt wirklich diesem `ssh` gehört, und öffnet das Dashboard in deinem Standardbrowser. Der Code ist 60 Sekunden gültig und nur einmal; er steht nur in einer Startdatei mit Rechten 0600, die nach 10 Sekunden verschwindet. Die Anmeldung ist an genau diese SSH-Verbindung gebunden und hat die Herkunft «über sshd» (`ariadne ui --sessions` in der Kali zeigt sie).

Der Browser ist dein normaler Browser (E93). Erweiterungen mit Zugriff auf alle Seiten können das Dashboard lesen; Secrets zeigt es darum verdeckt, und vor einer Bildschirmfreigabe schaltest du den Präsentationsmodus ein.

**Pause.** Gehst du weg: in der Kali `ariadne lock` oder vom Mac `ssh -F ~/.ssh/ariadne.conf kali-sl lock`. Das beendet auch die Anmeldung im Dashboard.

**Session beenden:**

```bash
ariadne-mac stop
```

Widerruft alle Anmeldungen, sperrt Ariadne (das Projekt bleibt aktiv), holt die Sicherung nach `~/Ariadne-Backups/kali-sl-DATUM.age` und schliesst den Tunnel. Ohne Sicherung: `ariadne-mac stop --no-backup`. Nur sichern geht jederzeit mit `ariadne-mac backup`, aber nur bei gesperrtem oder beendetem Projekt.

**Tunnel weg.** Klappst du den Mac zu oder wechselt das WLAN, endet die SSH-Verbindung und mit ihr die Anmeldung (E92). Das Dashboard zeigt dann wieder die Anmeldung. `ariadne-mac start` meldet dich neu an.

**Ohne Helfer, von Hand:** `ssh -F ~/.ssh/ariadne.conf -t -L 127.0.0.1:7330:127.0.0.1:7330 kali-sl code` zeigt einen kurzen Tippcode (`ABCDE-FGHJK`). Dann im Browser `http://127.0.0.1:7330` öffnen und den Code eingeben. Ctrl-C im Terminal beendet Tunnel und Anmeldung.

## 8 Wiederherstellen nach einem VM-Reset

Die Schule kann die VM jederzeit zurücksetzen. Dann:

1. **Neue Kali vorbereiten:** `passwd`, Ariadne installieren, `ariadne setup`. **Nicht** `ariadne init`, sonst entsteht ein neuer Operator-Tresor und das Zurückspielen wird abgelehnt.
2. **Tailscale:** In der Admin-Konsole den alten Knoten der Kali entfernen, dann Schritt 2 wiederholen. Die neue Tailscale-Adresse kommt in `~/.ssh/ariadne.conf` (`HostName`).
3. **kali-setup.sh** wie in Schritt 5. Es erzeugt neue Hostkeys; notiere den neuen Fingerprint.
4. **Hostkey auf dem Mac neu lernen.** Das ist der wichtigste Schritt, denn im nächsten geht deine Sicherung im Klartext an die Kali:

```bash
ssh-keygen -R kali-smartlearn
ssh -F ~/.ssh/ariadne.conf -o StrictHostKeyChecking=ask kali-sl check
```

Die erste Zeile vergisst den alten Hostkey. Bei der zweiten nur `yes`, wenn der Fingerprint mit der Konsole übereinstimmt.

5. **Zurückspielen:**

```bash
ariadne-mac restore ~/Ariadne-Backups/kali-sl-DATUM.age
```

Fragt, ob du den Hostkey geprüft hast, dann nach der Passphrase von `mac.key.age`. Der entschlüsselte Strom existiert nur in der Pipe. Die Kali prüft Manifest, Version und alle Hashes und schreibt erst, wenn alles stimmt.

6. **Ketten prüfen:** `ariadne-mac unlock`, dann in der Kali `ariadne project open SLUG` und `ariadne verify`. Den Kettenkopf vergleichst du mit dem Wert, den `ariadne-mac stop` bei der Sicherung angezeigt hat.

**Ohne Netzweg** (Tailscale geht noch nicht): Die `.age`-Datei per Datei-Übertragung in die VM bringen und dort aufrufen:

```bash
ariadne restore --from-file DATEI.age --identity -
```

`--identity -` fragt verdeckt nach dem Recovery-Schlüssel (die Zeile `AGE-SECRET-KEY-…` vom Ausdruck oder aus dem Passwortmanager); er kommt nie als Datei in die VM. Danach fragt `restore` nach der Passphrase von Ariadne und prüft jede Kette («Kette lab1: in Ordnung»). Weil der Schlüssel durch die Webkonsole getippt wurde, gilt er danach als verbraucht: erzeuge einen neuen (Schritt 4) und trage den neuen Empfänger ein (Schritt 5).

**Sicherung ohne Netzweg** (heute Weg E): In der Kali nach der Session `ariadne stop`, dann `install -d -m 700 ~/Abgabe` und `ariadne backup --to-file ~/Abgabe/sicherung-$(date -u +%Y%m%dT%H%M%SZ).age`, und die Datei über die Datei-Übertragung holen. Ausgabe auf das Terminal verweigert `ariadne backup`, damit nie ein Datenstrom auf dem Konsolenbild landet.

## 9 Fehlerbilder

| Was du siehst | Was es heisst | Was du tust |
|---|---|---|
| `Fernzugriff nicht sicher eingerichtet (ariadne remote check): …` | eine Prüfung der Kali meldet `[!!]`; die Gründe stehen dahinter | in der Kali `ariadne remote check --full`, dann `kali-setup.sh` erneut |
| `Host key verification failed` oder `REMOTE HOST IDENTIFICATION HAS CHANGED` | der Hostkey ist nicht der gelernte | nichts bestätigen. War ein Reset: Abschnitt 8, Schritt 4. Sonst sitzt jemand dazwischen |
| `[!!] Hostkey der Kali unbekannt` | der erste Login fehlt | Schritt 6, «Erster Login» |
| `Permission denied (publickey)` | Schlüssel nicht eingetragen, falscher `User`, oder die Verbindung kommt nicht aus dem Tailnet | `HostName` muss die `100.…`-Adresse sein; in der Kali `ariadne remote check` |
| `ssh: connect to host … timed out` | Tailscale auf Mac oder Kali nicht verbunden | `tailscale status` auf beiden Seiten |
| `[!!] Port 7330 belegt` | ein anderes Programm oder ein alter Tunnel hält den Port | `lsof -nP -iTCP:7330 -sTCP:LISTEN` zeigt wer; alten Tunnel mit `ariadne-mac stop --no-backup` schliessen |
| `kein Code von der Kali` | die Verbindung kam nicht zustande oder die Kali gab keinen Code | die letzten Zeilen darunter lesen; Protokoll in `~/Library/Application Support/ariadne-mac/tunnel.log` |
| `Kein Code: Web-Oberfläche aus: …` | der Web-Server im Daemon läuft nicht, der Grund steht dahinter | in der Kali `ariadne status`; `[ui]` in `config.toml` prüfen |
| `Kein Runtime-Ordner (XDG_RUNTIME_DIR fehlt …)` | kein `/run/user/UID`, weil niemand in der Kali angemeldet ist | in der Webkonsole anmelden oder einmal `sudo loginctl enable-linger $USER` |
| `Daemon nicht erreichbar` | der Daemon startet nicht | in der Kali `ariadne status` und das Daemon-Log unter `~/.local/state/ariadne/` |
| Dashboard zeigt wieder die Anmeldung | die Anmeldung endete: `lock`, Tunnel weg, Projekt beendet oder 12 Stunden um | `ariadne-mac start` |
| `421` im Browser | falscher Host, zum Beispiel `localhost` statt `127.0.0.1` | immer `http://127.0.0.1:7330` |
| `Sicherung fehlgeschlagen (project_open)` | ein Projekt ist offen | `ariadne-mac stop` sperrt vorher; von Hand `ssh -F ~/.ssh/ariadne.conf kali-sl lock` |
| `Sicherung fehlgeschlagen (no_recipients)` | in der Kali sind keine Empfänger eingetragen | `kali-setup.sh … --recipient age1…` |
| `Sicherungsordner … liegt in iCloud …` | der Ordner würde synchronisiert | anderen Ordner, zum Beispiel `~/Ariadne-Backups` (`ARIADNE_MAC_BACKUP_DIR`) |
| `Abgelehnt: In dieser Kali gibt es schon einen Operator-Tresor` | `restore` geht nur in eine frische Installation | auf einer neuen Kali kein `ariadne init` vor dem Zurückspielen |
| `Abgelehnt: Unbekannter Befehl` | der Mac-Schlüssel kann nur die sieben Befehle oben | Verwaltung über die Webkonsole |
| `Abgelehnt: unlock braucht ein Terminal` | `unlock` ohne `-t` | `ariadne-mac unlock` |
