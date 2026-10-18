# Installation in der Kali

Stand 2026-10-18, geprüft mit einer frischen Installation aus dem Wheel (neues venv, isoliertes HOME: `doctor`, `setup`, `init`, `ai setup`, `start`, `ui`, `stop`, `setup --remove`). Ziel: Kali (Xfce, X11) als normaler Benutzer, Ariadne per `pipx` (E84). Das Paket heisst `ariadne-recon`, der Befehl `ariadne`. Die Weboberfläche ist im Paket enthalten; Node brauchst du in der Kali nicht.

## 0 Vorbereitung

```sh
sudo apt update
sudo apt install pipx git xsel age
pipx ensurepath          # danach ein neues Terminal öffnen
```

Bricht die Installation später beim Paket `sqlcipher3` ab (kein fertiges Wheel für diese Python-Version), zusätzlich `sudo apt install build-essential python3-dev libsqlcipher-dev` und die Installation wiederholen.

Das Repo ist privat. Wähle **einen** der Wege A bis D. Am einfachsten ist D.

Solange v0.1 nicht auf `main` liegt, steht der Code auf dem Branch `ccr-9333dca5-pkv7z6`; darum enden die Befehle unten mit `@ccr-9333dca5-pkv7z6` bzw. `--branch ccr-9333dca5-pkv7z6`.

## D Klonen und aus dem Ordner installieren (am einfachsten)

Auf GitHub einen Fine-grained Token erstellen: Settings, Developer settings, Personal access tokens, Fine-grained tokens. Repository access «Only select repositories» mit `schwendolin/ariadne`, Permissions «Contents: Read-only», Ablauf zum Beispiel 30 Tage. Dann in der Kali:

```sh
git clone --branch ccr-9333dca5-pkv7z6 https://github.com/schwendolin/ariadne.git ~/ariadne-src
# Username: dein GitHub-Name, Password: den Token einfügen (wird nicht angezeigt)
pipx install ~/ariadne-src
```

Nicht nach `~/ariadne` klonen: Diesen Ordner braucht Ariadne für die Projekte. Der Token steht so weder in der History noch in der Adresse des Repos.

Aktualisieren: `ariadne stop`, dann `cd ~/ariadne-src && git pull` (fragt wieder nach Name und Token), `pipx install --force ~/ariadne-src`, `ariadne daemon stop`, `ariadne setup`, neue Terminals öffnen.

## A Aus dem Repo mit Deploy-Key (empfohlen)

Ein Deploy-Key gilt nur für dieses eine Repo und nur zum Lesen.

```sh
ssh-keygen -t ed25519 -f ~/.ssh/ariadne_deploy -N '' -C "kali-ariadne"
cat ~/.ssh/ariadne_deploy.pub
```

Den ausgegebenen Schlüssel auf GitHub unter Repo, Settings, Deploy keys eintragen («Allow write access» **nicht** ankreuzen). Dann in der Kali:

```sh
cat >> ~/.ssh/config <<'EOF'
Host github-ariadne
  HostName github.com
  User git
  IdentityFile ~/.ssh/ariadne_deploy
  IdentitiesOnly yes
EOF
chmod 600 ~/.ssh/config
pipx install "git+ssh://git@github-ariadne/schwendolin/ariadne.git@ccr-9333dca5-pkv7z6"
```

Beim ersten Mal fragt `ssh` nach dem Hostkey von github.com; den Fingerabdruck mit der Liste auf docs.github.com vergleichen.

## B Aus dem Repo mit HTTPS-Token

Ein Fine-grained Token mit Zugriff nur auf dieses Repo und nur «Contents: Read-only». Der Token wird ohne Echo gelesen und steht so weder in der Shell-History noch im Terminalbild noch in der Befehlszeile eines Prozesses:

```sh
printf 'Token: '; read -rs GH_TOKEN; echo
export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0="http.https://github.com/.extraheader"
export GIT_CONFIG_VALUE_0="Authorization: Basic $(printf 'x-access-token:%s' "$GH_TOKEN" | base64 -w0)"
pipx install "git+https://github.com/schwendolin/ariadne.git@ccr-9333dca5-pkv7z6"
unset GH_TOKEN GIT_CONFIG_COUNT GIT_CONFIG_KEY_0 GIT_CONFIG_VALUE_0
```

Nie `https://TOKEN@github.com/...` tippen: Das landet in der History und in `pipx list`.

Läuft Ariadne in diesem Terminal schon (Aktualisieren), vorher `ariadne pause` tippen: Ariadne nimmt sonst auch Eingaben ohne Echo auf (E26). Danach `ariadne resume`.

## C Wheel über die Datei-Übertragung der Webkonsole

Auf dem Rechner mit dem Checkout (Mac oder Entwicklungsrechner):

```sh
scripts/build-ui.sh            # nur nötig, wenn webui/ geändert wurde
uv build --wheel               # oder: python -m build --wheel
shasum -a 256 dist/ariadne_recon-*.whl
```

Die Datei `dist/ariadne_recon-….whl` über die Datei-Übertragung der Webkonsole in die Kali laden (landet meist in `~/Downloads`). In der Kali:

```sh
sha256sum ~/Downloads/ariadne_recon-*.whl     # muss mit dem Wert oben übereinstimmen
pipx install ~/Downloads/ariadne_recon-*.whl
```

Die Abhängigkeiten holt `pipx` aus dem Internet (PyPI).

## 1 Einrichten

```sh
ariadne doctor            # Zeile «Weboberfläche vorhanden» muss [ok] sein
ariadne setup             # Shell-Integration in ~/.zshrc und ~/.bashrc, systemd-Unit
```

Vor `setup` meldet `doctor` «Shell-Integration unvollständig» (`[!!]`); das ist richtig und verschwindet mit `setup`. Danach **alle Terminals schliessen** und ein neues öffnen; erst neue Terminals laufen mit Ariadne.

```sh
ariadne init              # Operator-Tresor mit Passphrase (mindestens 8 Zeichen); Recovery-Code sicher notieren
```

Nach einem VM-Reset mit Sicherung **nicht** `init`, sondern zurückspielen (siehe [Anleitung Fernzugriff](anleitung-fernzugriff.md) 8).

**Empfänger der Sicherung** eintragen, sonst bricht `ariadne backup` mit «Keine Empfänger für die Sicherung» ab. Ein öffentlicher age-Schlüssel (`age1…`) pro Zeile, mindestens der Mac-Schlüssel und der Recovery-Schlüssel aus [Anleitung Fernzugriff](anleitung-fernzugriff.md) 4 (bei Weg B erledigt das `kali-setup.sh --recipient`):

```sh
install -d -m 700 ~/.config/ariadne
printf '%s\n' 'age1…MAC' 'age1…RECOVERY' > ~/.config/ariadne/backup-recipients.txt
chmod 600 ~/.config/ariadne/backup-recipients.txt
```

## 2 KI (optional)

```sh
ariadne ai setup          # Anbieter (cloud oder local), Modell-ID, Monatslimit; bei cloud API-Key ohne Echo
ariadne ai check          # ok, warn oder fail: TLS ohne fremde CA, kein Proxy, Ollama erreichbar
ariadne ai status         # Anbieter, Modell, Verbrauch des Monats, Schlüssel vorhanden
```

Die Modell-ID setzt du selbst (aus der Liste deines Anbieters; lokal zuerst `ollama pull <ID>`); Ariadne kennt keinen Standard. Ist sie falsch, meldet das Dashboard «Modell-ID beim Anbieter unbekannt» bzw. «Modell in Ollama nicht geladen». Ohne `ai setup` läuft alles ausser den KI-Denkanstössen. Was an die KI geht, läuft vorher durch den Redaktor (E72).

- **cloud:** Der API-Key liegt verschlüsselt im Operator-Tresor (darum zuerst `ariadne init`) und gilt als eigenes Secret: Steht er in einer Ausgabe, ersetzt ihn Ariadne vor Export, Dashboard und KI. TLS prüft Ariadne nur gegen die Mozilla-Liste (`certifi`), nie gegen CAs, die im System installiert sind (Burp, Schulnetz): Bei einem Aufbruch scheitert die Verbindung, statt den Key durchzureichen. Pro Projekt braucht es zusätzlich die Freigabe im Terminal: `ariadne ai allow-cloud` (nach `ariadne start`). Im Profil customer und bei öffentlichen Adressen im Scope ohne `--not-customer` bleibt die Cloud gesperrt.
- **local:** Ollama auf `127.0.0.1` (`ollama serve`), Port 11434; ein anderer Port steht in `~/.config/ariadne/ai.toml` unter `[local]` als `port = …`.
- Die Preise in `ai.toml` unter `[prices]` sind vorsichtige Platzhalter; an die Preisliste deines Modells anpassen, sonst rechnet das Budget zu hoch.

## 3 Start

```sh
ariadne start ms2 --target 192.168.56.101 --not-customer
ariadne status
ariadne ui                # Dashboard im Browser der Kali (Einmal-Code)
ariadne ui --code         # nur den kurzen Anmeldecode zeigen (Browser schon offen, Mac)
```

**Anmeldecode.** Das Feld «Anmeldecode» im Dashboard will den Code aus `ariadne ui --code` (gilt kurz und nur einmal), **nie die Passphrase**. Nach `ariadne stop` oder `ariadne lock` ist jede Sitzung beendet: zuerst `ariadne start`, dann `ariadne ui` (öffnet den Browser angemeldet) oder `ariadne ui --code` und den Code eintippen.

**Scope.** `--target` gilt nur beim Anlegen. Danach zeigt und ändert `ariadne scope` den Scope, jede Änderung mit Rückfrage `[j/N]`, als Entscheid im Journal und mit Neuauswertung:

```sh
ariadne scope                               # Einschlüsse, Ausschlüsse, Zeitfenster, letzte Änderungen
ariadne scope add recovery.vantis.internal  # IP, CIDR, Bereich a.b.c.d-e, Name oder '*.domain' (Wildcard in Anführungszeichen)
ariadne scope exclude 10.36.198.1           # ausschliessen (Ausschluss schlägt Einschluss)
ariadne scope remove 10.36.198.1            # Eintrag wieder entfernen
ariadne scope undo                          # jüngste Änderung rückgängig (oder: undo <decision_id>)
```

Im Dashboard geht dasselbe über die Scope-Warnung in «Als Nächstes» («In den Scope aufnehmen» mit Bestätigung) und über die Zeitachse (Rückgängig). Namen erben nie den Scope ihrer IP (E49): Meldet nmap `recovery.vantis.internal (10.36.198.11)`, fragt Ariadne unter «Klären», ob der Name (oder `*.vantis.internal`) in den Scope soll. Ziele ausserhalb der Lab-Allowlist (öffentliche Adressen und Domains) gehen nur im Terminal mit `--not-customer`, wie beim Anlegen.

Im Terminal: `F12 s` nimmt einen Screenshot des aktiven Fensters auf (nur X11, Xfce), `ariadne shot monitor` den ganzen Bildschirm. Bericht: `ariadne export` (Vorlage `cys`, mit `--template htb` die HTB-Vorlage) schreibt nach `~/ariadne/<projekt>/exports/`; dasselbe geht im Dashboard über «Export». Vom Mac aus: [Anleitung Fernzugriff](anleitung-fernzugriff.md). Ende der Session: `ariadne stop`, danach `ariadne backup --to-file PFAD.age` (braucht die Empfänger aus Abschnitt 1).

## 4 Aktualisieren und entfernen

Aktualisieren: zuerst `ariadne stop`, dann denselben Weg wie oben mit `pipx install --force …` wiederholen, danach `ariadne daemon stop`, `ariadne setup` und neue Terminals öffnen. `ariadne doctor` meldet eine fehlende oder unvollständige Weboberfläche mit dem Hinweis `pipx reinstall ariadne-recon`.

Entfernen: `ariadne setup --remove`, dann `pipx uninstall ariadne-recon`. Projekte (`~/ariadne`) und Tresor (`~/.local/share/ariadne`) bleiben liegen, bis du sie selbst löschst.

## Für Entwickler: gebaute Oberfläche

Der Build der Oberfläche liegt eingecheckt in `src/ariadne/web/static` (mit `.build-info.json`: Hash der webui-Quellen und jeder Datei). Nach jeder Änderung in `webui/` gilt:

```sh
PATH=/opt/node22/bin:$PATH scripts/build-ui.sh   # baut und schreibt den Build-Vermerk
python -m pytest tests/packaging                  # prüft Vollständigkeit, Quellstand und Wheel
```

Den geänderten Build mit einchecken. In einem Checkout meldet `ariadne doctor` «Weboberfläche veraltet», sobald die Quellen nicht mehr zum Build passen.
