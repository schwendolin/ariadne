#!/bin/sh
# kali-setup.sh: Fernzugriff auf Ariadne in der Kali einrichten (Konzept Fernzugriff 4.2 bis 4.5,
# E89, E90, E94, R10, R11). Weg B (Tailscale) zuerst, Weg A und C als Optionen.
#
# Was das Skript tut (jede Änderung wird vorher als Diff gezeigt und erst nach «j» geschrieben):
#   1. Eigene SSH-Hostkeys: alte löschen, einen ed25519-Hostkey neu erzeugen, Marker
#      /etc/ssh/ariadne-hostkeys.marker mit Datum und Fingerprint (Kalis aus derselben Vorlage
#      haben sonst vielleicht dieselben Hostkeys).
#   2. sshd-Drop-in /etc/ssh/sshd_config.d/10-ariadne.conf: nur Schlüssel, kein root, nur
#      Weiterleitung zu 127.0.0.1:7330; Weg B nur aus dem Tailnet (AllowUsers USER@100.64.0.0/10).
#   3. Weg A und B: Filter, der Port 22 nur über den erlaubten Weg zulässt (Weg B: tailscale0),
#      und sshd startet nur, wenn der Filter geladen ist (Requires=, fail-closed).
#   4. authorized_keys mit genau einer Zeile:
#      restrict,pty,port-forwarding,permitopen="127.0.0.1:7330",command=".../ariadne remote serve" KEY
#   5. Empfänger der Sicherung nach ~/.config/ariadne/backup-recipients.txt (0600).
#   6. linger für den Benutzer (Runtime-Ordner auch ohne Anmeldung, für ssh kali-sl code).
#   7. Weg C: Benutzer-Dienst für den Rückwärts-Tunnel zum eigenen Server.
#   8. sshd -t, dann (nach Rückfrage) Filter und sshd aktivieren.
#
# Nie: Tailscale-Routen, Exit-Node, Tailscale SSH, Serve oder Funnel; kein Passwort-Login.
# Idempotent: Ein zweiter Lauf mit denselben Angaben ändert nichts.
#
# Aufruf (bewusst mit sudo, aus der Konsole der Kali):
#   sudo sh kali-setup.sh --weg b --key mac.pub --recipient age1... --recipient age1...
#
# Für Tests: ARIADNE_SETUP_ROOT=/pfad/zur/wegwerf-wurzel legt alle Systempfade darunter an,
# braucht kein root, ruft weder systemctl noch sshd -t noch loginctl auf.

set -eu

PROG=kali-setup.sh
R="${ARIADNE_SETUP_ROOT:-}"
WEG=b
USER_NAME="${SUDO_USER:-}"
USER_HOME=""
KEY_FILE=""
KEY_LINE=""
ARIADNE_BIN=""
ALLOW=""
PORT=7330
YES=0
DRY=0
NEW_HOSTKEYS=0
RECIPIENTS=""
SERVER=""
SERVER_PORT=22
CHANGED=0
DROPIN_OLD=""

say() { printf '%s\n' "$*"; }
warn() { printf 'Warnung: %s\n' "$*" >&2; }
die() { printf 'Fehler: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Aufruf: sudo sh kali-setup.sh [Optionen]

  --weg a|b|c          Zugangsweg (Standard b: Tailscale). a: offizieller Weg der Schule,
                       c: eigener Server mit ssh -R
  --user NAME          Benutzer in der Kali (Standard: der Aufrufer von sudo)
  --home PFAD          Home des Benutzers (Standard: aus /etc/passwd)
  --key DATEI          öffentlicher Schlüssel des Macs (.pub, ssh-ed25519)
  --key-line 'ZEILE'   derselbe Schlüssel als Text: 'ssh-ed25519 AAAA... kommentar'
  --ariadne PFAD       Programm ariadne (Standard: HOME/.local/bin/ariadne, pipx)
  --port N             Port der Web-Oberfläche (Standard 7330, wie [ui] port)
  --allow 'REGEL'      Weg a: wer an Port 22 darf, z. B. 'ip saddr 10.20.0.0/16'
  --recipient age1...  Empfänger der Sicherung (mehrfach: Mac-Schlüssel und Recovery-Schlüssel)
  --server USER@HOST   Weg c: eigener Server für den Rückwärts-Tunnel
  --server-port N      Weg c: SSH-Port des Servers (Standard 22)
  --new-hostkeys       Hostkeys auch dann neu erzeugen, wenn der Marker passt
  --yes                nicht nachfragen (alle gezeigten Änderungen übernehmen)
  --dry-run            nur zeigen, nichts schreiben
  -h, --help           diese Hilfe
EOF
}

need_arg() {
    [ "$2" -ge 2 ] || die "$1 braucht einen Wert"
}

while [ $# -gt 0 ]; do
    case $1 in
        --weg) need_arg "$1" $#; WEG=$2; shift 2 ;;
        --user) need_arg "$1" $#; USER_NAME=$2; shift 2 ;;
        --home) need_arg "$1" $#; USER_HOME=$2; shift 2 ;;
        --key) need_arg "$1" $#; KEY_FILE=$2; shift 2 ;;
        --key-line) need_arg "$1" $#; KEY_LINE=$2; shift 2 ;;
        --ariadne) need_arg "$1" $#; ARIADNE_BIN=$2; shift 2 ;;
        --port) need_arg "$1" $#; PORT=$2; shift 2 ;;
        --allow) need_arg "$1" $#; ALLOW=$2; shift 2 ;;
        --recipient) need_arg "$1" $#; RECIPIENTS="$RECIPIENTS $2"; shift 2 ;;
        --server) need_arg "$1" $#; SERVER=$2; shift 2 ;;
        --server-port) need_arg "$1" $#; SERVER_PORT=$2; shift 2 ;;
        --new-hostkeys) NEW_HOSTKEYS=1; shift ;;
        --yes) YES=1; shift ;;
        --dry-run) DRY=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; die "unbekannte Option: $1" ;;
    esac
done

# --------------------------------------------------------------------------- #
# Prüfen der Angaben
# --------------------------------------------------------------------------- #

# Kein Wert darf einen Zeilenumbruch oder ein anderes Steuerzeichen enthalten: Die Prüfungen mit
# grep arbeiten zeilenweise, und ein Wert mit Zeilenumbruch landete sonst als eigene Zeile im
# Drop-in oder in authorized_keys (Befund SEC-S1).
NL='
'
CR=$(printf '\r')
no_ctrl() {
    case $2 in
        *"$NL"*|*"$CR"*) die "$1: Zeilenumbruch im Wert, abgebrochen" ;;
    esac
    if printf '%s' "$2" | LC_ALL=C grep -q '[[:cntrl:]]'; then
        die "$1: Steuerzeichen im Wert, abgebrochen"
    fi
}
no_ctrl ARIADNE_SETUP_ROOT "$R"
no_ctrl --weg "$WEG"
no_ctrl --user "$USER_NAME"
no_ctrl --home "$USER_HOME"
no_ctrl --key "$KEY_FILE"
no_ctrl --key-line "$KEY_LINE"
no_ctrl --ariadne "$ARIADNE_BIN"
no_ctrl --port "$PORT"
no_ctrl --allow "$ALLOW"
no_ctrl --recipient "$RECIPIENTS"
no_ctrl --server "$SERVER"
no_ctrl --server-port "$SERVER_PORT"

if [ -n "$R" ]; then
    case $R in /*) ;; *) die "ARIADNE_SETUP_ROOT muss ein absoluter Pfad sein" ;; esac
    [ -d "$R" ] || die "ARIADNE_SETUP_ROOT ist kein Ordner: $R"
    R=${R%/}
elif [ "$(id -u)" != 0 ]; then
    die "bitte mit sudo starten: sudo sh $PROG ... (das Skript ändert sshd und Systemdienste)"
fi

case $WEG in a|b|c) ;; *) die "--weg muss a, b oder c sein" ;; esac
case $USER_NAME in
    ''|root) die "Benutzer fehlt: --user NAME (nicht root)" ;;
esac
printf '%s' "$USER_NAME" | grep -Eq '^[a-z_][a-z0-9_.-]{0,31}$' || die "ungültiger Benutzername"
if [ -z "$USER_HOME" ]; then
    USER_HOME=$(getent passwd "$USER_NAME" | cut -d: -f6) || true
    [ -n "$USER_HOME" ] || die "Benutzer $USER_NAME unbekannt (--home angeben)"
    no_ctrl "Home aus /etc/passwd" "$USER_HOME"
fi
case $USER_HOME in /*) ;; *) die "--home muss absolut sein" ;; esac
printf '%s' "$USER_HOME" | grep -Eq '^/[A-Za-z0-9/._-]+$' || die "Home-Pfad mit ungewöhnlichen Zeichen"
printf '%s' "$PORT" | grep -Eq '^[0-9]{4,5}$' || die "--port: Zahl von 1024 bis 65535"
[ "$PORT" -ge 1024 ] && [ "$PORT" -le 65535 ] || die "--port: Zahl von 1024 bis 65535"
[ -n "$ARIADNE_BIN" ] || ARIADNE_BIN="$USER_HOME/.local/bin/ariadne"
printf '%s' "$ARIADNE_BIN" | grep -Eq '^/[A-Za-z0-9/._+-]*/ariadne$' \
    || die "--ariadne: absoluter Pfad zu einem Programm namens ariadne, ohne Leer- und Sonderzeichen"
if [ "$WEG" = a ]; then
    [ -n "$ALLOW" ] || die "Weg a braucht --allow 'ip saddr NETZ/MASKE' (Quelle des offiziellen Wegs)"
    printf '%s' "$ALLOW" | grep -Eq '^(ip|ip6) saddr [0-9A-Fa-f.:]+(/[0-9]{1,3})?$|^iifname "[A-Za-z0-9_.-]{1,15}"$' \
        || die "--allow: nur 'ip saddr NETZ/MASKE', 'ip6 saddr NETZ/MASKE' oder 'iifname \"NAME\"'"
fi
if [ "$WEG" = c ]; then
    [ -n "$SERVER" ] || die "Weg c braucht --server tunnel@DEIN-SERVER"
    printf '%s' "$SERVER" | grep -Eq '^[a-z_][a-z0-9_.-]{0,31}@[A-Za-z0-9.-]{1,253}$' || die "--server: BENUTZER@HOST"
    printf '%s' "$SERVER_PORT" | grep -Eq '^[0-9]{1,5}$' || die "--server-port: Zahl"
fi
for rcp in $RECIPIENTS; do
    printf '%s' "$rcp" | grep -Eq '^age1[02-9ac-hj-np-z]{58}$' \
        || die "--recipient: nur öffentliche age-Schlüssel (age1..., X25519)"
done

UH="$R$USER_HOME"
TMPD=$(mktemp -d)
trap 'rm -rf "$TMPD"' EXIT
trap 'rm -rf "$TMPD"; exit 130' INT TERM

# --------------------------------------------------------------------------- #
# Hilfen
# --------------------------------------------------------------------------- #

testmode() { [ -n "$R" ]; }

confirm() {
    if [ "$DRY" = 1 ]; then
        say "  (Trockenlauf: nichts geschrieben)"
        return 1
    fi
    [ "$YES" = 1 ] && return 0
    printf '%s [j/N] ' "$1"
    answer=""
    read -r answer || answer=""
    case $answer in j|J|ja|Ja|JA|y|Y|yes) return 0 ;; esac
    say "  übersprungen"
    return 1
}

# Befehl als der Benutzer (Dateien in seinem Home). Im Testmodus oder ohne root direkt.
as_user() {
    if testmode || [ "$(id -u)" != 0 ]; then
        "$@"
    else
        runuser -u "$USER_NAME" -- "$@"
    fi
}

mode_of() { stat -c %a "$1" 2>/dev/null || echo -; }

# Zeigt den Unterschied zwischen ALT (Datei oder leer) und NEU.
show_diff() {
    old=$1 new=$2 label=$3
    if [ -s "$old" ] || [ -e "$old" ]; then
        diff -u --label "vorher: $label" --label "nachher: $label" "$old" "$new" | sed 's/^/  /' || true
    else
        say "  neu: $label"
        sed 's/^/  + /' "$new"
    fi
}

# Systemdatei schreiben (root): put_file ZIEL MODUS NEU
put_file() {
    target=$1 mode=$2 new=$3
    [ -L "$target" ] && die "$target ist ein Symlink, abgebrochen"
    if [ -f "$target" ] && cmp -s "$target" "$new" && [ "$(mode_of "$target")" = "$mode" ]; then
        say "unverändert: ${target#"$R"}"
        return 0
    fi
    if [ -f "$target" ]; then
        if cmp -s "$target" "$new"; then
            say "Rechte ändern: ${target#"$R"} $(mode_of "$target") -> $mode"
        else
            say "Änderung: ${target#"$R"}"
            show_diff "$target" "$new" "${target#"$R"}"
        fi
    else
        show_diff /nonexistent "$new" "${target#"$R"}"
    fi
    confirm "Schreiben?" || return 0
    mkdir -p "$(dirname "$target")"
    cp "$new" "$target.ariadne-neu"
    chmod "$mode" "$target.ariadne-neu"
    mv -f "$target.ariadne-neu" "$target"
    CHANGED=$((CHANGED + 1))
}

# Datei im Home des Benutzers schreiben, als der Benutzer: put_user_file ZIEL MODUS NEU
put_user_file() {
    target=$1 mode=$2 new=$3
    cur="$TMPD/aktuell"
    rm -f "$cur"
    exists=0
    if as_user test -L "$target"; then
        die "${target#"$R"} ist ein Symlink, abgebrochen"
    fi
    if as_user test -f "$target"; then
        exists=1
        as_user cat "$target" > "$cur"
    fi
    if [ "$exists" = 1 ] && cmp -s "$cur" "$new" && [ "$(as_user stat -c %a "$target")" = "$mode" ]; then
        say "unverändert: ${target#"$R"}"
        return 0
    fi
    if [ "$exists" = 1 ] && cmp -s "$cur" "$new"; then
        say "Rechte ändern: ${target#"$R"} -> $mode"
    elif [ "$exists" = 1 ]; then
        say "Änderung: ${target#"$R"}"
        show_diff "$cur" "$new" "${target#"$R"}"
    else
        show_diff /nonexistent "$new" "${target#"$R"}"
    fi
    confirm "Schreiben?" || return 0
    as_user sh -c 'set -eu; umask 077; d=$(dirname "$1"); mkdir -p "$d"; chmod 700 "$d"
        cat > "$1.ariadne-neu"; chmod "$2" "$1.ariadne-neu"; mv -f "$1.ariadne-neu" "$1"' \
        sh "$target" "$mode" < "$new"
    CHANGED=$((CHANGED + 1))
}

fingerprint() {
    ssh-keygen -lf "$1" | awk '{print $2}'
}

# --------------------------------------------------------------------------- #
# Schritte
# --------------------------------------------------------------------------- #

step_hostkeys() {
    say ""
    say "== 1 Hostkeys =="
    marker="$R/etc/ssh/ariadne-hostkeys.marker"
    pub="$R/etc/ssh/ssh_host_ed25519_key.pub"
    if [ "$NEW_HOSTKEYS" = 0 ] && [ -f "$marker" ] && [ -f "$pub" ]; then
        fp=$(fingerprint "$pub")
        mfp=$(sed -n 's/^fingerprint=//p' "$marker" | head -n 1)
        if [ -n "$fp" ] && [ "$fp" = "$mfp" ]; then
            say "Hostkeys schon selbst erzeugt: $fp"
            created=$(sed -n 's/^created=//p' "$marker" | head -n 1)
            write_marker "$created" "$fp"
            return 0
        fi
        say "Der Hostkey passt nicht zum Marker (ersetzt?)."
    fi
    say "Neue Hostkeys: Kalis aus derselben Vorlage haben sonst vielleicht dieselben."
    say "Wird gelöscht:"
    found=0
    for f in "$R"/etc/ssh/ssh_host_*; do
        [ -e "$f" ] || continue
        found=1
        say "  ${f#"$R"}"
    done
    [ "$found" = 1 ] || say "  (keine)"
    say "Wird erzeugt: /etc/ssh/ssh_host_ed25519_key (ed25519) und der Marker"
    confirm "Hostkeys neu erzeugen?" || return 0
    mkdir -p "$R/etc/ssh"
    rm -f "$R"/etc/ssh/ssh_host_*
    ssh-keygen -q -t ed25519 -N '' -C '' -f "$R/etc/ssh/ssh_host_ed25519_key"
    chmod 600 "$R/etc/ssh/ssh_host_ed25519_key"
    chmod 644 "$pub"
    fp=$(fingerprint "$pub")
    CHANGED=$((CHANGED + 1))
    write_marker "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$fp"
    say ""
    say "Fingerprint des neuen Hostkeys (notieren, auf dem Mac beim ersten Login vergleichen):"
    say "  $fp"
}

write_marker() {
    {
        say "# Ariadne: SSH-Hostkeys dieser Kali selbst erzeugt (kali-setup.sh). Prüfen: ariadne remote check"
        say "created=$1"
        say "fingerprint=$2"
        say "weg=$WEG"
    } > "$TMPD/marker"
    put_file "$R/etc/ssh/ariadne-hostkeys.marker" 644 "$TMPD/marker"
}

dropin_content() {
    say "# Ariadne Fernzugriff, Weg $(printf '%s' "$WEG" | tr abc ABC) (kali-setup.sh). Wird bei jedem Lauf neu geschrieben."
    say "# Bei sshd gilt der erste Wert: Diese Datei wird vor dem Rest von sshd_config gelesen."
    say "# Prüfen: sudo sshd -T -C user=$USER_NAME,host=pruefung,addr=192.0.2.1 und ariadne remote check --full"
    say "PermitRootLogin no"
    say "PasswordAuthentication no"
    say "KbdInteractiveAuthentication no"
    say "PubkeyAuthentication yes"
    say "AuthenticationMethods publickey"
    case $WEG in
        a) say "AllowUsers $USER_NAME" ;;
        b) say "AllowUsers $USER_NAME@100.64.0.0/10" ;;
        c) say "AllowUsers $USER_NAME@127.0.0.1"
           say "ListenAddress 127.0.0.1" ;;
    esac
    say "AllowTcpForwarding local"
    say "PermitOpen 127.0.0.1:$PORT"
    say "PermitListen none"
    say "GatewayPorts no"
    say "X11Forwarding no"
    say "AllowAgentForwarding no"
    say "AllowStreamLocalForwarding no"
    say "PermitTunnel no"
    say "PermitUserEnvironment no"
    say "MaxAuthTries 3"
    say "LoginGraceTime 20"
    say "ClientAliveInterval 30"
    say "ClientAliveCountMax 3"
    say "HostKey /etc/ssh/ssh_host_ed25519_key"
}

step_dropin() {
    say ""
    say "== 2 sshd-Einstellungen =="
    main="$R/etc/ssh/sshd_config"
    if [ -f "$main" ]; then
        grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "$main" \
            || die "/etc/ssh/sshd_config bindet sshd_config.d nicht ein: 'Include /etc/ssh/sshd_config.d/*.conf' ganz oben eintragen"
    elif testmode; then
        warn "kein sshd_config im Testmodus"
    else
        die "openssh-server fehlt: sudo apt install openssh-server"
    fi
    target="$R/etc/ssh/sshd_config.d/10-ariadne.conf"
    if [ -f "$target" ]; then
        DROPIN_OLD="$TMPD/dropin.alt"
        cp "$target" "$DROPIN_OLD"
    fi
    dropin_content > "$TMPD/dropin"
    put_file "$target" 644 "$TMPD/dropin"
}

step_filter() {
    say ""
    say "== 3 Filter für Port 22 =="
    if [ "$WEG" = c ]; then
        say "Weg C: sshd lauscht nur auf 127.0.0.1, kein Filter nötig."
        return 0
    fi
    if [ "$WEG" = b ]; then
        rule='iifname "tailscale0"'
    else
        rule=$ALLOW
    fi
    {
        say "# Ariadne: Port 22 nur über den erlaubten Weg (kali-setup.sh, Weg $(printf '%s' "$WEG" | tr abc ABC))"
        say "table inet ariadne_ssh"
        say "delete table inet ariadne_ssh"
        say "table inet ariadne_ssh {"
        say "  chain input {"
        say "    type filter hook input priority -10; policy accept;"
        say "    iifname \"lo\" accept"
        say "    $rule tcp dport 22 accept"
        say "    tcp dport 22 drop"
        say "  }"
        say "}"
    } > "$TMPD/filter"
    put_file "$R/etc/ariadne/ssh-filter.nft" 644 "$TMPD/filter"
    {
        say "[Unit]"
        say "Description=Ariadne: Port 22 nur über den erlaubten Weg"
        say "Before=ssh.service"
        say "[Service]"
        say "Type=oneshot"
        say "RemainAfterExit=yes"
        say "ExecStart=/usr/sbin/nft -f /etc/ariadne/ssh-filter.nft"
        say "ExecStop=/usr/sbin/nft delete table inet ariadne_ssh"
        say "[Install]"
        say "WantedBy=multi-user.target"
    } > "$TMPD/unit"
    put_file "$R/etc/systemd/system/ariadne-ssh-filter.service" 644 "$TMPD/unit"
    {
        say "# Ariadne: sshd startet nur mit geladenem Filter (fail-closed)"
        say "[Unit]"
        say "Requires=ariadne-ssh-filter.service"
        say "After=ariadne-ssh-filter.service"
    } > "$TMPD/dep"
    put_file "$R/etc/systemd/system/ssh.service.d/ariadne.conf" 644 "$TMPD/dep"
}

# Schlüssel (Typ, Base64, Kommentar) aus einer Zeile; Optionen davor werden übergangen.
key_from_line() {
    printf '%s\n' "$1" | awk '{
        for (i = 1; i <= NF; i++) if ($i == "ssh-ed25519" || $i == "sk-ssh-ed25519@openssh.com") {
            c = ""; if (i + 2 <= NF) c = $(i + 2); print $i, $(i + 1), c; exit
        }
    }'
}

# Fingerprint (SHA256:...) eines Schlüssels "typ base64"; "?" ohne ssh-keygen.
key_fp() {
    fp=$(printf '%s %s\n' "$1" "$2" | ssh-keygen -lf - 2>/dev/null | awk '{print $2}') || fp=""
    printf '%s' "${fp:-?}"
}

# Schlüssel aus --key, --key-line oder der vorhandenen authorized_keys; prüft vor jeder Änderung.
# Ergebnis in KEY_PARTS ("typ base64 kommentar") oder leer.
resolve_key() {
    ak="$UH/.ssh/authorized_keys"
    src=""
    if [ -n "$KEY_FILE" ]; then
        [ -f "$KEY_FILE" ] || die "--key: Datei fehlt: $KEY_FILE"
        n=$(grep -cE '^(ssh-ed25519|sk-ssh-ed25519@openssh\.com) ' "$KEY_FILE") || n=0
        if [ "$n" -gt 1 ]; then
            # etwa alle Schlüssel eines GitHub-Kontos: nie still den ersten nehmen (Befund F5)
            say "In $KEY_FILE stehen $n Schlüssel:"
            grep -E '^(ssh-ed25519|sk-ssh-ed25519@openssh\.com) ' "$KEY_FILE" | while read -r t b _rest; do
                say "  $(key_fp "$t" "$b")"
            done
            die "--key: genau ein Schlüssel nötig. Nur die Zeile behalten, deren Fingerprint auf dem Mac ssh-keygen -lf ~/.ssh/id_ed25519_kali_sl.pub zeigt."
        fi
        src=$(grep -E '^(ssh-ed25519|sk-ssh-ed25519@openssh\.com) ' "$KEY_FILE" | head -n 1) || true
        [ -n "$src" ] || die "--key: keine Zeile mit ssh-ed25519 in $KEY_FILE"
    elif [ -n "$KEY_LINE" ]; then
        src=$KEY_LINE
    elif as_user test -f "$ak"; then
        lines=$(as_user cat "$ak" | grep -Ev '^[[:space:]]*(#|$)' | wc -l)
        if [ "$lines" -gt 1 ]; then
            die "authorized_keys hat $lines Schlüssel: mit --key den Schlüssel des Macs angeben (die anderen fallen weg)"
        fi
        src=$(as_user cat "$ak" | grep -Ev '^[[:space:]]*(#|$)' | head -n 1) || true
    fi
    KEY_PARTS=""
    [ -n "$src" ] || return 0
    parts=$(key_from_line "$src")
    [ -n "$parts" ] || die "Schlüssel: nur ssh-ed25519 (auf dem Mac: ssh-keygen -t ed25519 -a 100)"
    # shellcheck disable=SC2086
    set -- $parts
    printf '%s' "$2" | grep -Eq '^AAAA[A-Za-z0-9+/]+={0,2}$' || die "Schlüssel: Base64-Teil ungültig"
    kc=${3:-}
    printf '%s' "$kc" | grep -Eq '^[A-Za-z0-9@._-]{0,64}$' || kc=""
    KEY_PARTS="$1 $2 $kc"
}

step_keys() {
    say ""
    say "== 4 Schlüssel des Macs (authorized_keys) =="
    ak="$UH/.ssh/authorized_keys"
    if [ -z "$KEY_PARTS" ]; then
        say "Kein Schlüssel angegeben und keiner eingetragen: übersprungen (--key mac.pub)."
        return 0
    fi
    # shellcheck disable=SC2086
    set -- $KEY_PARTS
    say "Schlüssel des Macs: $(key_fp "$1" "$2") (auf dem Mac vergleichen:"
    say "  ssh-keygen -lf ~/.ssh/id_ed25519_kali_sl.pub)"
    line="restrict,pty,port-forwarding,permitopen=\"127.0.0.1:$PORT\",command=\"$ARIADNE_BIN remote serve\" $1 $2"
    if [ -n "${3:-}" ]; then
        line="$line $3"
    fi
    printf '%s\n' "$line" > "$TMPD/ak"
    put_user_file "$ak" 600 "$TMPD/ak"
    ak2="$UH/.ssh/authorized_keys2"
    if as_user test -f "$ak2" && as_user cat "$ak2" | grep -Evq '^[[:space:]]*(#|$)'; then
        say "authorized_keys2 enthält Schlüssel; sshd liest auch diese Datei."
        : > "$TMPD/empty"
        put_user_file "$ak2" 600 "$TMPD/empty"
    fi
    if [ ! -x "$R$ARIADNE_BIN" ]; then
        warn "$ARIADNE_BIN fehlt oder ist nicht ausführbar (pipx install …, sonst --ariadne PFAD)"
    fi
}

step_recipients() {
    say ""
    say "== 5 Empfänger der Sicherung =="
    if [ -z "$RECIPIENTS" ]; then
        say "Keine angegeben: übersprungen (--recipient age1... für Mac- und Recovery-Schlüssel)."
        return 0
    fi
    {
        say "# Empfänger der Sicherung (öffentliche age-Schlüssel, kali-setup.sh). Mac-Schlüssel und Recovery-Schlüssel."
        seen=" "
        for rcp in $RECIPIENTS; do
            case $seen in *" $rcp "*) continue ;; esac
            seen="$seen$rcp "
            say "$rcp"
        done
    } > "$TMPD/rcp"
    put_user_file "$UH/.config/ariadne/backup-recipients.txt" 600 "$TMPD/rcp"
}

step_linger() {
    say ""
    say "== 6 Runtime-Ordner ohne Anmeldung (linger) =="
    if [ -e "$R/var/lib/systemd/linger/$USER_NAME" ]; then
        say "unverändert: linger für $USER_NAME ist an"
        return 0
    fi
    say "Neu: loginctl enable-linger $USER_NAME (/run/user/UID besteht ab dem Start der VM; sonst"
    say "findet ssh kali-sl code den Daemon erst nach einer Anmeldung in der Kali)"
    confirm "Einschalten?" || return 0
    if testmode; then
        mkdir -p "$R/var/lib/systemd/linger"
        : > "$R/var/lib/systemd/linger/$USER_NAME"
    else
        loginctl enable-linger "$USER_NAME"
    fi
    CHANGED=$((CHANGED + 1))
}

step_tunnel() {
    [ "$WEG" = c ] || return 0
    say ""
    say "== 7 Rückwärts-Tunnel zum eigenen Server (Weg C) =="
    key="$UH/.ssh/id_ed25519_rendezvous"
    if as_user test -f "$key"; then
        say "unverändert: Tunnel-Schlüssel ${key#"$R"}"
    else
        say "Neu: Tunnel-Schlüssel ${key#"$R"} (ohne Passphrase, kann nur 127.0.0.1:2222 am Server öffnen)"
        if confirm "Erzeugen?"; then
            as_user sh -c 'umask 077; mkdir -p "$(dirname "$1")"; ssh-keygen -q -t ed25519 -N "" -C kali-vm -f "$1"' \
                sh "$key"
            CHANGED=$((CHANGED + 1))
        fi
    fi
    {
        say "[Unit]"
        say "Description=Ariadne: Rückwärts-Tunnel zum eigenen Server (Weg C)"
        say "After=network-online.target"
        say "[Service]"
        say "ExecStart=/usr/bin/ssh -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes -o ControlMaster=no -o ControlPath=none -i %h/.ssh/id_ed25519_rendezvous -p $SERVER_PORT -R 127.0.0.1:2222:127.0.0.1:22 $SERVER"
        say "Restart=always"
        say "RestartSec=20"
        say "[Install]"
        say "WantedBy=default.target"
    } > "$TMPD/revtunnel"
    put_user_file "$UH/.config/systemd/user/ariadne-revtunnel.service" 644 "$TMPD/revtunnel"
    if as_user test -f "$key.pub"; then
        say "Auf dem Server in /home/tunnel/.ssh/authorized_keys eintragen:"
        say "  restrict,port-forwarding,permitlisten=\"127.0.0.1:2222\" $(as_user cat "$key.pub")"
    fi
    say "Danach als $USER_NAME: ssh -i ~/.ssh/id_ed25519_rendezvous $SERVER true (Hostkey prüfen),"
    say "dann systemctl --user enable --now ariadne-revtunnel"
}

restore_dropin() {
    target="$R/etc/ssh/sshd_config.d/10-ariadne.conf"
    if [ -n "$DROPIN_OLD" ]; then
        cp "$DROPIN_OLD" "$target"
    else
        rm -f "$target"
    fi
}

step_finish() {
    say ""
    say "== 8 Prüfen und aktivieren =="
    if testmode; then
        say "Testmodus: sshd -t und systemctl übersprungen."
        return 0
    fi
    if [ "$DRY" = 1 ]; then
        say "Trockenlauf: nichts aktiviert."
        return 0
    fi
    if ! sshd -t; then
        restore_dropin
        die "sshd -t meldet einen Fehler: Drop-in zurückgesetzt, nichts aktiviert"
    fi
    say "sshd -t: Konfiguration in Ordnung"
    systemctl daemon-reload
    if systemctl is-enabled --quiet ssh.socket 2>/dev/null || systemctl is-active --quiet ssh.socket 2>/dev/null; then
        say "ssh.socket ist an: Socket-Aktivierung umgeht die Abhängigkeit vom Filter."
        if confirm "ssh.socket abschalten (systemctl disable --now ssh.socket)?"; then
            systemctl disable --now ssh.socket
            CHANGED=$((CHANGED + 1))
        fi
    fi
    if [ "$WEG" = c ]; then
        cmd="systemctl enable ssh && systemctl restart ssh"
    else
        cmd="systemctl enable --now ariadne-ssh-filter && systemctl enable ssh && systemctl restart ssh"
    fi
    say "Zum Schluss: $cmd"
    if confirm "sshd jetzt mit den neuen Einstellungen starten?"; then
        if [ "$WEG" != c ]; then
            systemctl enable --now ariadne-ssh-filter.service
        fi
        systemctl enable ssh.service
        systemctl restart ssh.service
    fi
}

# --------------------------------------------------------------------------- #
# Ablauf
# --------------------------------------------------------------------------- #

KEY_PARTS=""
resolve_key

say "Ariadne: Fernzugriff einrichten, Weg $(printf '%s' "$WEG" | tr abc ABC), Benutzer $USER_NAME"
testmode && say "Testmodus: Wurzel $R"
[ "$DRY" = 1 ] && say "Trockenlauf: Es wird nichts geschrieben."
step_hostkeys
step_dropin
step_filter
step_keys
step_recipients
step_linger
step_tunnel
step_finish
say ""
say "Fertig: $CHANGED Änderungen."
if [ "$WEG" = b ]; then
    say "Tailscale (falls noch nicht): sudo tailscale up --ssh=false --accept-dns=false --accept-routes=false --advertise-tags=tag:kali-lab"
    say "Nie --advertise-routes oder --advertise-exit-node."
fi
say "Prüfen: ariadne remote check --full"
