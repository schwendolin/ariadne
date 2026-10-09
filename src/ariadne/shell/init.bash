# Ariadne Shell-Integration für bash (Architektur 3.1, 3.3).
#
# Wird ganz oben aus ~/.bashrc eingelesen, mehrfaches Einlesen ist erlaubt.
# Aussen (noch kein Shim für dieses TTY): startet per exec den Launcher.
# Innen (ARIADNE_SHIM_TTY ist dieses TTY): installiert die Marker-Hooks.
#
# Marker: OSC 133 A/C/D unverändert ans Terminal, dazu der private Marker
#   ESC ] 7701 ; ariadne ; v1 ; <nonce> ; <pid>:<zähler> ; <typ> ; <felder> BEL
# PROMPT_COMMAND (an erster Stelle) liefert D und A, PS0 liefert C. Kein
# DEBUG-Trap. Ab bash 5.3 holt ${ builtin history 1; } den Befehlstext ohne
# Fork. Davor enthält erst der D-Marker den Befehl (ein Fork pro Befehl).

# Percent-Kodierung byteweise (Aufrufer setzt LC_ALL=C). Ergebnis in __ariadne_r.
__ariadne_enc() {
  local s=$1 out= safe c n
  while [[ -n $s ]]; do
    safe=${s%%[!A-Za-z0-9._~/:@+,-]*}
    out+=$safe
    s=${s:${#safe}}
    [[ -z $s ]] && break
    printf -v n '%d' "'${s:0:1}"
    printf -v c '%%%02X' $(( n & 255 ))
    out+=$c
    s=${s:1}
  done
  __ariadne_r=$out
}

# Einfache Referenzen $NAME und ${NAME} auflösen, ohne eval; $(...) nie ausführen.
__ariadne_vars() {
  local rest=$1 name val out= n=0 seen=' '
  while (( n < 4 )) && [[ $rest == *'$'* ]]; do
    rest=${rest#*\$}
    if [[ $rest == '{'[A-Za-z_]* ]]; then
      name=${rest#\{}
      name=${name%%[!A-Za-z0-9_]*}
      [[ ${rest#\{"$name"} == '}'* ]] || continue
    elif [[ $rest == [A-Za-z_]* ]]; then
      name=${rest%%[!A-Za-z0-9_]*}
    else
      continue
    fi
    (( ${#name} <= 32 )) || continue
    [[ $seen == *" $name "* ]] && continue
    seen+="$name "
    [[ -v $name ]] || continue
    case ${!name@a} in *a*|*A*) continue ;; esac
    val=${!name}
    __ariadne_enc "${val:0:128}"
    out+="&var.$name=$__ariadne_r"
    n=$(( n + 1 ))
  done
  __ariadne_r=$out
}

__ariadne_emit() {
  __ariadne_ctr=$(( __ariadne_ctr + 1 ))
  printf '\e]7701;ariadne;v1;%s;%s:%s;%s;%s\a' "$__ariadne_nonce" "$$" "$__ariadne_ctr" "$1" "$2"
}

# History-Ausgabe zerlegen. Neuer Eintrag: Text in __ariadne_r, sonst leer.
__ariadne_hist() {
  local h=$1 n
  h=${h#"${h%%[![:space:]]*}"}
  n=${h%%[!0-9]*}
  h=${h#"$n"}
  h=${h#\*}
  h=${h#"${h%%[! ]*}"}
  if [[ -z $n || $n == "${__ariadne_hnum-}" ]]; then
    __ariadne_r=
  else
    __ariadne_r=$h
  fi
  __ariadne_hnum=$n
}

__ariadne_precmd() {
  local __ariadne_ec=$? __ariadne_ps="${PIPESTATUS[*]}"
  local LC_ALL=C f cwd c
  if [[ -t 1 ]]; then
    if [[ -z ${__ariadne_hinit-} ]]; then
      __ariadne_hinit=1
      if (( __ariadne_funsub )); then
        __ariadne_hist "${ HISTTIMEFORMAT= builtin history 1; }"
      else
        __ariadne_hist "$(HISTTIMEFORMAT= builtin history 1 2>/dev/null)"
      fi
    fi
    __ariadne_enc "${PWD:0:300}"
    cwd=$__ariadne_r
    if (( __ariadne_ran )); then
      __ariadne_ran=0
      f="exit=$__ariadne_ec&pipestatus=${__ariadne_ps// /,}&cwd=$cwd"
      if (( ! __ariadne_funsub )); then
        __ariadne_hist "$(HISTTIMEFORMAT= builtin history 1 2>/dev/null)"
        c=$__ariadne_r
        if [[ -n $c ]]; then
          __ariadne_enc "${c:0:1000}"
          f="cmd=$__ariadne_r&$f"
          __ariadne_vars "$c"
          (( ${#f} + ${#__ariadne_r} <= 7600 )) && f+=$__ariadne_r
        fi
      fi
      printf '\e]133;D;%s\a' "$__ariadne_ec"
      __ariadne_emit D "$f"
    fi
    __ariadne_enc "${__ariadne_user:0:64}"
    __ariadne_cf="cwd=$cwd&user=$__ariadne_r&shlvl=${SHLVL//[!0-9]/}"
    printf '\e]133;A\a'
    __ariadne_emit A "cwd=$cwd"
  fi
  return "$__ariadne_ec"
}

# Nur bash >= 5.3: läuft per ${ ...; } in PS0, ohne Fork. Die Ausgabe ist der C-Marker.
__ariadne_ps0() {
  local LC_ALL=C f c
  __ariadne_ran=1
  [[ -t 2 ]] || return 0
  __ariadne_hist "${ HISTTIMEFORMAT= builtin history 1; }"
  c=$__ariadne_r
  f=
  if [[ -n $c ]]; then
    __ariadne_enc "${c:0:1000}"
    f="cmd=$__ariadne_r&"
  fi
  f+=$__ariadne_cf
  if [[ -n $c ]]; then
    __ariadne_vars "$c"
    (( ${#f} + ${#__ariadne_r} <= 7600 )) && f+=$__ariadne_r
  fi
  printf '\e]133;C\a'
  __ariadne_emit C "$f"
}

__ariadne_install() {
  local e
  __ariadne_nonce=$ARIADNE_NONCE
  if [[ -z ${__ariadne_ctr-} ]]; then
    # Startwert aus der Uhr (Mikrosekunden): nach "exec bash" mit gleicher PID
    # muss der Zähler weiter steigen, sonst gilt der Marker als Wiederholung.
    if [[ -n ${EPOCHREALTIME-} ]]; then
      __ariadne_ctr=${EPOCHREALTIME//[!0-9]/}
    else
      printf -v __ariadne_ctr '%(%s)T000000' -1
    fi
    __ariadne_ctr=$(( 10#${__ariadne_ctr:0:16} ))
  fi
  __ariadne_ran=${__ariadne_ran:-0}
  # Benutzername wie in \u des Prompts, ohne Fork und unabhängig von $USER.
  __ariadne_user='\u'
  __ariadne_user=${__ariadne_user@P}
  __ariadne_cf=${__ariadne_cf-}
  __ariadne_funsub=0
  if (( BASH_VERSINFO[0] > 5 || (BASH_VERSINFO[0] == 5 && BASH_VERSINFO[1] >= 3) )); then
    __ariadne_funsub=1
  fi
  # PROMPT_COMMAND: unser Hook zuerst, damit $? und PIPESTATUS unverändert ankommen.
  if [[ ${PROMPT_COMMAND@a} == *a* ]] \
    && (( BASH_VERSINFO[0] > 5 || (BASH_VERSINFO[0] == 5 && BASH_VERSINFO[1] >= 1) )); then
    for e in "${PROMPT_COMMAND[@]}"; do
      [[ $e == __ariadne_precmd ]] && break
    done
    [[ $e == __ariadne_precmd ]] || PROMPT_COMMAND=(__ariadne_precmd "${PROMPT_COMMAND[@]}")
  else
    case ${PROMPT_COMMAND-} in
      *__ariadne_precmd*) ;;
      *) PROMPT_COMMAND="__ariadne_precmd${PROMPT_COMMAND:+$'\n'$PROMPT_COMMAND}" ;;
    esac
  fi
  case ${PS0-} in
    *__ariadne_*|*7701*) ;;
    *)
      if (( __ariadne_funsub )); then
        PS0='${ __ariadne_ps0; }'"${PS0-}"
      elif shopt -q promptvars; then
        # Ohne Fork: Arithmetik und Parameter in PS0 laufen in der Shell selbst.
        PS0='\e]133;C\a\e]7701;ariadne;v1;'"$__ariadne_nonce;$$"':$((__ariadne_ran=1,__ariadne_ctr+=1));C;${__ariadne_cf}\a'"${PS0-}"
      fi
      ;;
  esac
}

[[ $- == *i* ]] || return 0

if [[ -n ${ARIADNE_SHIM_TTY-} && ${ARIADNE_SHIM_TTY} -ef /dev/stdin ]]; then
  # Innen: Hooks installieren (idempotent).
  if [[ ${#ARIADNE_NONCE} == 32 && ${ARIADNE_NONCE} != *[!0-9a-f]* ]]; then
    __ariadne_install
  fi
  return 0
fi

if [[ -n ${ARIADNE_SHIM_FAILED-} ]]; then
  if [[ $ARIADNE_SHIM_FAILED != nested && -t 1 ]]; then
    printf '\e]2;[ariadne inaktiv]\a'
  fi
  return 0
fi

# Aussen: Shim starten, wenn alles passt.
if [[ -t 0 && -t 1 && -n ${TERM-} && $TERM != dumb && -z ${ARIADNE_DISABLE-} ]] \
  && [[ ! -e ${XDG_CONFIG_HOME:-$HOME/.config}/ariadne/disable ]]; then
  __ariadne_launcher=${BASH_SOURCE[0]%/*}/launcher.sh
  if [[ /proc/$$/exe -ef ${BASH-} ]]; then
    __ariadne_self=$BASH
  else
    __ariadne_self=$(readlink /proc/$$/exe 2>/dev/null)
  fi
  if [[ -f $__ariadne_launcher && -x $__ariadne_launcher && -x /bin/sh \
        && -f $__ariadne_self && -x $__ariadne_self ]]; then
    if shopt -q execfail; then __ariadne_ef=1; else __ariadne_ef=0; fi
    shopt -s execfail
    exec "$__ariadne_launcher" "$__ariadne_self" -i
    (( __ariadne_ef )) || shopt -u execfail
  fi
  unset __ariadne_launcher __ariadne_self __ariadne_ef
fi
return 0
