# Ariadne Shell-Integration für zsh (Architektur 3.1, 3.3).
#
# Wird ganz oben aus ~/.zshrc eingelesen, mehrfaches Einlesen ist erlaubt.
# Aussen (noch kein Shim für dieses TTY): startet per exec den Launcher.
# Innen (ARIADNE_SHIM_TTY ist dieses TTY): installiert die Marker-Hooks.
#
# Marker: OSC 133 A/C/D unverändert ans Terminal, dazu der private Marker
#   ESC ] 7701 ; ariadne ; v1 ; <nonce> ; <pid>:<zähler> ; <typ> ; <felder> BEL
# Die Hooks benutzen nur Builtins (kein Fork) und verändern $? nicht.

# Percent-Kodierung byteweise. Ergebnis in $REPLY.
__ariadne_enc() {
  emulate -L zsh
  setopt nomultibyte
  local s=$1 out= safe c
  while [[ -n $s ]]; do
    safe=${s%%[^A-Za-z0-9._~/:@+,-]*}
    out+=$safe
    s=${s[${#safe}+1,-1]}
    [[ -z $s ]] && break
    c=${s[1]}
    out+=%${(l:2::0:)$(( [##16] #c ))}
    s=${s[2,-1]}
  done
  REPLY=$out
}

# Einfache Referenzen $NAME und ${NAME} im getippten Befehl auflösen, ohne eval.
# $(...) wird nie ausgeführt. Ergebnis ("&var.NAME=wert...") in $REPLY.
__ariadne_vars() {
  emulate -L zsh
  setopt nomultibyte
  local rest=$1 name val out=
  local -i n=0
  local -A seen
  while (( n < 4 )) && [[ $rest == *'$'* ]]; do
    rest=${rest#*\$}
    if [[ $rest == '{'[A-Za-z_]* ]]; then
      name=${${rest#\{}%%[^A-Za-z0-9_]*}
      [[ ${rest#\{$name} == '}'* ]] || continue
    elif [[ $rest == [A-Za-z_]* ]]; then
      name=${rest%%[^A-Za-z0-9_]*}
    else
      continue
    fi
    (( ${#name} <= 32 )) || continue
    (( ${+seen[$name]} )) && continue
    seen[$name]=1
    [[ ${(Pt)name} == (scalar|integer|float)* ]] || continue
    val=${(P)name}
    __ariadne_enc "${val[1,128]}"
    out+="&var.$name=$REPLY"
    n+=1
  done
  REPLY=$out
}

__ariadne_emit() {
  __ariadne_ctr+=1
  print -rn -- $'\e]7701;ariadne;v1;'"$__ariadne_nonce;$$:$__ariadne_ctr;$1;$2"$'\a'
}

__ariadne_preexec() {
  emulate -L zsh
  setopt nomultibyte
  [[ -t 1 ]] || return 0
  __ariadne_ran=1
  local REPLY f base vars cmdx=
  __ariadne_enc "${1[1,1000]}"
  f="cmd=$REPLY"
  if [[ -n $3 && $3 != "$1" ]]; then
    __ariadne_enc "${3[1,1000]}"
    cmdx="&cmdx=$REPLY"
  fi
  __ariadne_enc "${PWD[1,300]}"
  base="&cwd=$REPLY"
  __ariadne_enc "${USERNAME[1,64]}"
  base+="&user=$REPLY&shlvl=${SHLVL//[^0-9]/}"
  __ariadne_vars "$1"
  vars=$REPLY
  if (( ${#f} + ${#cmdx} + ${#base} + ${#vars} > 7600 )); then
    vars=
    (( ${#f} + ${#cmdx} + ${#base} > 7600 )) && cmdx=
  fi
  print -rn -- $'\e]133;C\a'
  __ariadne_emit C "$f$cmdx$base$vars"
}

__ariadne_precmd() {
  local ec=$? ps="${(j:,:)pipestatus[@]}"
  emulate -L zsh
  setopt nomultibyte
  [[ -t 1 ]] || return 0
  local REPLY cwd
  __ariadne_enc "${PWD[1,300]}"
  cwd=$REPLY
  if (( __ariadne_ran )); then
    __ariadne_ran=0
    print -rn -- $'\e]133;D;'"$ec"$'\a'
    __ariadne_emit D "exit=$ec&pipestatus=${ps//[^0-9,]/}&cwd=$cwd"
  fi
  print -rn -- $'\e]133;A\a'
  __ariadne_emit A "cwd=$cwd"
}

[[ -o interactive ]] || return 0

if [[ -n ${ARIADNE_SHIM_TTY-} && ${ARIADNE_SHIM_TTY} == "${TTY-}" ]]; then
  # Innen: Hooks installieren (idempotent, Zähler bleibt beim erneuten Einlesen).
  () {
    emulate -L zsh
    local nonce=${ARIADNE_NONCE-}
    [[ ${#nonce} == 32 && $nonce != *[^0-9a-f]* ]] || return 0
    typeset -g __ariadne_nonce=$nonce
    if (( ! ${+__ariadne_ctr} )); then
      # Startwert aus der Uhr (Mikrosekunden): nach "exec zsh" mit gleicher
      # PID muss der Zähler weiter steigen, sonst gilt der Marker als Wiederholung.
      zmodload -F zsh/datetime p:EPOCHREALTIME 2>/dev/null
      local now=${${EPOCHREALTIME-0}//[^0-9]/}
      typeset -gi __ariadne_ctr=${now[1,16]}
    fi
    (( ${+__ariadne_ran} )) || typeset -gi __ariadne_ran=0
    autoload -Uz add-zsh-hook
    add-zsh-hook preexec __ariadne_preexec
    add-zsh-hook precmd __ariadne_precmd
  }
  return 0
fi

if [[ -n ${ARIADNE_SHIM_FAILED-} ]]; then
  if [[ $ARIADNE_SHIM_FAILED != nested && -t 1 ]]; then
    print -rn -- $'\e]2;[ariadne inaktiv]\a'
  fi
  return 0
fi

# Aussen: Shim starten, wenn alles passt. zsh kennt kein execfail, ein
# gescheitertes exec beendet die Shell. Darum vorher alles prüfen.
if [[ -t 0 && -t 1 && -n ${TERM-} && $TERM != dumb && -z ${ARIADNE_DISABLE-} ]] \
  && [[ ! -e ${XDG_CONFIG_HOME:-$HOME/.config}/ariadne/disable ]]; then
  () {
    local launcher=${${(%):-%x}:A:h}/launcher.sh
    local self=${${:-/proc/$$/exe}:A}
    [[ -f $launcher && -x $launcher && -x /bin/sh && -f $self && -x $self ]] || return 0
    exec "$launcher" "$self" -i
  }
fi
return 0
