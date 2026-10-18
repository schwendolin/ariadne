# Ariadne: HTTP-API der Web-Oberfläche (v2)

> **Verbindlich für den Bau v0.1-Server.** Stand 2026-10-17 (Phase 1, nach Prüfung überarbeitet: Peer-Bindung bei Weg B, `d.unit.distrust` über `/decisions`, Ereignisquellen). Ersetzt den Entwurf vom 2026-10-09 (v1). Grundlage sind die Entscheide vom 2026-10-15 (E22, E23, E26, E42, E45, E60, E72, E74, E86 bis E104), das [Konzept Fernzugriff](konzept-fernzugriff.md) (Regeln R1 bis R14, Tests T1 bis T16), die [Lösungsarchitektur](architektur.md) (7, 8.5, 8.6, 9.2), die Funktionsbeschreibung des Dashboards ([dashboard-funktionen.md](ui/dashboard-funktionen.md), Anhang B.4 und B.5) und der echte Datenbestand: `ingest/queries.py`, `ingest/schema_claims.py`, `ingest/schema_units.py`, `ingest/inputs.py`, `cli/views.py` und die ctl-Operationen in `daemon/core.py` und `daemon/ops_eval.py`.
>
> Das Dokument heisst «v2», weil sich das Modell gegenüber v1 grundlegend geändert hat (Daueraufnahme statt REC, Arbeitsliste «Als Nächstes» statt Inbox, Eingaben, Sitzungen mit Peer-Bindung). Der Pfad bleibt `/api/v1`; `GET /status` meldet `api_version: 2`. Später ist das OpenAPI-Schema der FastAPI-App der verbindliche Vertrag, und die UI erzeugt ihre Typen daraus (`openapi-typescript`). Die Svelte-Oberfläche (`webui/`) ändert sich in diesem Bau nicht; ihre Typen folgen dem Design des Nutzers.
>
> **Ergänzt im Bau v0.1-Oberfläche** (Phase 1, 2026-10-18): Abschnitt [18](#18-ergänzungen-für-die-oberfläche-v01) spezifiziert, was die Oberfläche nach Design v0.1 ([docs/ui/design-v01](ui/design-v01/README.md), E105 bis E118) braucht und API v2 noch fehlte: Vorlieben (E112), «Neu seit» (E106), Findings (E113), Denkanstösse aus Regeln (Architektur 6.1, E64, E68), «in die Kali kopieren» (E111), Quittieren der Scope-Warnung und additive Felder an bestehenden Antworten. Geänderte Stellen in den Abschnitten 9, 12 bis 16 tragen die Marke «Bau v0.1-Oberfläche». Alle Ergänzungen sind additiv; kein bestehendes Feld ändert Bedeutung oder Typ.

**Kennzeichnung pro Endpunkt**

| Marke | Bedeutung |
|---|---|
| **[v0.1]** | wird in diesem Bau gebaut und getestet |
| **[501 bis vX]** | hier spezifiziert, die Route antwortet in diesem Bau mit `501` und Code `not_implemented`; gebaut wird sie in Version X |
| **[vX]** | nur beschrieben, damit die Oberfläche Platz lässt; es gibt in diesem Bau keine Route (404) |

## Inhalt

1. [Grundregeln](#1-grundregeln)
2. [Gemeinsame Typen](#2-gemeinsame-typen)
3. [Anmeldung und Sitzung](#3-anmeldung-und-sitzung)
4. [Status, Pause, Präsentation](#4-status-pause-präsentation)
5. [Terminals und Kontext](#5-terminals-und-kontext)
6. [Projekt und Scope](#6-projekt-und-scope)
7. [Karte und Änderungen](#7-karte-und-änderungen)
8. [Hosts und Services](#8-hosts-und-services)
9. [Als Nächstes](#9-als-nächstes)
10. [Zeitachse und Eingaben](#10-zeitachse-und-eingaben)
11. [Belege](#11-belege)
12. [Entscheide](#12-entscheide)
13. [Suche, Warteliste, Aufdecken](#13-suche-warteliste-aufdecken)
14. [Ereignisstrom (SSE)](#14-ereignisstrom-sse)
15. [Später](#15-später)
16. [Offene Punkte](#16-offene-punkte)
17. [Präzisierungen aus dem Bau v0.1-Server](#17-präzisierungen-aus-dem-bau-v01-server)
18. [Ergänzungen für die Oberfläche v0.1](#18-ergänzungen-für-die-oberfläche-v01) (mit 18.12 Präzisierungen aus dem Bau)

## 1 Grundregeln

### 1.1 Transport und Sicherheit

Die Regeln R1 bis R3, R5 bis R8 und R12 aus dem Konzept Fernzugriff (5.4) und Architektur 7.2 gelten ohne Ausnahme. Es gibt keinen Schalter, der eine davon aufhebt.

| Thema | Regel | Regel-Nr. |
|---|---|---|
| Bindung | nur `127.0.0.1` oder `::1`, Standardport 7330 (`[ui] port` in `config.toml`, `0` nur für Tests). Jede andere Adresse lehnt die Konfiguration ab, der HTTP-Teil startet dann nicht (fail-closed), die Aufnahme läuft weiter. Nach dem Start prüft der Server `getsockname()`. Nur HTTP/1.1, kein TLS | R1, E89 |
| Peer | Jede TCP-Verbindung muss einem Socket desselben Benutzers gehören (UID über `/proc/net/tcp` bzw. `tcp6`), sonst wird sie ohne Antwort geschlossen. Jedes Token ist an einen Prozess gebunden (PID und Startzeit) und gilt nur, solange dieser lebt. **lokal** (Weg E): der Prozess hinter der Verbindung beim Tausch Code gegen Token (Browser in der Kali, gefunden über den Socket in `/proc/<pid>/fd`); jede spätere Verbindung muss zu genau diesem Prozess gehören. **über sshd** (Weg B): der sshd-Prozess der SSH-Verbindung, über die `ariadne remote serve code` den Code geholt hat; diese Verbindung trägt auch den Tunnel. Der sshd-Prozess ist nach dem Rechtewechsel nicht lesbar («nicht dumpable»), darum gilt: Eine Verbindung, deren Prozess lesbar ist, muss der gebundene sein; eine Verbindung ohne lesbaren Prozess wird nur bei einer sshd-Sitzung angenommen | R2 |
| Host | `Host` exakt `127.0.0.1:PORT`, `localhost:PORT` oder `[::1]:PORT`, sonst 421. Keine Ausnahme für `*.ts.net`, Tunnel-Dienste oder Lab-IPs | R3 |
| Fetch-Metadaten | `Sec-Fetch-Site` nur `same-origin` oder `none` (oder fehlend, etwa bei `curl`), sonst 403, auch für statische Dateien und `/api/v1/session`. Einzige Ausnahme (E115, **geändert im Bau v0.1-Server, Integration**): ein `GET` der SPA-Shell (`/`, `/index.html`, Routen ohne Dateiendung, nie `/api/` oder `/assets/`) als Navigation (`Sec-Fetch-Mode: navigate`, `Sec-Fetch-Dest: document`) auch von `cross-site` oder `same-site`, damit die Startdatei aus `file://` die Shell laden kann; liefert die App dafür etwas anderes als die Shell, antwortet der Server 403 | R12 |
| Origin | bei `POST`, `PUT`, `PATCH`, `DELETE` Pflicht und genau der eigene (`http://127.0.0.1:PORT`, bzw. der Wert passend zum `Host`), sonst 403 | R12 |
| Methoden | `OPTIONS` ergibt 405; kein CORS, nie `Access-Control-Allow-*` | R12 |
| Anmeldung | `Authorization: Bearer <token>` auf jeder Route unter `/api/v1` ausser `POST /api/v1/session`. Keine Cookies, darum kein CSRF. Ein Token in der URL (`?token=`) wird ignoriert (401). Tokenvergleich über den SHA-256 mit `hmac.compare_digest` | R6, R8 |
| Fehlversuche | zählen erst nach der Middleware: Eine Anfrage, die an Host, Fetch-Metadaten oder Origin scheitert, kann keine Codes sperren | R5 |
| Entsperren | gibt es über HTTP nicht, auch keine Passphrase-Felder. Hinweis der UI: «im Terminal `ariadne start` oder `ariadne unlock`» | R4, E74 |
| Logs | nur Metadaten (Methode, Routen-Name, Status, Dauer). Keine Pfadparameter, keine Query, keine Bodies, kein Token, kein Code | A 8.6 |

**Prüfreihenfolge** (verbindlich, T3 und T4 hängen daran): Peer-UID der Verbindung, `Host` (421), `Sec-Fetch-Site` (403), `OPTIONS` (405), `Origin` bei schreibenden Methoden (403), dann erst Route und Anmeldung (401, 429). Statische Dateien durchlaufen dieselben Prüfungen bis vor die Anmeldung.

**Header auf jeder Antwort**, auch auf 401, 403, 404, 421, 429, 501 und auf statischen Dateien:

```
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Cache-Control: no-store
```

Dazu `Content-Security-Policy`:

| Antwort | CSP |
|---|---|
| SPA-Shell (`index.html`) | `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'` |
| alles andere (API, Assets, Fehler) | `default-src 'none'; frame-ancestors 'none'; sandbox` |

`frame-ancestors` erbt nicht von `default-src` und steht deshalb überall ausdrücklich. Keine Fremdressourcen: keine Webfonts, keine CDN, keine `data:`-URIs. Die gebaute SPA unter `src/ariadne/web/static/` bleibt in diesem Bau, wie sie ist (Mock-Modus).

### 1.2 Format

- JSON in UTF-8, `Content-Type: application/json; charset=utf-8`. Ausser SSE, `log.txt` und `204` ist jede Antwort JSON, auch Fehler.
- **Zeitpunkte** als ISO-8601 in UTC mit Mikrosekunden: `"2026-10-08T12:02:11.123456Z"`. Wo die genaue Ordnung zählt, kommt zusätzlich `ts_ns` als Dezimalstring (Nanosekunden liegen über 2^53). Massgeblich ist die Shim-Zeit (E96).
- **Offsets** und Zeilennummern sind Ganzzahlen, Zeilen 0-basiert, Bereiche `[start, ende]` mit inklusivem Ende.
- Felder, die es nicht gibt, sind `null`, nie weggelassen.
- Unbekannte Felder in Anfragen lehnt der Server mit 422 ab (`extra="forbid"`). Anfragen über 1 MiB: 413.
- **Konfidenz** nur als Stufe `high | medium | low` (Grenzen 0.9 und 0.6).

### 1.3 Zieldaten und Secrets

Alles, was ein Ziel beeinflussen kann (Hostnamen, Banner, Titel, Versionen, Befehlstexte, Logzeilen, Dateinamen, Kontext-Labels), ist feindlich (E13):

- **Nur als JSON-String**, nie als HTML, Markdown oder URL zum Anklicken. Ziel-URLs stehen als Text da.
- **Steuerzeichen sichtbar**: Der Server ersetzt C0, C1, DEL, Bidi-, Zero-Width- und Tag-Zeichen in jedem String aus Zieldaten wie `term_safe` (`<ESC>`, `<BEL>`, `<U+202E>`) und setzt am Objekt `ctrl: true`. Die UI wendet `displaySafe()` trotzdem an (zweite Schicht, ändert sichtbaren Text nicht). Gekürzt wird nur, wo die Route es nennt; der volle Wert steht im Detail.
- **Secrets maskiert**: Secret-Werte als `"••••••••"` ohne Längenangabe. Klartext gibt es nur über eine ausdrückliche Aufdeck-Aktion für genau einen Wert (13.3), nur im Profil lab und nicht im Präsentationsmodus. Das gilt auch für Befehlstexte und daraus abgeleitete Titel (`CommandRef.text`, `UnitBrief.title`, `cmd` der Suche, `last_command` der Terminals, Gruppen der Arbeitsliste): Bekannte Secret-Werte, die ein Parser irgendwo als Secret erkannt hat (etwa ein NTLM-Hash in einem Pass-the-Hash-Befehl), stehen dort als `"••••••••"` (geändert im Bau v0.1-Server, Korrektur SEC-W1).
- **Eigene Secrets** (sudo-Passwort, Passphrase, Recovery-Code) ersetzt der Server an jedem Ausgang mit `Redactor.redact_json` (E72), auch in aufgedeckten Werten. Über HTTP gibt es sie nie im Klartext.
- **Präsentationsmodus** (Architektur 7.8): Der Server maskiert zusätzlich alle Secret-Bereiche in Logzeilen und Eingaben, in Befehlstexten auch den Text jedes Secret-Bereichs, den ein Parser in einer Prompt-Zeile gemeldet hat, und verweigert jedes Aufdecken (403 `policy`).
- **Eingaben ohne Echo** (E104) erscheinen als `"••••••••"`, mit `length: null` (Abschnitt 10.3).

### 1.4 Bezeichner

| Bezeichner | Form | Hinweis |
|---|---|---|
| `pid` | UUIDv7 des Projekts | jede projektbezogene Route prüft, dass `pid` das offene Projekt ist (sonst 409 `project_mismatch`) |
| `tid` | `terminal_id`, UUIDv7 | Kurz-ID für Anzeigen: die letzten 8 Zeichen (wie `ariadne status`) |
| `host_id`, `service_id` | stärkste Kennung: `ip:default/10.10.10.3`, `name:lame.htb`, `svc:ip:default/10.10.10.3\|tcp/445` | als letztes Pfadsegment einzeln kodiert (`encodeURIComponent`); Routen nutzen `{host_id:path}` |
| `claim_key` | 64 Hex-Zeichen | natürlicher Schlüssel eines Werts (`fact_id` in v1), übersteht Reparse |
| `item_key` | Text, z. B. `claim:<key>`, `conflict:<key>`, `ctx:<tid>@<off>`, `merge:<…>` | Eintrag in «Als Nächstes» |
| `group_ref` | `g` + 8 Hex | Gruppe in «Als Nächstes» (wie `ariadne confirm`) |
| `cmd_id`, `cmd_ref` | `<tid>@<offset>`, Kurzform `<8 Zeichen>@<offset>` | Befehl; `cmd_ref` wie `ariadne undo` |
| `unit_id` | Text | Einheit (Befehl, Segment, Datei) |
| `seq` | Ganzzahl | Journal-Sequenz einer Eingabe (`term.input`) oder eines Entscheids |
| `decision_id` | UUIDv7 | Entscheid im Journal |

### 1.5 Fehler

```ts
interface ApiErrorBody {
  error: {
    code: ApiErrorCode;
    message: string;        // fester deutscher Text pro Code, nie Zieldaten, nie Exception-Text
    detail?: { loc: (string | number)[]; type: string }[];   // nur bei 422, ohne Werte
  };
}
type ApiErrorCode =
  | 'unauthorized'      // 401 Token fehlt, abgelaufen, widerrufen, fremder Peer, Code unbekannt/abgelaufen/benutzt
  | 'forbidden'         // 403 Fetch-Metadaten oder Origin falsch
  | 'policy'            // 403 Profil oder Modus verbietet es (Aufdecken im Präsentationsmodus, kritischer Entscheid)
  | 'not_found'         // 404
  | 'method'            // 405 (auch OPTIONS)
  | 'no_project'        // 409 kein Projekt offen
  | 'project_mismatch'  // 409 pid ist nicht das offene Projekt
  | 'conflict'          // 409 Entscheid passt nicht mehr (verwaist, schon anders entschieden)
  | 'too_large'         // 413
  | 'host'              // 421 Host-Header falsch
  | 'validation'        // 422 Eingabe ungültig
  | 'locked'            // 423 gesperrt: im Terminal ariadne start oder ariadne unlock
  | 'rate_limited'      // 429 zu viele Code-Versuche, alle Codes ungültig
  | 'not_implemented'   // 501 kommt in einer späteren Version
  | 'unavailable'       // 503 Auswertung nicht bereit (Neubau läuft), später erneut
  | 'clipboard_tool'    // 503 kein xclip, xsel oder wl-copy in der Kali (18.10, Bau v0.1-Oberfläche)
  | 'clipboard_session' // 503 keine grafische Sitzung für die Zwischenablage (18.10)
  | 'internal';         // 500
```

Die UI übersetzt nur über `code`. Für jede Route unter `/api/v1/p/{pid}` gelten zusätzlich 401, 409 `no_project`/`project_mismatch` und 423 `locked`; sie stehen unten nicht jedes Mal dabei. Codes der ctl-Operationen bildet der Server so ab: `locked` → 423, `no_project` → 409, `not_found`/`unknown_terminal` → 404, `invalid` → 422, `policy` → 403, `conflict` und `project_changed` → 409 `conflict`, `no_ingest` → 503, alles andere → 500 `internal`. Die Meldung der ctl-Operation geht nie an den Browser (sie kann Zieldaten enthalten); es gilt der feste Text des Codes.

### 1.6 Paginierung und Grenzen

Listen mit möglicher Länge haben `limit` (Standard und Höchstwert pro Route) und einen undurchsichtigen `cursor` aus der vorigen Antwort (`next_cursor`, `null` am Ende). Ohne Paginierung liefern Listen höchstens die genannte Zahl und `truncated: true`.

### 1.7 SPA-Auslieferung

Pfade ausserhalb von `/api/` liefern Dateien aus `src/ariadne/web/static/` oder, für unbekannte Pfade ohne Dateiendung, die SPA-Shell `index.html` (History-Router: `/karte`, `/terminals`, `/zeitachse`, `/findings`, mit Query wie `?host=`). Nur `GET` und `HEAD`. Keine Verzeichnislisten, keine Symlinks ausserhalb von `static/`, `..` ergibt 404. Content-Type nur aus einer festen Tabelle (`.html`, `.js`, `.css`, `.svg`, `.png`, `.woff2`, `.json`), sonst `application/octet-stream`. Die URL enthält nie ein Token oder einen Code.

## 2 Gemeinsame Typen

Literale stammen aus `events.py`, `ontology.py`, `parsers/api.py`, `scope/api.py` und `daemon/core.py`.

```ts
// Erfassung (events.py, daemon/core.py)
type TermState = 'paused' | 'held' | 'on' | 'locked' | 'preroll' | 'off';   // Reihenfolge = Vorrang (A 3.6)
type StageKind = 'local' | 'su' | 'ssh' | 'winrm' | 'remote' | 'revshell' | 'msf' | 'meterpreter' | 'db' | 'unknown';
type StageSource = 'auto' | 'hotkey' | 'webui' | 'cli' | 'suggestion';
type GapReason = 'pause' | 'no_project' | 'daemon_down' | 'project_switch' | 'sensitive_output' | 'locked'
               | 'disk_low' | 'shim_error' | 'multiplexer' | 'buffer_overflow' | 'rec_off';
type Keystep = 'foothold' | 'privesc' | 'pivot' | 'loot';
type WorkStatus = 'open' | 'in_progress' | 'dead_end' | 'done' | 'out_of_scope';
type AccessLevel = 'none' | 'user' | 'admin';
type Profile = 'lab' | 'customer';

// Auswertung (schema_claims.py, parsers/api.py, scope/api.py)
type Trust = 'user' | 'structured' | 'tool_text' | 'heuristic' | 'ai' | 'ocr';
type Verdict = 'in' | 'out' | 'excluded' | 'outside_window' | 'unknown';
type ClaimState = 'candidate' | 'auto' | 'confirmed' | 'rejected';
type Lane = 'auto' | 'quiet' | 'decide' | 'user';             // Drei-Spuren-Regel (E42)
type ConfidenceLevel = 'high' | 'medium' | 'low';
type Knowledge = 'mentioned' | 'discovered' | 'scanned' | 'versions';
type Progress = 0 | 1 | 2 | 3 | 4 | 5;                         // rein abgeleitet (A 5.9)

interface StageView {                 // eine Stufe des Kontext-Stapels
  depth: number;                      // 0 = Kali
  kind: StageKind;
  host_id: string | null;             // Kennung, z. B. 'ip:default/10.10.10.5'
  host_label: string | null;          // Anzeige (Zieldaten)
  user: string | null;
  state: 'active' | 'suspended';
  source: StageSource;
  auto: boolean;                      // Host aus dem ersten Callback (E23), Anzeige «(auto)»
  candidate: string | null;           // Ziel-Kandidat aus argv, unbestätigt
  opened_at: number;                  // Offset im Strom
}

interface CommandRef {
  cmd_id: string;
  cmd_ref: string;                    // Kurzform für undo
  text: string | null;                // Befehlstext (Zieldaten möglich)
  started_at: string;
  ended_at: string | null;
  exit: number | null;
  src_ip: string | null;              // aus net.route
  origin: 'local' | 'remote_reconstructed';   // remote bestätigt erst ab v0.2
}

interface EvidenceRef {               // Sprung in die Belegansicht
  claim_key: string | null;
  unit_id: string | null;
  lines: [number, number] | null;
  label: string;
}

interface QuietCounts {               // stille Spur als Zähler (E42)
  heuristic: number; out_of_scope: number; mentions: number; system_accounts: number;
  own_address?: number;               // nur in der Projektsumme
}
```

## 3 Anmeldung und Sitzung

Der Code kommt nie aus dem Browser. Er entsteht im Daemon (ctl-Operation `ui.code`) und erreicht den Browser auf einem von zwei Wegen:

- **Weg E (Browser in der Kali):** `ariadne ui` schreibt eine Startdatei mit Rechten 0600 nach `$XDG_RUNTIME_DIR/ariadne/`, die auf `http://127.0.0.1:7330/#c=<code>` weiterleitet, öffnet sie und löscht sie nach 10 s. `ariadne ui --code` zeigt einen kurzen Tippcode im Terminal (vorher `pause_terminal`, damit er nicht in die Aufnahme kommt).
- **Weg B (Mac über Tailscale und SSH):** `ariadne-mac start` öffnet **eine** SSH-Verbindung für Tunnel und Code: `ssh -n -o ExitOnForwardFailure=yes -L 127.0.0.1:7330:127.0.0.1:7330 kali-sl code` (Forced Command `ariadne remote serve`, ohne Terminal: 128 Bit). `remote serve code` gibt den Code aus und hält die Verbindung offen, bis sie endet; der Code und das Token daraus sind an den sshd-Prozess genau dieser Verbindung gebunden (R2). Der Helfer schreibt die Startdatei (0600) in `$TMPDIR` des Macs, öffnet sie im normalen Standardbrowser (E93) und löscht sie nach 10 s. Von Hand: `ssh -t -L 127.0.0.1:7330:127.0.0.1:7330 kali-sl code` zeigt einen Tippcode und hält den Tunnel, bis Ctrl-C.

Das Fragment `#c=` geht nie an den Server. Die SPA liest es, entfernt es sofort per `history.replaceState` und tauscht den Code gegen ein Token, das nur in `sessionStorage` liegt.

Ein Code gilt nur auf seinem Weg: Ein lokaler Code (`ariadne ui`) nur von einem lesbaren Prozess der Kali (dem Browser), ein Code aus `remote serve code` nur über SSH (eine Verbindung, deren Prozess nicht lesbar ist oder der gebundene sshd-Prozess selbst), und das Token daraus nur, solange die SSH-Verbindung lebt, die den Code geholt hat. Ein Code auf dem falschen Weg ergibt 401 und zählt als Fehlversuch.

| Code | Form | Gültigkeit |
|---|---|---|
| lang (Startdatei) | 128 Bit, base64url, 22 Zeichen | 60 s, einmal |
| Tippcode | 10 Zeichen Crockford-Base32 (50 Bit), Anzeige `ABCDE-FGHJK`, ohne Bindestrich und Gross/klein tolerant | 120 s, einmal |

Nach **5 echten Fehlversuchen innerhalb einer Minute** werden alle offenen Codes ungültig; bis ein neuer Code erzeugt wird, antwortet `POST /session` mit 429. Anfragen, die schon an der Middleware scheitern, zählen nicht (R5, T4).

### POST /api/v1/session [v0.1]

Einzige Route ohne Bearer. Tauscht einen Code gegen ein Token und bindet es an den Peer-Prozess der Verbindung (R2).

```ts
interface SessionRequest { code: string }           // 8 bis 64 Zeichen [A-Za-z0-9_-]
interface SessionResponse {
  token: string;                                    // 256 Bit, base64url (43 Zeichen)
  expires_at: string;                               // höchstens 12 h (E92)
  session: SessionView;
}
interface SessionView {
  session_id: string;                               // kurze Kennung für Anzeige und Widerruf, nicht das Token
  origin: 'local' | 'sshd';                         // «lokal» oder «über sshd» (E60)
  created_at: string;
  expires_at: string;
}
```

Fehler: 401 `unauthorized` (unbekannt, abgelaufen, schon benutzt), 429 `rate_limited`, 422 `validation`.

### GET /api/v1/session [v0.1]

Die eigene Sitzung (`SessionView`) für die Kopfzeile («über sshd»). Fehler: 401.

### DELETE /api/v1/session [v0.1]

Abmelden: widerruft das eigene Token. Antwort 204 mit `Clear-Site-Data: "cache", "storage"` (leert auch `sessionStorage`). Offene SSE-Ströme dieser Sitzung enden sofort.

### Ende einer Sitzung

Ein Token gilt höchstens 12 h und endet zusätzlich bei `ariadne lock`, `ariadne stop`, `ariadne project close`, dem Leerlauf-Ende, einem Neustart des Daemons (Tokens liegen nur im Speicher, nur als SHA-256), `ariadne ui --revoke` bzw. `ssh kali-sl revoke`, `DELETE /session` und wenn der gebundene Prozess endet (lokal: der Browser-Prozess; über sshd: die SSH-Verbindung mit Tunnel und Code, also Tunnel zu oder Mac zugeklappt; der Server prüft das alle 2 s). Ein Projektwechsel mit `ariadne start <anderes>` beendet die Sitzung **nicht**; der Strom meldet `project`, und die UI verwirft alle Daten. Offene SSE-Ströme enden in allen Fällen innerhalb 1 s; die nächste REST-Anfrage ergibt 401. Die UI zeigt dann die Anmeldung ohne Grund (dashboard-funktionen 4.1).

`ariadne ui --sessions` zeigt jede Sitzung mit Herkunft (lokal oder über sshd), Prozess, Beginn, letzter Nutzung und Ablauf, nie das Token (R7).

## 4 Status, Pause, Präsentation

### GET /api/v1/status [v0.1]

Globaler Zustand für Kopfzeile, Aufnahme-Popover und die Zustände aus dashboard-funktionen 4.1. Funktioniert ohne Projekt und bei gesperrtem Projekt.

```ts
interface Status {
  version: string;                    // Ariadne-Version
  api_version: 2;
  server_time: string;
  session: SessionView;               // Herkunft der eigenen Sitzung (E60)
  operator: { exists: boolean; unlocked: boolean };
  project: ProjectBrief | null;       // offenes Projekt
  active: { slug: string; stopped: boolean; end_reason: 'stop' | 'idle' | 'missing' | null } | null;
  locked: boolean;                    // Tresor gesperrt (UI: «im Terminal ariadne start oder ariadne unlock»)
  recording: {                        // «2 von 3 Terminals nehmen auf»
    connected: number; on: number; paused: number; held: number; mux: number;
  };
  terminals: TerminalState[];         // Zustand pro Terminal, Reihenfolge wie ariadne status
  idle: { idle_s: number; end_after_s: number | null } | null;   // nur bei offenem Projekt
  preroll: {                          // Vorlauf und Ausfallpuffer im RAM (E95, E102)
    terminals: number; seconds: number; window_s: number;
    ask_terminals: number; ask_seconds: number;           // fragt ariadne start
    outage_terminals: number; outage_seconds: number;     // übernimmt start/unlock ohne Frage
  };
  presentation: boolean;
  llm: { mode: 'off' | 'local' | 'cloud'; model: string | null; available: boolean;
         budget: { month_limit_usd: number; month_used_usd: number } | null };   // v0.1: mode 'off'
  generation: number | null;          // Projektionsgeneration (für /changes)
  ingest: { active: boolean; last_error: string | null } | null;
  disk_low: boolean;                  // v0.1 immer false (Speicher-Wächter folgt)
  scope_warning: {                    // jüngster Befehl mit Ziel ausserhalb des Scopes (E67, Briefing 4.5);
    cmd_id: string; cmd_ref: string; terminal_id: string; ts: string;   // Kennzeichen bis zum Quittieren,
  } | null;                           // quittiert wird nur in der UI (bis ein neuerer kommt); null ohne Projekt
}
interface ProjectBrief {
  id: string; slug: string; name: string; profile: Profile; chain_head_ok: boolean;
}
interface TerminalState {
  terminal_id: string;
  short_id: string;                   // letzte 8 Zeichen
  tty: string | null;
  state: TermState;
  pause_until: string | null;         // nur bei 'paused'
  held_slug: string | null;           // nur bei 'held': Projekt der Remote-Sitzung
  preroll_s: number;                  // Sekunden im Vorlauf
  mux: boolean;                       // Multiplexer im Vordergrund
  context_label: string | null;       // «Kali › 192.168.56.101 [msf] (auto)»; Zieldaten
  ctrl: boolean;
}
```

Fehler: 401.

### POST /api/v1/terminals/{tid}/pause [v0.1]

Pause pro Terminal (ctl `term.pause` mit `source = webui`, E22). `tid = all` pausiert alle verbundenen Terminals.

```ts
interface PauseRequest { minutes?: number }   // Standard 10, höchstens 30
// Antwort 202
interface Accepted { accepted: true }
```

Eine Pause über 30 Minuten gibt es über das Web nicht (Briefing 9.10, kritische Operation): 403 `policy`; im Terminal geht sie mit `ariadne pause --minutes N` (bis 240). Das gilt auch für die Summe: Pro Terminal zählt der Daemon die Web-Pausen der letzten Stunde (bis zum Ende der neuen Pause); mehr als 30 Minuten darin ergeben ebenfalls 403 `policy`, auch über Verlängern oder `resume` und neue Pause. Eine Pause oder Fortsetzung im Terminal (Hotkey, CLI) setzt diese Summe zurück (geändert im Bau v0.1-Server, Korrektur F9). Den neuen Zustand zeigt die UI erst nach dem SSE-Ereignis `terminal` (bis dahin «wartet auf Bestätigung»; nach 5 s ohne Ereignis lädt sie `/status`). Fehler: 404 (Terminal unbekannt), 422.

### POST /api/v1/terminals/{tid}/resume [v0.1]

Pause aufheben (ctl `term.resume`, `source = webui`). Antwort 202. Fehler: 404.

### PUT /api/v1/presentation [v0.1]

Präsentationsmodus global (ctl `presentation`). Request `{ on: boolean }`, Antwort 202; Bestätigung per SSE `presentation` an alle Sitzungen. Maskiert wird auf dem Server (1.3).

## 5 Terminals und Kontext

### GET /api/v1/terminals [v0.1]

Alle verbundenen Terminals mit Kontext-Stapel. Ein Terminal, das an ein anderes Projekt gebunden ist (`held`), erscheint nur mit `held_slug`, ohne Stapel und ohne letzten Befehl (Projekte mischen sich nie, E70).

```ts
interface TerminalsResponse { terminals: Terminal[] }
interface Terminal extends TerminalState {
  shell: string | null;
  connected: boolean;
  stack: StageView[];                 // unten immer Kali; leer bei 'held'
  last_command: CommandRef | null;    // null bei 'held'
  remote_segment: { since: string; lines: number } | null;   // «Remote-Segment seit 16:45:12 · 41 Zeilen»
  suggestion: ContextSuggestion | null;                      // offener Kontextvorschlag (E23)
}
interface ContextSuggestion {
  item_key: string;                   // Eintrag in «Als Nächstes»
  from_off: number;
  host_id: string; host_label: string;
  reason: string;                     // «Callback von 192.168.56.101 (nc:4445)»; Zieldaten
}
```

### POST /api/v1/terminals/{tid}/context [v0.1]

Kontext setzen, auch rückwirkend; Stufe öffnen oder schliessen; Vorschlag übernehmen. Der Server schreibt über die ctl-Operationen `ctx.set`, `ctx.push`, `ctx.pop` mit `source = webui` die Entscheide `d.ctx.set`, `d.ctx.push`, `d.ctx.pop` (Herkunft `webui`). `from_off` setzt rückwirkend ab diesem Offset; der Live-Stapel ändert sich nur, wenn der Offset in der obersten Stufe liegt. Für ein beendetes Terminal geht nur ein rückwirkendes `set`.

```ts
type ContextOp =
  | { op: 'set'; host?: string | null; user?: string | null; kind?: StageKind; from_off?: number }
  | { op: 'push'; kind?: StageKind; host?: string | null; user?: string | null }
  | { op: 'pop' }
  | { op: 'accept'; item_key: string };      // Kontextvorschlag: set mit host und from_off des Vorschlags
// Antwort 200
interface ContextResult {
  stored: boolean;                    // false: kein Projekt offen oder Terminal nimmt nicht auf (nur Stapel)
  stack: StageView[] | null;
  warnings: { code: 'scope_out' | 'scope_excluded' | 'scope_unknown' | 'host_unknown'; host: string }[];
}
```

`host` ist eine IP oder ein Name; der Server normalisiert (`ip:default/…`, `name:…`), löst nie per DNS auf und warnt, wenn der Host ausserhalb des Scopes liegt, ausgeschlossen, unbekannt im Scope oder noch nicht als Host bekannt ist. Fehler: 404 (Terminal oder Vorschlag unbekannt), 422 (`pop` auf Kali, nichts zu setzen, `from_off` in der Zukunft), 409 `conflict` (Vorschlag schon entschieden).

## 6 Projekt und Scope

### GET /api/v1/p/{pid}/project [v0.1]

```ts
interface ProjectView extends ProjectBrief {
  created_at: string;
  scope: { include: string[]; exclude: string[]; version: number };   // Eingaben des Nutzers
  lab_guard: { public_targets: boolean; confirmed_not_customer: boolean } | null;
  started_at: string | null;          // erste Aufnahme
  chain: { head_seq: number; head_hash: string; head_ok: boolean };
}
```

Scope ändern und «Das ist kein Kundenauftrag» gehen in v0.1 nur im Terminal (12.2).

## 7 Karte und Änderungen

### GET /api/v1/p/{pid}/graph?layers= [v0.1]

Graph für die Karte (Architektur 7.5, Briefing 5.1). `layers` ist eine Komma-Liste aus `topology` (immer), `services`, `thread`, `oos`, `fog`; Standard alle. Linse nur `karte` (der Faden als Linse folgt in v0.2).

```ts
interface GraphView {
  project_id: string;
  generation: number;
  nodes: (KaliNode | SegmentNode | HostNode | ServiceNode)[];
  edges: (ThreadEdge | MemberEdge)[];
  oos: { total: number; items: OosItem[] };          // Out-of-Scope-Rand, höchstens 200 Einträge
  summary: {                                         // Lagebild «3 Hosts, 1 im Nebel · 1 mit Zugriff»
    hosts: number; fog: number; with_access: number; services: number; conflicts: number;
  };
  table_only: boolean;                               // ab 200 Hosts: Karte als Tabelle (E50)
}
interface KaliNode { kind: 'kali'; id: 'kali'; label: 'Kali'; addresses: string[] }   // eigene Adressen, nie Host
interface SegmentNode {
  kind: 'segment'; id: string;        // 'seg:192.168.56.0/24'
  cidr: string; label: string;
  origin: 'scope' | 'observed';       // aus dem Scope gezeichnet oder aus Adressen ohne Scope-Netz
}
interface HostNode {
  kind: 'host'; id: string;           // host_id
  segment: string | null;
  label: string; ctrl: boolean;       // Zieldaten
  addresses: string[]; names: string[];
  claim_state: ClaimState;            // 'candidate' = Nebel
  knowledge: Knowledge; access: AccessLevel; work: WorkStatus; work_reason: string | null;
  progress: Progress;
  os: string | null;
  services_total: number;
  service_classes: { web: number; smb: number; db: number; remote: number; file: number; mail: number; other: number };
  conflicts: number;
  auto: boolean;                      // mindestens ein Wert der Spur «auto»
  ai: boolean;                        // v0.1 immer false
  on_thread: boolean;
  hint: 'conflict' | 'ai' | 'services' | null;      // genau ein Hinweis (E87)
  tags: string[];
}
interface ServiceNode {
  kind: 'service'; id: string; host: string;
  proto: 'tcp' | 'udp'; port: number;
  name: string | null; product: string | null; version: string | null; ctrl: boolean;
  class: 'web' | 'smb' | 'db' | 'remote' | 'file' | 'mail' | 'other';
  state: 'open' | 'filtered' | 'closed' | null;
  claim_state: ClaimState; conflicts: number;
}
interface ThreadEdge {                // der Faden: Schlüsselschritte in Reihenfolge
  kind: 'thread'; id: string; seq: number;          // ab 1
  step: Keystep; source: string; target: string;    // gleich bei Schritten auf demselben Host (Schleife)
  ts: string; note: string | null; decision_id: string | null;
}
interface MemberEdge { kind: 'member'; id: string; source: string; target: string }   // Host im Segment
interface OosItem {
  identifier: string; label: string; ctrl: boolean;
  verdict: 'out' | 'excluded' | 'outside_window' | 'unknown';
  rule: string | null; mentions: number;
  first_unit: string | null;          // Beleg
}
```

Regeln: Hosts mit Urteil ungleich `in` erscheinen nie als Knoten, nur in `oos` (Einschluss wird nie vererbt). Eigene Adressen von Kali erscheinen nie als Host (E42). `fog` liefert Kandidaten im Scope; ohne `fog` fehlen Knoten mit `claim_state = 'candidate'`. Kanten zeigen nur auf Knoten derselben Antwort. Fehler: 422 (unbekannte Ebene).

### GET /api/v1/p/{pid}/changes?since= [v0.1]

Änderungen seit einer Generation (Architektur 5.10, Tabelle `projection_delta`). Die UI ruft das nach jedem SSE-Ereignis `changes` auf.

```ts
interface ChangeSet {
  project_id: string; from: number; to: number;
  reset: boolean;                     // since zu alt oder mehr als 5000 Änderungen: alles neu laden
  changes: { generation: number; entity: 'host' | 'service' | 'claim' | 'inbox' | 'keystep' | 'unit'
                                   | 'credential' | 'url' | 'other' | 'finding';   // Bau v0.1-Oberfläche: wie projection_delta
             entity_key: string; change: 'added' | 'updated' | 'removed' }[];
}
```

Fehler: 422 (`since` fehlt oder negativ).

### GET, PUT /api/v1/p/{pid}/ui/positions [v0.1]

Knotenpositionen der Karte pro Projekt (in `state.db`, ausserhalb der Hash-Kette, kein Entscheid). `PUT` mit `{ positions: Record<node_id, { x: number; y: number }> }`, höchstens 5000 Einträge, endliche Zahlen; Antwort 202. `GET` liefert `{ positions, updated_at }`. Fehler: 422.

## 8 Hosts und Services

### GET /api/v1/p/{pid}/hosts [v0.1]

Host-Tabelle (ab 200 Knoten statt der Karte). Grundlage `queries.hosts`.

```ts
interface HostsResponse { hosts: HostSummary[] }
interface HostSummary extends Omit<HostNode, 'kind'> {
  first_seen: string | null; last_seen: string | null;
  quiet: QuietCounts;                 // «+27 Systemkonten», Erwähnungen, Werte ausserhalb
}
```

### GET /api/v1/p/{pid}/hosts/{host_id} [v0.1]

Host-Detail für die rechte Spalte (Briefing 5.3).

```ts
interface HostDetail extends HostSummary {
  identifiers: { key: string; label: string; type: string; verdict: Verdict; rule: string | null; ctrl: boolean;
                 punycode: string | null }[];   // pro Kennung mit Scope-Urteil
  services: ServiceView[];
  facts: Fact[];                      // Werte des Hosts und seiner Services (Secrets maskiert)
  conflicts: Conflict[];
  open_items: string[];               // item_keys in «Als Nächstes» zu diesem Host
  thread: ThreadEdge[];               // Faden-Schritte dieses Hosts
  note: string | null;                // Markdown-Text ohne HTML (Zieldaten-frei, aber als Text behandeln)
  commands: (CommandRef & { terminal_id: string; unit_id: string })[];   // Befehle in diesem Kontext, neueste 50
}
interface Fact {
  claim_key: string;
  subject: string; subject_label: string;
  predicate: string;                  // ontology.py
  value: string; ctrl: boolean;       // Secret: '••••••••'
  is_secret: boolean;
  state: ClaimState; lane: Lane; lane_reason: string | null;
  confidence: ConfidenceLevel; trust: Trust; parser: string | null;
  from_target: boolean; suspect: boolean;
  verdict: Verdict | null;
  sources: number;
  first_seen: string | null; last_seen: string | null;
  conflict_key: string | null;
  history: boolean;                   // durch einen genaueren oder neueren Wert abgelöst (E45)
}
interface Conflict {
  conflict_key: string; subject: string; subject_label: string; predicate: string;
  state: 'open' | 'resolved' | 'kept_open';
  values: { claim_key: string; value: string; ctrl: boolean; sources: number; trust: Trust; state: ClaimState }[];
  choice: string | null;
}
```

Fehler: 404.

### GET /api/v1/p/{pid}/services?host=&class= [v0.1]

```ts
interface ServicesResponse { services: ServiceView[] }
interface ServiceView {
  service_id: string; host_id: string; host_label: string;
  proto: 'tcp' | 'udp'; port: number;
  name: string | null; product: string | null; version: string | null; ctrl: boolean;
  class: ServiceNode['class'];
  state: 'open' | 'filtered' | 'closed' | null;
  claim_state: ClaimState; verdict: Verdict | null; work: WorkStatus | null;
  conflicts: number; cves: string[];
  history: { predicate: 'service.state' | 'service.version' | 'service.product' | 'service.name';
             value: string; ctrl: boolean; until: string | null; claim_key: string }[];
             // Verlauf: Samba '3.X - 4.X' -> '3.0.20-Debian', 445 open -> filtered (E45)
}
```

### Credentials [501 bis v0.2]

`GET /api/v1/p/{pid}/credentials`, `GET …/cred-matrix`, `POST …/credentials/{id}/copy`: In v0.1 erzeugt kein Parser Credentials (Briefing 5.10). Modelle wie in v1 (`CredentialView`, `CredMatrix`); «Kopieren ohne Anzeigen» geht nur in die Zwischenablage der Kali (R14), nie an den Browser.

## 9 Als Nächstes

### GET /api/v1/p/{pid}/next [v0.1]

Die Arbeitsliste (E86, Briefing 5.2). Ersetzt `/inbox` und `/suggestions` aus v1. Grundlage `queries.inbox` und `queries.quiet_summary`.

```ts
interface NextView {
  clarify: NextItem[];                // «Klären»: Spur «entscheiden» (E42), älteste zuerst
  confirm: NextGroup[];               // «Bestätigen»: nur Profil customer (v0.3); im Profil lab leer
  suggestions: Suggestion[];          // «Denkanstösse» aus Regeln, nur offene (18.6, Bau v0.1-Oberfläche)
  suggestions_available: boolean;     // true, sobald die Regel-Engine läuft (18.6)
  quiet: QuietCounts;                 // stille Summe «21 Werte ausserhalb des Scopes, 2 Erwähnungen»
  open: number;                       // offene Einträge in clarify (für die Zahl im Kopf)
}
type NextItem =
  | { kind: 'decide_value'; item_key: string; group_ref: string; ts: string;
      fact: Fact; reason: 'important_heuristic' | 'offered' | 'suspect' | 'ai' | 'ocr' | string;
      unit: UnitBrief | null }
  | { kind: 'conflict'; item_key: string; ts: string; conflict: Conflict }
  | { kind: 'ctx_unknown'; item_key: string; ts: string;
      terminal_id: string | null; from_off: number | null; stage_kind: StageKind | null;
      candidate: string | null; units: number; unit: UnitBrief | null }   // Datei ohne Host: unit gesetzt
  | { kind: 'ctx_suggestion'; item_key: string; ts: string;
      terminal_id: string; from_off: number; stage_kind: StageKind | null; units: number;
      suggested_host: string; suggested_label: string; reason: string; claim_key: string | null }
  | { kind: 'merge_suggestion'; item_key: string; ts: string;
      identifiers: { key: string; label: string; verdict: Verdict | null }[]; shared: string; reason: string }
  | { kind: 'orphan_decision'; item_key: string; ts: string;
      decision_id: string; decision_kind: string; reason: string; ref: string | null }
  | { kind: 'mass_find'; item_key: string; ts: string; unit: UnitBrief; hosts: number; candidates: number };
interface NextGroup {                 // Profil customer: Gruppe pro Befehl mit Sammelbestätigung
  group_ref: string; title: string; unit: UnitBrief | null;
  items: Extract<NextItem, { kind: 'decide_value' }>[];
  summary: { hosts: number; services: number; other: number; out_of_scope: number; low_confidence: number };
}
interface UnitBrief {
  unit_id: string; kind: 'command' | 'segment' | 'file';
  cmd_id: string | null; cmd_ref: string | null;
  title: string; ctrl: boolean;       // Befehlstext oder Dateiname (Zieldaten)
  terminal_id: string | null; parser: string | null; ts: string | null;
}
```

Aktionen gehen über `POST /decisions` (12) bzw. `POST /terminals/{tid}/context` mit `op: 'accept'` (5). Fehler: keine ausser den allgemeinen.

**Bau v0.1-Oberfläche:** `Suggestion` ist in 18.6 definiert; `ctx_suggestion` und `ctx_unknown` tragen zusätzlich `terminal: TermRef | null`, `from_ts` und `excerpt` (18.8). Die UI lädt `/next` nach den Ereignissen `inbox`, `suggestion` und `changes` (gebündelt, höchstens alle 250 ms).

## 10 Zeitachse und Eingaben

### GET /api/v1/p/{pid}/timeline?types=&terminal=&host=&cursor=&limit= [v0.1]

Alles in einer Liste über alle Terminals, sortiert nach Shim-Zeit (E96: Rang des Systemstarts, monotone Uhr, Terminal, Offset), neueste zuerst. `limit` Standard 200, höchstens 1000. `types` filtert (Komma-Liste der `type`-Werte), `terminal` nach `terminal_id`, `host` nach `host_id`.

```ts
interface TimelinePage { items: TimelineItem[]; next_cursor: string | null }
type TimelineItem = { id: string; ts: string; ts_ns: string; terminal_id: string | null;
                      context_label: string | null; host_id: string | null; ctrl: boolean } & (
  | { type: 'command'; cmd: CommandRef; unit_id: string;
      adopted: number;                // «N Werte übernommen» (Spur auto aus dieser Evidenzgruppe)
      distrusted: { decision_id: string; rejected: number; weakened: number } | null;   // misstraut, aufhebbar
      scope_warning: { targets: { value: string; verdict: Verdict }[] } | null;          // Scope-Warnung (E67)
      flags: ('partial' | 'truncated' | 'gap' | 'altscreen' | 'marker_forged')[];
      files: { unit_id: string; path: string }[];   // vom Befehl geschriebene Dateien
      lines: number }
  | { type: 'segment'; unit_id: string; lines: number; state: 'open' | 'provisional' | 'final' }   // remote, «rekonstruiert»
  | { type: 'file'; unit_id: string; path: string; cmd_id: string | null }
  | { type: 'keystep'; step: Keystep; host_label: string | null; note: string | null; ordinal: number }
  | { type: 'context'; change: 'set' | 'push' | 'pop' | 'auto'; stack_label: string; source: StageSource }
  | { type: 'decision'; decision_id: string; kind: string; summary: string }   // «Widerspruch gelöst», «Rückgängig: …»
  | { type: 'gap'; reason: GapReason; until: string | null; bytes_lost: number }   // «Pause 16:50 bis 17:00»
  | { type: 'project'; change: 'start' | 'end' | 'preroll'; reason: string | null; detail: string | null }
  | { type: 'input'; input: InputView }
);
```

- Remote-Segmente heissen nie «ausgeführt», sondern «rekonstruiert» (Architektur 5.13); einzelne Remote-Befehle folgen in v0.2.
- `adopted` kann sich nach einer Neuauswertung ändern (gemessen 141, 139, 140).
- Eingaben (`type = 'input'`) liefert die Zeitachse nur mit `types=input` oder `types=…,input`; Standard ist ohne Eingaben, weil jede Eingabe sonst doppelt neben ihrem Befehl stünde.

Fehler: 422.

### 10.2 GET /api/v1/p/{pid}/inputs?terminal=&limit= [v0.1]

Eingaben (E26) nach E104, älteste zuerst, die neuesten `limit` (Standard 200, höchstens 1000). Grundlage `ingest.inputs.collect_inputs` über `IngestService.query_journal`.

```ts
interface InputsResponse { items: InputView[] }
interface InputView {
  seq: number;                        // Journal-Sequenz (für Aufdecken)
  terminal_id: string;
  stream_off: number; out_end: number;
  ts: string; ts_ns: string;
  length: number | null;              // Bytes; null, solange hidden und nicht aufgedeckt (geändert im Bau v0.1-Server, Korrektur SEC-W3)
  paste: boolean;
  redacted: boolean;                  // Body geschwärzt (ariadne redact)
  hidden: boolean;                    // ohne Echo: nur verdeckt
  reason: 'tty_no_echo' | 'no_echo_seen' | 'no_output' | null;
  revealed: boolean;                  // nur in der Antwort von reveal
  text: string;                       // '••••••••' wenn hidden, sonst sichtbar gemachter Text ohne Enter
}
```

### 10.3 Eingaben ohne Echo (E104)

- **Gespeichert wird immer alles** (`term.input`, verschlüsselt).
- **Verdeckt** wird eine Eingabe, wenn der Shim beim Tippen den Passwortmodus des Kindes sah (`ECHO` aus, `ICANON` an, Feld `no_echo` am Event), wenn die getippten druckbaren Zeichen in der Ausgabe ab dem ersten getippten Byte bis kurz nach dem Enter nicht wieder erscheinen (Remote-Shells), oder wenn diese Ausgabe fehlt (Lücke). Kurze Wörter zählen nur als Echo, wenn sie eine angezeigte Zeile beenden oder direkt vor dem Cursor stehen, als die Zeile endete (rechter Prompt, Vorschläge rechts vom Cursor); ein Tab gilt als Platzhalter für die Vervollständigung (ein Wort ohne Leerzeichen). Lieber zu viel als zu wenig verdecken.
- **Aufdecken** nur ausdrücklich und einzeln (13.3). Die CLI hat dasselbe: `ariadne show inputs` und `ariadne show inputs --reveal NR`.

## 11 Belege

### GET /api/v1/p/{pid}/facts/{claim_key}/sources [v0.1]

Belegansicht (Architektur 7.6, E12): zu einem Wert jede Stelle, aus der er stammt.

```ts
interface FactSources { fact: Fact; sources: SourceView[] }
type SourceView =
  | { t: 'stream'; unit_id: string; terminal_id: string; cmd: CommandRef | null;
      context: StageView[];           // Stapel zum Zeitpunkt
      lines: [number, number] | null; // Zeilen in der Einheit
      parser: string; trust: Trust; confidence: ConfidenceLevel;
      flags: string[];                // 'truncated', 'partial', 'remote_reconstructed'
      distrusted: boolean }
  | { t: 'file'; unit_id: string; path: string; sha256: string | null; lines: [number, number] | null;
      parser: string; trust: Trust; produced_by_cmd: string | null }
  | { t: 'user'; decision_id: string; kind: string; ts: string };
```

Fehler: 404.

### GET /api/v1/p/{pid}/units/{unit_id} [v0.1]

Kopf einer Einheit für die Belegansicht: `UnitBrief` plus `exit`, `started_at`, `ended_at`, `duration_ms`, `src_ip`, `context: StageView[]`, `line_count`, `flags`, `chain_ok` (Kettenkopf beim Öffnen geprüft). Fehler: 404.

### GET /api/v1/p/{pid}/units/{unit_id}/lines?from=&count=&reveal_hidden= [v0.1]

Bereinigte Logzeilen (Tabelle `unit_line`) für die virtuelle Liste. `count` Standard 400, höchstens 2000.

```ts
interface LinesPage { unit_id: string; total: number; from: number; lines: LogLine[] }
interface LogLine {
  n: number;                          // Zeile in der Einheit
  text: string;                       // ohne ANSI und OSC, Steuerzeichen sichtbar (1.3)
  ctrl: boolean;
  sgr: { col_start: number; col_end: number; fg: string | null; bg: string | null; bold: boolean }[];
  prompt_echo: boolean;               // Bereich A bis C
  concealed: boolean; overwritten: boolean;    // ohne reveal_hidden durch Platzhalter ersetzt
  masked: { col_start: number; col_end: number; kind: string }[];   // vom Server verdeckt (Secrets, eigene Secrets)
}
```

Farben als Namen (`red`, `bright_red`). Bekannte Secrets (Tabelle `secret_value`) und eigene Secrets ersetzt der Server immer durch `••••••••` (in `masked` vermerkt), im Präsentationsmodus zusätzlich alle Secret-Bereiche. Fehler: 404, 422.

### GET /api/v1/p/{pid}/units/{unit_id}/log.txt [v0.1]

«Ganzes Log» als Text mit sichtbar gemachten Escapes, `Content-Type: text/plain; charset=utf-8`, `Content-Disposition: attachment; filename="<unit-kurz-id>.txt"` (Dateiname nie aus Zieldaten), Secrets wie bei `/lines` ersetzt. Rohbytes gibt es nicht über HTTP.

### GET /api/v1/p/{pid}/blobs/{blob_id} [501 bis v0.2]

Bilder (Screenshots). Nur `image/png`, `image/jpeg`, `image/webp` nach Neukodierung; alles andere als `application/octet-stream` mit `attachment`. Nie SVG, nie HTML.

## 12 Entscheide

### POST /api/v1/p/{pid}/decisions [v0.1]

**Einziger allgemeiner Schreibweg** (Architektur 7.1). Jede Aktion ist ein Entscheid in Schicht 3 mit Operator-ID, UTC und Herkunft `webui`; der Server setzt diese Felder selbst. Mehrere Entscheide gehen in einer Transaktion: alle oder keiner. Die Nutzlast prüft der Server mit `events.validate_header`.

```ts
interface DecisionRequest { decisions: DecisionInput[] }      // 1 bis 500
interface DecisionInput { kind: DecisionKind; payload: object; client_ref?: string }   // client_ref: UUID der UI
// Antwort 201
interface DecisionResponse { results: { decision_id: string | null; seq: number | null; client_ref: string | null;
                                       effect: { rejected: number; weakened: number } | null }[] }   // effect nur bei d.unit.distrust
```

`client_ref` macht Wiederholungen idempotent (derselbe Wert innerhalb von 10 Minuten liefert das frühere Ergebnis). «Alle oder keiner»: Der Server prüft zuerst jede Nutzlast (`events.validate_header`) und jeden Bezug (Claim, Konflikt, Entscheid, Befehl) gegen den Stand der Auswertung und reiht erst danach alle Entscheide ein; sie gehen in einem Commit ins Journal. Unmittelbar vor dem Einreihen prüft er noch einmal, dass `pid` das offene Projekt ist (E70). Auf jeden erfolgreichen Entscheid folgen die SSE-Ereignisse `changes` und, bei Wirkung auf die Arbeitsliste, `inbox`; die UI aktualisiert sich über sie, nicht über die Antwort.

| `kind` | Nutzlast (events.py) | UI-Aktion | Stand |
|---|---|---|---|
| `d.claim.confirm`, `d.claim.reject` | `{ claim_key, reason? }` | Annehmen `a`, Verwerfen `x` | [v0.1] |
| `d.claim.edit` | `{ claim_key, value }` | Ändern `e` | [v0.1] |
| `d.conflict.resolve` | `{ conflict_key, choice?, keep_open? }` | Wert wählen oder bewusst offen lassen (nie verwerfen) | [v0.1] |
| `d.entity.merge`, `d.entity.split` | `{ identifiers: string[2..], reason? }` | zusammenführen, trennen | [v0.1] |
| `d.status.work` | `{ subject, value: WorkStatus, reason? }` | Arbeitsstand, Sackgasse mit Grund | [v0.1] |
| `d.status.access` | `{ subject, value: AccessLevel }` | Zugriff übersteuern | [v0.1] |
| `d.note.set` | `{ subject, text }` (bis 100 000 Zeichen) | Notiz (Markdown ohne HTML) | [v0.1] |
| `d.tag.add`, `d.tag.remove` | `{ subject, tag }` (bis 64 Zeichen) | Tags | [v0.1] |
| `d.terminal.label` | `{ terminal_id, label }` (bis 64 Zeichen) | Terminal umbenennen | [v0.1] |
| `d.keystep.mark` | `{ step, host?, note? }` (ohne Terminal-Offset) | Schlüsselschritt im Host-Detail | [v0.1] |
| `d.revoke` | `{ decision_id, reason? }` | Rückgängig eines Entscheids, auch Aufheben von «Rückgängig pro Befehl» | [v0.1] |
| `d.unit.distrust` | `{ cmd_id, reason? }`; `cmd_id` voll oder als `cmd_ref`; **allein** in der Anfrage | Rückgängig pro Befehl (E42); Ergebnis mit `effect` | [v0.1] |
| `d.ctx.*` | nur über `POST /terminals/{tid}/context` | Kontext | [v0.1], hier 422 |
| `d.scope.update`, `d.lab.not_customer` | | kritisch: in v0.1 nur im Terminal | 403 `policy` |
| `d.automode.set` | | nur Profil customer | [v0.3] |
| `d.suggestion.done` | `{ suggestion_key, basis, reason? }` (`basis` Pflicht, 18.6) | Denkanstoss erledigt | [v0.1] (Bau v0.1-Oberfläche) |
| `d.suggestion.dismiss` | `{ suggestion_key, reason? }` | Denkanstoss verwerfen (bleibt verworfen) | [v0.1] (Bau v0.1-Oberfläche) |
| `d.finding.create`, `d.finding.update`, `d.finding.evidence.add`, `d.finding.evidence.remove`, `d.finding.delete` | 18.5 | Findings (E113) | [v0.1] (Bau v0.1-Oberfläche) |
| `d.finding` (alt, ohne Modell) | | ersetzt durch `d.finding.*` | 422 |
| `d.artifact`, `d.hypothesis`, `d.goal.status` | | Artefakte, KI-Hypothesen, Prüfziel-Status | [501 bis v0.2] |

Fehler: 422 `validation` (Schema, unbekannte Art, `d.ctx.*`), 409 `conflict` (Claim, Konflikt oder Entscheid unbekannt bzw. schon anders entschieden), 403 `policy`, 501.

### POST /api/v1/p/{pid}/decisions/confirm-group [v0.1]

Sammelbestätigung einer Gruppe (E88), wie `ariadne confirm g1a2b3c4d` (ctl `claim.confirm`, Herkunft `webui`). Request `{ group_ref: string }`. Der Server nimmt nur Werte im Scope, ohne KI- oder OCR-Quelle, Konfidenz mindestens 0.5, keine eigene Adresse, nicht im offenen Konflikt, kein Kontext, kein Merge, keine verdächtige Quelle.

```ts
interface ConfirmGroupResult {
  confirmed: number;
  excluded: Record<'own_address' | 'context' | 'out_of_scope' | 'conflict' | 'merge' | 'ai' | 'suspect' | 'low_confidence', number>;
}
```

Im Profil lab ist «Bestätigen» leer; die Route gibt es trotzdem. Fehler: 404 (Gruppe unbekannt).

### Rückgängig pro Befehl [v0.1]

`d.unit.distrust` geht wie jeder Entscheid über `POST /decisions`, aber allein in der Anfrage (sonst 422). Der Server löst `cmd_id` bzw. `cmd_ref` über die ctl-Operation `unit.distrust` mit Herkunft `webui` auf und schreibt damit den Entscheid; `effect` nennt «18 verworfen, 0 geschwächt». Aufheben mit `d.revoke` auf `decision_id`. Fehler: 404 (Befehl unbekannt), 409 `conflict` (aus diesem Befehl stammen keine Werte).

## 13 Suche, Warteliste, Aufdecken

### GET /api/v1/p/{pid}/search?q=&limit= [v0.1]

Volltextsuche über die aufgenommene Ausgabe (ohne Prompt-Echo), als Phrase; bekannte Secrets maskiert (`queries.search`). `q` 1 bis 200 Zeichen ohne Steuerzeichen (NUL, Tab, DEL: 422), `limit` Standard 50, höchstens 200. Treffer, deren Zeile die Phrase nur mit einem eigenen Secret enthält, fallen weg: Die Suche verrät so nie, ob ein geratenes Wort ein eigenes Secret ist (geändert im Bau v0.1-Server, Korrektur SEC-W4). Das Feld `cmd` ist wie jeder Befehlstext maskiert (1.3). Die Befehlspalette sucht Ansichten, Hosts und Befehle in den geladenen Daten selbst und ruft diese Route nur für den Rohlog.

```ts
interface SearchResult { items: { unit_id: string; line: number; text: string; ctrl: boolean;
                                  kind: string; context_label: string; host_id: string | null;
                                  cmd: string | null; ts: string }[]; truncated: boolean }
```

### GET /api/v1/p/{pid}/files/pending [v0.1]

Warteliste (Briefing 5.8, `list_pending`): `{ files: { path: string; reason: string; cmd_id: string | null; terminal_id: string | null; ts: string; ctrl: boolean }[] }`, höchstens 200. Übernehmen geht in v0.1 nur mit `ariadne import`.

### 13.3 POST /api/v1/p/{pid}/secrets/reveal [v0.1]

Einen einzelnen Secret-Wert aufdecken (E99, E104). Nur im Profil lab, nie im Präsentationsmodus (403 `policy`).

```ts
type RevealRequest =
  | { ref: 'input'; seq: number }           // Eingabe ohne Echo (E104)
  | { ref: 'claim'; claim_key: string };    // Secret-Wert eines Claims (Hash, Key), v0.1 selten
// Antwort 200
interface RevealResponse { value: string; ctrl: boolean }
```

Eigene Secrets (sudo-Passwort, Passphrase, API-Keys) gibt es über HTTP nie, auch nicht hier: Sie bleiben durch den Redaktor ersetzt. Der Server schreibt nichts davon ins Log. Fehler: 404, 403 `policy`.

**«In die Kali kopieren»** (E111, Bau v0.1-Oberfläche): `POST /api/v1/p/{pid}/secrets/copy` mit demselben Request, der Wert geht nie an den Browser (18.7).

## 14 Ereignisstrom (SSE)

### GET /api/v1/events [v0.1]

Ein globaler Strom pro Tab (löst den offenen Punkt «globaler Strom» aus v1). Er enthält **nie Daten oder Secrets**, nur Hinweise, was neu zu laden ist.

- `EventSource` kann keinen Bearer senden; die UI liest den Strom mit einem eigenen `fetch`-Client. Request-Header: `Authorization: Bearer`, `Accept: text/event-stream`, beim Wiederverbinden `Last-Event-ID`.
- Antwort: `Content-Type: text/event-stream`, `Cache-Control: no-store`, `X-Accel-Buffering: no`, dazu die Header aus 1.1.
- Jede Nachricht hat `id:` (aufsteigend pro Daemon-Lauf), `event:` und genau eine `data:`-Zeile mit einem JSON-Objekt.
- Der Server bündelt in 250-ms-Fenstern: ein nmap-Import ergibt ein `changes`, nicht 3000.
- Herzschlag alle 15 s als Kommentar `: hb`. Die UI verbindet neu, wenn 45 s nichts kommt (Backoff 1, 2, 4, 8, 16, 30 s mit 20 % Streuung).
- Ringpuffer der letzten 1000 Ereignisse für `Last-Event-ID`; liegt die ID ausserhalb, kommt zuerst `reset`.
- Der Strom endet sofort (innerhalb 1 s), wenn die Sitzung endet (3). Danach ergibt jede Anfrage 401.
- Höchstens 8 offene Ströme pro Sitzung; der neunte ersetzt den ältesten.

```
id: 1042
event: changes
data: {"project_id":"0199…","generation":43,"entities":{"host":1,"claim":3}}

: hb

```

| Ereignis | Daten | Reaktion der UI |
|---|---|---|
| `changes` | `{ project_id, generation, entities?: Record<string, number> }` (`entities` kann fehlen) | `GET /changes?since=<eigene Generation>`, dann gezielt nachladen, Neues einblenden |
| `terminal` | `{ terminal_id, change: 'opened' \| 'closed' \| 'state' \| 'context' \| 'command' }` | `/status`, `/terminals`, bei `command` die Zeitachse nachladen; erst jetzt Pause anzeigen |
| `inbox` | `{ project_id, open: number }` | `/next` nachladen |
| `suggestion` | `{ project_id, open: number }` | `/next` nachladen (Bau v0.1-Oberfläche: nach jeder Neuauswertung, wenn sich die Zahl offener Denkanstösse ändert, 18.9) |
| `prefs` | `{}` | `GET /ui/prefs` nachladen (Bau v0.1-Oberfläche, 18.2); kommt auch ohne Projekt |
| `project` | `{ project_id: string \| null, change: 'opened' \| 'closed' \| 'locked' \| 'unlocked', locked: boolean }` | **alle Daten verwerfen**, laufende Abrufe abbrechen, `/status` neu laden |
| `reset` | `{ reason: 'reparse' \| 'buffer' \| 'restart' }` (auch, wenn die Generation zurückspringt) | alles neu laden |
| `presentation` | `{ on: boolean }` | Kennzeichen, Logzeilen und offene Belege neu laden |
| `progress` | `{ job_id, kind, status, pct: number \| null, message: string \| null }` | v0.1 nur `reparse` (aus dem Daemon-Ereignis `job`; nach `done` folgt `reset` mit `reason: 'reparse'`); `message` ist fester deutscher Text, nie Ziel- oder Modelltext |

Der Strom läuft auch ohne Projekt und bei gesperrtem Projekt; dann kommen nur `terminal`, `project`, `presentation` und `prefs`.

## 15 Später

| Endpunkt | Zweck | Stand |
|---|---|---|
| `POST /p/{pid}/ai/denkanstoss` | KI-Denkanstoss auf Knopfdruck (Architektur 6.3): Lagebild, höchstens 4 Anstösse, Kosten, Ablehnung nie umformuliert; Job per SSE `progress` | [501 bis v0.1-KI] |
| `GET /p/{pid}/suggestions`, Denkanstösse aus Regeln | Regeln, Prüfziele, Befehlsvorlagen nur vom Server mit typisierten Platzhaltern (E68), Lernmodus | **[v0.1]** seit Bau v0.1-Oberfläche (18.6); Prüfziel-Status (`d.goal.status`) bleibt [501 bis v0.2] |
| `POST /p/{pid}/exports`, `GET …/exports` | Markdown-Export (Architektur 8.7), Vorlagen `cys` und `htb` | [501 bis v0.1-Export]; die UI zeigt den Dialog mit Hinweis, Knöpfe gesperrt |
| `POST /p/{pid}/screenshots` | Screenshot mit Countdown (`mode`, `delay_s`) | [501 bis v0.1-Screenshots]; die UI zeigt den Dialog mit Hinweis, Knöpfe gesperrt |
| `GET /p/{pid}/findings`, `GET /p/{pid}/findings/{finding_id}`, `d.finding.*` | Findings (Titel, Schwere, Belege, Massnahme, ATT&CK, CVE) | **[v0.1]** seit Bau v0.1-Oberfläche (18.5, E113) |
| `GET /p/{pid}/credentials`, `/cred-matrix`, `/credentials/{id}/copy` | Credentials, Matrix, Kopieren in die Kali-Zwischenablage | [501 bis v0.2]; «in die Kali kopieren» für einzelne Secret-Werte gibt es schon in v0.1 (18.7) |
| `POST /p/{pid}/query`, `POST …/ai/frage` | DSL-Abfragen, Fragen an die Karte (E61) | [501 bis v0.2] |
| `GET /p/{pid}/blobs/{id}` | Bilder | [501 bis v0.2] |
| Datei aus der Warteliste übernehmen (`d.file.accept`) | Knopf statt `ariadne import` | [v0.2] |
| Session abspielen, Export-Vorschau, Phasenzuordnung | | [v0.2] bis [v0.4] |

Jede Route mit Marke «501» existiert in diesem Bau, durchläuft dieselbe Middleware und Anmeldung und antwortet dann `501 { error: { code: 'not_implemented', message: 'Kommt in einer späteren Version.' } }`.

## 16 Offene Punkte

1. **Kritische Operationen** (Architektur 7.2.7, Briefing 9.10): Scope erweitern, «kein Kundenauftrag», Klartext-Export, Pause über 30 Minuten. v0.1 antwortet 403 `policy` und verweist ins Terminal. Ein zweiter Kanal (Dialog auf dem Kali-Desktop mit Anzeige des anfragenden Prozesses) ist offen.
2. **Eigene Secrets aufdecken** (E99): über HTTP nie (13.3). Ob die UI sie überhaupt zeigen soll oder nur ihre Labels, entscheidet der Nutzer.
3. **Bezugspunkt «Neu seit»** (Briefing 13.1, Frage 2): **erledigt** im Bau v0.1-Oberfläche mit `GET`/`PUT /p/{pid}/ui/seen` in `state.db` (18.3, E106).
4. **Mehrere Tabs**: je ein Strom (höchstens 8 pro Sitzung). Später `BroadcastChannel`.
5. **Peer-Bindung bei Weg E**: Ob Firefox in der Kali alle Anfragen aus demselben Prozess stellt (Socket-Prozess), ist zu verifizieren. Wechselt der Prozess, endet die Sitzung (lieber neu anmelden als ein fremdes Token annehmen).
8. **Peer-Bindung bei Weg B**: Der sshd-Prozess der Sitzung ist für den eigenen Benutzer nicht lesbar (nach dem Rechtewechsel nicht «dumpable»), seine Sockets lassen sich ihm also nicht zuordnen. Gebunden wird darum an die SSH-Verbindung, die den Code geholt hat (PID über `ctl.sock` und die Eltern von `remote serve`), und jede Verbindung mit lesbarem Prozess muss genau dieser sein. Ein anderer, ebenfalls nicht lesbarer Prozess desselben Benutzers könnte ein gestohlenes Token benutzen, solange der Tunnel steht; ein solcher Prozess kann aber ohnehin `ctl.sock` erreichen und Codes holen (gleiche UID, Architektur 9.1 A4).
6. **Positionen bei Merge und Split**: Wer verschiebt gespeicherte Positionen, wenn sich die stärkste Kennung eines Hosts ändert? v0.1: die UI legt einen unbekannten Knoten neu.
7. **IP-Adressen in der URL** (Briefing 13.3): `?host=ip:default/…` steht im Browserverlauf. v0.1 erlaubt es; neutrale IDs wären eine spätere Änderung.
9. **Entscheide der Design-Session (E105 bis E114).** **Erledigt** im Bau v0.1-Oberfläche: E106 (18.3), E112 (18.2), E113 (18.5), E111 (18.7). Offen bleibt nur, ob die Oberfläche eigene Secrets je einzeln aufdecken darf (Punkt 2); v0.1 zeigt nur ihre Zahl (18.8, `Status.operator.own_secrets`).

## 17 Präzisierungen aus dem Bau v0.1-Server

> **geändert im Bau v0.1-Server** (Teil «api», 2026-10-17). Die Umsetzung hat folgende Stellen festgelegt, die oben offen oder mehrdeutig waren. Nichts davon lockert eine Regel aus 1.1 oder 1.3.

| Stelle | Festlegung |
|---|---|
| Ausgang (1.3) | Jede JSON-Antwort geht zuletzt durch `Redactor.redact_json` und danach durch eine zweite Schicht, die jeden String (auch Schlüssel) sichtbar macht; zusätzlich zu `term_safe` werden U+2028 und U+2029 als `<U+2028>`/`<U+2029>` gezeigt. Gekürzt wird nur, wo es steht (Eingaben: 2000 Zeichen). |
| Zeilen einer Einheit (11) | `n`, `from` und die Bereiche `lines` in `SourceView` zählen nach der Position in der Einheit (`unit_line.pos`, 0-basiert, mit Prompt-Echo). Fundstellen der Parser werden darauf umgerechnet. `masked[].kind`: `secret` (bekannter Secret-Wert oder im Präsentationsmodus ein von einem Parser gemeldeter Secret-Bereich), `own_secret` (eigenes Secret), `concealed` (SGR-verdeckter Text ohne `reveal_hidden`). |
| `reveal_hidden` (11) | wirkt nur im Profil lab und nie im Präsentationsmodus; sonst bleibt verdeckter Text verdeckt (kein Fehler). |
| `log.txt` (11) | Dateiname `unit-<12 Hex-Zeichen>.txt` (Hash der `unit_id`), höchstens 200 000 Zeilen, danach ein Vermerk. |
| Suche (13) | `line` ist die Position wie bei `/lines`; der Text ist so verdeckt wie dort. |
| Warteliste (13) | Antwort zusätzlich mit `truncated`. |
| Host-Tabelle (8) | `/hosts` zeigt wie die Karte nur Hosts im Scope (auch Nebel); das Detail gibt es für jeden bekannten Host, auch über eine andere Kennung des Hosts. `HostDetail` zusätzlich mit `facts_truncated` (höchstens 2000 Werte); `conflicts` ist im Detail die Liste. Namen in Punycode (`xn--`) zeigt `label` dekodiert, `punycode` die ASCII-Form. |
| Services (8) | `/services` zeigt nur Services im Scope; `class` ist eine der Klassen aus `ServiceNode`, sonst 422. Verlauf: abgelöste Werte von `service.state`, `version`, `product`, `name` mit `until` = zuletzt gesehen. |
| Karte (7) | `oos` enthält Hosts mit Urteil ungleich `in` und IP-Erwähnungen ausserhalb des Scopes (ohne eigene Adressen), nach Zahl der Erwähnungen. Segmente: Netze aus `scope.include` (`origin: scope`), sonst das beobachtete /24 bzw. /64. `summary.services` ist die Summe der Services der Hosts im Scope. |
| Änderungen (7) | `reset: true`, wenn `since` grösser als die aktuelle Generation ist (neue `derived.db` nach Reparse) oder älter als die aufbewahrten 1000 Generationen. |
| Positionen (7) | `PUT` ersetzt alle gespeicherten Positionen des Projekts. |
| Status (4) | `ingest.last_error` ist ein fester Text («Auswertung fehlgeschlagen»), nie eine Ausnahme. `llm.budget.month_limit_usd` aus den Projekteinstellungen, `month_used_usd` in v0.1 immer 0. |
| Terminals (5) | `remote_segment` nur, wenn das jüngste offene Segment in einer Remote-Stufe liegt. `last_command.ended_at` ist `null`, solange der Befehl läuft. |
| Kontext (5) | `pop` auf Kali: 422. `accept` für einen Vorschlag dieses Terminals, der nicht mehr offen ist: 409; ein unbekannter Eintrag: 404. Warnungen nennen `host` als eingegebenen Text (IP oder Name). |
| Zeitachse (10) | `id`: `unit_id` bei Einheiten, `k:<seq>` Schlüsselschritt, `c:<seq>` Kontext-Entscheid, `a:<tid>@<off>` Auto-Kontext, `decision_id` bei Entscheiden, `g:<seq>` Lücke, `p:<seq>` Projekt, `i:<seq>` Eingabe. Eine Pause steht als `gap` mit `reason: pause` ab Beginn der Pause bis `until`. `summary` der Entscheide ist ein fester Text ohne Werte. Die Zeitachse trägt die jüngsten 5000 Einträge aus Einheiten und Schritten. |
| Entscheide (12) | `d.claim.confirm` und `d.claim.edit` auf eine eigene Adresse: 409. `d.revoke` auf `d.scope.update` oder `d.lab.not_customer`: 403 `policy`; auf einen schon aufgehobenen Entscheid: 409. `d.keystep.mark` mit `terminal_id` oder `stream_off`: 422. `d.automode.set`: 403 im Profil lab. Bei `d.unit.distrust` ist `seq` `null`. |
| Aufdecken (13.3) | Für Eingaben ist `ctrl` wahr, wenn der Text sichtbar gemachte Steuerzeichen enthält. |
| Fetch-Metadaten (1.1) | Navigation zur Shell auch von fremder Herkunft (E115, Integration); alles andere unverändert. |
| UI-Bau | Schreibende Anfragen mit `fetch` im Modus `cors` (Standard): Nur dann schickt der Browser trotz `Referrer-Policy: no-referrer` den echten `Origin` statt `null`. Den Strom mit `fetch` lesen (Bearer, `Last-Event-ID`). Positionen von Host-Karten über CSSOM setzen, nicht über `style`-Attribute (Shell-CSP). |

## 18 Ergänzungen für die Oberfläche v0.1

> **Bau v0.1-Oberfläche**, Phase 1, Stand 2026-10-18. Grundlage: Design v0.1 ([README](ui/design-v01/README.md), [SCREENS](ui/design-v01/SCREENS.md), [BEHAVIOR](ui/design-v01/BEHAVIOR.md)), E105 bis E118, Architektur 6.1 und 6.3, Briefing [dashboard-funktionen.md](ui/dashboard-funktionen.md). Alles hier ist **[v0.1]** und wird in diesem Bau gebaut und getestet. Es gelten ohne Ausnahme 1.1 bis 1.6: Middleware, Bearer, `extra="forbid"`, Zieldaten nur als JSON-String mit sichtbaren Steuerzeichen und `ctrl`, Ausgang durch `Redactor.redact_json` und die zweite Schicht, feste Fehlertexte, Projektprüfung nach jedem `await`.

### 18.1 Überblick

| Lücke (Design, Briefing) | Lösung | Abschnitt |
|---|---|---|
| Theme, Dichte, Lernmodus ohne Browser-Speicher (E112) | `GET`/`PUT /api/v1/ui/prefs`, global in `state_dir`, SSE `prefs` | 18.2 |
| «+N seit HH:MM» mit den IDs des Neuen, übersteht Neuladen (E106) | `GET`/`PUT /api/v1/p/{pid}/ui/seen` in `state.db` | 18.3 |
| Scope-Warnung quittieren ohne Browser-Speicher, Inhalt der Meldung (Briefing 4.5, Screen 10) | `PUT /api/v1/p/{pid}/ui/scope-ack`, `Status.scope_warning` erweitert | 18.4 |
| Findings schon in v0.1 (E113) | `GET /p/{pid}/findings`, `GET /p/{pid}/findings/{finding_id}`, Entscheide `d.finding.*`, Projektion in `derived.db` | 18.5 |
| Denkanstösse aus Regeln mit Vorlagen und Lernmodus (A 6.1, 6.3, E64, E68) | `Suggestion` in `/next`, `GET /p/{pid}/suggestions`, `d.suggestion.done`/`dismiss` | 18.6 |
| «in die Kali kopieren» (E111) | `POST /p/{pid}/secrets/copy` | 18.7 |
| Terminal-Namen und Nummern (T1 «scan»), Web-Pausenbudget (E117), Herkunft der Werte im Detail, Lagebild «Stand», Out-of-Scope-Popover, Host-Tabelle, Ergebnis pro Befehl in der Zeitachse, «wird frühestens … ausgewertet», Logauszug «Darum mehrdeutig», Zahl eigener Secrets, Grösse in der Warteliste | additive Felder an bestehenden Antworten | 18.8 |
| Live-Hinweise für Vorlieben und Denkanstösse | SSE `prefs`, `suggestion` | 18.9 |
| Fehler beim Kopieren in die Kali | Codes `clipboard_tool`, `clipboard_session` (503) | 18.10 |

Gemeinsamer Hilfstyp für Terminal-Bezüge in allen Antworten dieses Abschnitts und in 18.8:

```ts
interface TermRef {
  terminal_id: string;
  ordinal: number | null;     // «T1», «T2» …: Rang des ersten Auftretens des Terminals im offenen Projekt
                              // (früheste Einheit bzw. term.open), stabil über Neustarts des Daemons;
                              // null für Terminals ohne Bindung an dieses Projekt (ungebunden, held)
  label: string | null;       // Name aus dem jüngsten gültigen d.terminal.label (Zieldaten-frei, aber Text), sonst null
}
```

### 18.2 GET, PUT /api/v1/ui/prefs [v0.1] (E112)

Vorlieben der Oberfläche. Global (nicht pro Projekt), auch ohne Projekt und bei gesperrtem Projekt; nötig, damit Anmeldung und Zustände schon im richtigen Theme erscheinen. Gespeichert in `state_dir/ui_prefs.json` (Rechte 0600, atomar über eine Temp-Datei und `rename`, höchstens 4 KiB; ungültiger Inhalt beim Lesen ergibt die Standardwerte). Kein Entscheid, ausserhalb der Hash-Kette.

```ts
type Theme = 'system' | 'light' | 'dark';
type Density = 'comfortable' | 'compact';
interface Prefs {
  theme: Theme;               // Standard 'system'
  density: Density;           // Standard 'comfortable'
  learning: boolean;          // Lernmodus: Denkanstösse in Stufen (A 6.3); Standard true (im Lab an)
}
interface PrefsView { prefs: Prefs; updated_at: string | null }
// GET -> 200 PrefsView
// PUT  body: Partial<Prefs> mit mindestens einem Feld -> 200 PrefsView
```

`PUT` setzt nur die genannten Felder. Danach SSE `prefs` an alle Ströme. Fehler: 401, 422 (unbekanntes Feld, falscher Wert, leerer Body).

Die UI setzt das Theme als `data-theme` auf `<html>` (`system` entfernt das Attribut) und die Dichte als `data-density`. Bis die Antwort da ist, folgt sie dem System.

### 18.3 GET, PUT /api/v1/p/{pid}/ui/seen [v0.1] (E106)

Bezugspunkt «Neu seit». Die UI meldet beim `visibilitychange` auf `hidden` (und bei `pagehide`) mit `PUT` (`fetch` mit `keepalive: true`), dass der Tab jetzt unsichtbar wird. Der Server nimmt **seine** Uhrzeit, nicht die des Browsers. Gespeichert pro Projekt in `state.db` (Tabelle `ui_state`, Schlüssel `seen_at`, Nanosekunden), ausserhalb der Hash-Kette, kein Entscheid. Übersteht Neuladen, Abmelden und Neustart des Daemons.

```ts
// PUT body {} -> 202 { seen_at: string }
// GET -> 200 SeenView
interface SeenView {
  seen_at: string | null;             // null: noch nie unsichtbar geworden -> keine Marke
  new: NewSince | null;               // null genau dann, wenn seen_at null ist
}
interface NewSince {
  since: string;                      // = seen_at; Anzeige «+N seit HH:MM» in Lokalzeit
  count: number;                      // N = hosts.length + access.length + services.length + items.length + keysteps.length
  hosts: string[];                    // host_id: Hosts im Scope (auch Nebel) mit first_seen > since
  access: string[];                   // host_id: Zugriff seit since gesetzt oder erhöht (Schlüsselschritt
                                      // foothold/privesc, d.status.access oder Zugriffs-Wert mit first_ts > since),
                                      // ohne Hosts, die schon in hosts stehen
  services: string[];                 // service_id: neue Services (first_seen > since), deren Host nicht in hosts steht
  items: string[];                    // item_key: offene Einträge in clarify mit created_ts > since
  keysteps: string[];                 // ThreadEdge.id: Schlüsselschritte mit ts > since
}
```

Jede Liste höchstens 500 Einträge (dann zählt `count` trotzdem alle). Zeitpunkte sind Shim- bzw. Entscheidzeiten (E96). Die UI zeigt die Marke nur bei `count > 0`; ein Klick lässt genau diese Elemente einmal pulsieren (900 ms, bei `prefers-reduced-motion` 2 s statischer Ring): Host-Karten (`hosts`, `access`, Host der `services`), Einträge der Spalte (`items`), Faden-Kanten (`keysteps`). Fehler: 422 (Body nicht leer).

### 18.4 PUT /api/v1/p/{pid}/ui/scope-ack [v0.1]

Quittiert die Scope-Warnung (Briefing 4.5) ohne Browser-Speicher. Body `{ cmd_id: string }` (voll oder als `cmd_ref`); gespeichert in `state.db` (`ui_state`, Schlüssel `scope_ack`). Antwort 202. `Status.scope_warning.acked` ist danach `true`, bis ein neuerer Befehl mit Ziel ausserhalb kommt. Fehler: 404 (Befehl unbekannt), 422.

`Status.scope_warning` (4) bekommt dazu den Inhalt der Meldung (Screen 10, «Ziel ausserhalb des Scopes»):

```ts
scope_warning: {
  cmd_id: string; cmd_ref: string; terminal_id: string; ts: string;   // wie bisher
  terminal: TermRef;
  text: string | null; ctrl: boolean;            // Befehlstext (Zieldaten, Secrets maskiert wie CommandRef.text)
  targets: { value: string; verdict: Verdict; ctrl: boolean }[];   // nur Ziele mit verdict != 'in', höchstens 20
  scope: string[];                               // scope.include zur Anzeige «liegt nicht in 192.168.56.0/24»
  acked: boolean;
} | null
```

### 18.5 Findings [v0.1] (E113)

Ein Finding ist ein Urteil des Menschen über Belege (VISION Grundsatz 10). Es entsteht nur aus Entscheiden; Schwere setzt nur der Mensch. Formular im Reiter Findings und «Als Finding» aus der Belegansicht führen ins selbe Formular (die UI füllt dann `evidence` und `created_from` vor).

**Entscheide** (über `POST /decisions`, Herkunft `webui`; Modelle in `events.py`):

| `kind` | Nutzlast | Wirkung |
|---|---|---|
| `d.finding.create` | `{ title, severity?, status?, affected?, description?, remediation?, attack?, cves?, evidence?, created_from? }` | neues Finding; `finding_id` = `decision_id` dieses Entscheids |
| `d.finding.update` | `{ finding_id, title?, severity?, status?, affected?, description?, remediation?, attack?, cves? }` | genannte Felder ersetzen; nicht genannte bleiben |
| `d.finding.evidence.add` | `{ finding_id, claim_key?, unit_id?, lines? }` | Beleg anhängen (mindestens `claim_key` oder `unit_id`) |
| `d.finding.evidence.remove` | `{ finding_id, evidence_id }` | Beleg entfernen |
| `d.finding.delete` | `{ finding_id, reason? }` | Finding löschen (als Entscheid; `d.revoke` darauf stellt es wieder her) |

```ts
type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';    // Kritisch, Hoch, Mittel, Tief, Info
type FindingStatus = 'draft' | 'final';                            // Entwurf, final
interface FindingRefIn { id: string; supported?: boolean }         // ATT&CK 'T1190', 'T1059.004'; CVE 'CVE-2011-2523'
interface EvidenceRefIn { claim_key?: string; unit_id?: string; lines?: [number, number] }
```

Prüfung (422 mit `loc` und `type`, nie mit Werten): `title` 1 bis 200 Zeichen ohne Zeilenumbruch; `description`, `remediation` je höchstens 20 000 Zeichen (Markdown ohne HTML, angezeigt nur über `SafeMarkdown`); `affected` höchstens 50 Kennungen (Host- oder Service-ID; jede muss bekannt sein, sonst 409); `attack` höchstens 20, jede `^T\d{4}(\.\d{3})?$`; `cves` höchstens 20, jede `^CVE-\d{4}-\d{4,7}$`; `evidence` höchstens 100; `lines` mit `0 <= start <= ende`; `status: 'final'` verlangt eine `severity` (sonst 422 `severity_required`). Bezüge (Claim, Einheit, Finding, Beleg) prüft der Server wie in 12 (409 `conflict`, wenn unbekannt oder das Finding gelöscht ist). `d.finding.*` darf mit anderen Entscheiden in einer Anfrage stehen (alle oder keiner); ein `d.finding.update` auf ein `finding_id`, das in derselben Anfrage angelegt wird, gibt es nicht (422).

**Projektion.** Bei jeder Neuauswertung baut die Auswertung aus den aktiven (nicht widerrufenen) `d.finding.*` in Journal-Reihenfolge die Tabellen `finding` und `finding_evidence` in `derived.db`; sie übersteht damit jeden Reparse. Änderungen erscheinen in `projection_delta` mit `entity = 'finding'` (SSE `changes`). Ein Beleg ist `ok`, `distrusted` (stammt aus einem Befehl mit `d.unit.distrust`, oder der Claim ist verworfen) oder `missing` (Claim oder Einheit nach dem Reparse nicht mehr da).

**ATT&CK und CVE** sind Text. Jeder Eintrag trägt `hypothesis: true` («Hypothese ohne eigenen Beleg»), ausser der Mensch hat ihn als belegt markiert (`supported: true`) **und** das Finding hat mindestens einen Beleg im Zustand `ok`.

#### GET /api/v1/p/{pid}/findings [v0.1]

```ts
interface FindingsResponse { findings: FindingSummary[] }    // nach ordinal, höchstens 500
interface FindingSummary {
  finding_id: string;
  ordinal: number;                   // F1, F2 … in Reihenfolge der Anlage (gelöschte behalten ihre Nummer)
  title: string; ctrl: boolean;
  severity: Severity | null;
  status: FindingStatus;
  affected: { subject: string; label: string; ctrl: boolean }[];   // «192.168.56.101:21 ftp»
  evidence_count: number;
  warnings: ('evidence_distrusted' | 'evidence_missing' | 'no_evidence' | 'no_severity')[];
  created_at: string; updated_at: string;
}
```

#### GET /api/v1/p/{pid}/findings/{finding_id} [v0.1]

```ts
interface FindingDetail extends FindingSummary {
  description: string; remediation: string;          // Markdown-Text (Zieldaten möglich)
  attack: { id: string; supported: boolean; hypothesis: boolean }[];
  cves: { id: string; supported: boolean; hypothesis: boolean }[];
  evidence: FindingEvidence[];
  created_from: EvidenceRef | null;                  // «angelegt aus dem Beleg T2 16:45:12»
  history: { decision_id: string; kind: string; ts: string }[];   // Entscheide dieses Findings, älteste zuerst
}
interface FindingEvidence {
  evidence_id: string;               // 'ev:' + 16 Hex, Hash aus claim_key | unit_id | lines, stabil über Reparse
  ref: EvidenceRef;                  // Sprung in die Belegansicht (2)
  label: string; ctrl: boolean;      // «nmap 14:02 · Zeile 6 · vsftpd 2.3.4», «T2 msf 16:45:12 · Zeilen 44 bis 47»
  terminal: TermRef | null;
  ts: string | null;                 // Zeit der Quelle
  state: 'ok' | 'distrusted' | 'missing';
  added_at: string; decision_id: string;
}
```

Fehler: 404 (unbekannt oder gelöscht).

### 18.6 Denkanstösse aus Regeln [v0.1] (A 6.1, 6.3, E10, E64, E68)

Die Regel-Engine (`ariadne.rules`) läuft bei jeder Anfrage von `/next` und `/suggestions` über der Projektion in `derived.db` (nur lesend, im Thread der Auswertung, mit Grenzen). Sie erzeugt nur Vorschläge, nie Fakten, und Ariadne führt nie etwas davon aus (E10): Es gibt keinen Ausführen-Weg, nur Text zum Kopieren.

```ts
interface Suggestion {
  suggestion_key: string;           // 'sg:' + 24 Hex: Hash aus rule_id und den sortierten natürlichen Schlüsseln
                                    // (host_id, service_id …); übersteht Reparse und Merge
  origin: 'rule';                   // 'ai' ab v0.1-KI
  rule_id: string;                  // 'R-ANON-ZUGRIFF'
  goal_id: string | null;           // Prüfziel 'PZ-AUTH-ANON'
  kind: 'goal' | 'question' | 'hypothesis' | 'hint';
  title: string; ctrl: boolean;     // «Unauthentisierten Zugriff auf 192.168.56.101:21 prüfen»
  title_parts: TextPart[];          // derselbe Titel in Teilen; Zieldaten markiert (Mono, gepunktet unterstrichen)
  host_id: string | null; service_id: string | null;
  host_label: string | null;
  reason: string; ctrl_reason: boolean;   // Begründung: fester Text der Regel mit eingesetzten, sichtbar gemachten Werten
  evidence: EvidenceRef[];          // Claim und Zeile; label «nmap -sV · 14:02 · Zeile 6»; höchstens 5
  stages: {                         // Lernmodus (A 6.3): Stufe 1 Frage, Stufe 2 Richtung, Stufe 3 = templates
    question: string;
    direction: string;
  };
  templates: CommandTemplate[];     // Befehlsbibliothek, höchstens 4
  state: 'open' | 'done' | 'dismissed';
  decision_id: string | null;       // Entscheid, der state setzt (für «Rückgängig» per d.revoke)
  basis: string;                    // Fingerabdruck des Anlasses (16 Hex), geht in d.suggestion.done
  flags: ('from_target' | 'injection_suspect')[];
  ts: string | null;                // jüngster Anlass (für die Sortierung «neu»)
  ai: null;                         // reserviert: { model, confirmed_if, refuted_if } ab v0.1-KI
}
interface TextPart { text: string; target: boolean }   // target: Teil stammt aus Zieldaten
type PlaceholderType = 'ip' | 'port' | 'hostname' | 'cidr' | 'url' | 'word' | 'words' | 'path' | 'user' | 'share';
interface CommandTemplate {
  template_id: string;              // 'nmap-ftp-anon'
  tool: string;                     // Werkzeug, fester Text der Bibliothek ('nmap', 'searchsploit')
  label: string;                    // «nmap-Skript ftp-anon»
  rendered: boolean;                // false: mindestens ein Wert ist nicht sicher kodierbar
  command: string | null;           // fertiger Befehl ohne Zeilenumbruch am Ende; nur wenn rendered
  parts: TextPart[];                // command in Teilen (leer, wenn nicht rendered)
  values: {                         // die Einzelwerte, jeder einzeln kopierbar («Kopieren · Mac»)
    slot: string;                   // 'host.ip', 'service.port', 'service.product'
    type: PlaceholderType;
    label: string;                  // «IP», «Port», «Produkt», «Werkzeug»
    value: string; ctrl: boolean;   // sichtbar gemacht wie jeder Zielwert
    target: boolean;                // aus Zieldaten (false nur beim Werkzeug)
    safe: boolean;                  // passt zum Typ und seinem Kontext-Encoder
  }[];
  blocked_reason: 'shell_meta' | 'control' | 'newline' | 'non_ascii' | 'invalid' | 'out_of_scope' | null;
}
```

**Befehlsvorlagen (E68, A 6.1, Punkte 1 bis 6).** Vorlagen stehen nur in der Bibliothek des Servers, nie im Browser, und haben nur typisierte Platzhalter. Jeder Platzhalter hat einen Kontext-Encoder, der prüft und nie umformt:

| Typ | erlaubt | Encoder `sh` |
|---|---|---|
| `ip` | `ipaddress`, Scope-Urteil `in` (sonst `out_of_scope`) | kanonische Form |
| `port` | Ganzzahl 1 bis 65535 | Dezimalzahl |
| `hostname` | nach IDNA nur `[A-Za-z0-9.-]{1,253}` | unverändert |
| `cidr` | `ipaddress.ip_network`, im Scope | kanonische Form |
| `url` | nur `http`, `https`, neu serialisiert, ohne Benutzer und Passwort | nur Zeichen aus `[A-Za-z0-9._~:/@=%+-]` (kein `?`, `#`, `&`); sonst gesperrt |
| `word` | `[A-Za-z0-9._+-]{1,64}` | unverändert, ein argv-Element |
| `words` | Wörter wie `word`, durch einzelne Leerzeichen getrennt, höchstens 6 | je Wort ein argv-Element |
| `path` | absolut, `[A-Za-z0-9._/+-]{1,255}`, ohne `..` | unverändert, hinter `--` wo das Werkzeug es kennt |
| `user`, `share` | `[A-Za-z0-9._-]{1,64}` bzw. `[A-Za-z0-9._$-]{1,80}` | unverändert |

Passt ein Wert nicht, rendert der Server **keinen** Befehl (`rendered: false`, `command: null`, `parts: []`) und nennt den ersten Grund in `blocked_reason`: Steuerzeichen (`control`), Zeilenumbruch (`newline`), Nicht-ASCII (`non_ascii`), Shell-Metazeichen (Anführungszeichen, Backtick, `$ ; & | < > ( ) { } [ ] * ? ! \ #`) und Leerraum an falscher Stelle (`shell_meta`), sonst `invalid` bzw. `out_of_scope`. Die UI zeigt dann «Enthält Shell-Sonderzeichen. Keine fertige Vorlage.» und nur `values`. Ein Lint beim Laden prüft jede Vorlage; Golden-Tests prüfen mit `shlex.split`, dass jeder gerenderte Befehl genau die erwarteten argv ergibt, auch mit dem feindlichen Korpus (`'`, `$( )`, LF, ESC, U+202E, Homoglyphen). Gerenderte Befehle enden nie mit einem Zeilenumbruch.

**Zustand.** `d.suggestion.dismiss` verwirft für immer (auch nach Reparse, Merge und neuem Anlass). `d.suggestion.done` gilt, solange `basis` gleich dem aktuellen Fingerabdruck ist: Ändert sich der Anlass (neuer Wert, neue Version, neuer Beleg), ist der Denkanstoss wieder offen. `basis` ist darum in `d.suggestion.done` Pflicht (422 `basis_required`). `d.revoke` auf den Entscheid öffnet ihn wieder. Bezug: `suggestion_key` muss bei der Prüfung existieren (sonst 409 `conflict`).

**`/next`** liefert in `suggestions` nur offene Denkanstösse, sortiert nach Priorität der Regel, dann Host, dann Port; höchstens 50. `suggestions_available` ist `true`.

#### GET /api/v1/p/{pid}/suggestions?state= [v0.1]

Alle Denkanstösse mit Zustand, für Palette und «Verworfene zeigen». `state` ist `open` (Standard), `done`, `dismissed` oder `all`; höchstens 200. Antwort `{ suggestions: Suggestion[]; truncated: boolean }`. Fehler: 422.

**Regelkatalog v0.1** (Golden-Tests mit den Fixtures MS2 und Lame; Details im Vertrag des Baus): `R-ANON-ZUGRIFF` (FTP, SMB, NFS ohne geprüfte anonyme Anmeldung), `R-VERSION-RECHERCHE` (bekanntes Produkt mit Version), `R-FULL-PORTSCAN` (Host nur mit Top-Ports gescannt), `R-UDP-SCAN` (kein UDP-Scan im Scope), `R-SMB-SHARES` (SMB ohne Auflistung der Shares), `R-WEB-INHALT` (Webdienst ohne Inhaltsprüfung), `R-STANDARD-CREDS` (Dienst mit typischen Standardkonten, als Frage), `R-NFS-EXPORTS` (NFS ohne `showmount`), `R-SMTP-USER` (SMTP ohne Benutzer-Enumeration, als Frage), `R-DB-ZUGRIFF` (Datenbankdienst ohne Anmeldeversuch, als Frage). Der Katalog darf im Bau wachsen; Regel-IDs sind stabil.

### 18.7 POST /api/v1/p/{pid}/secrets/copy [v0.1] (E111)

Kopiert **einen** Secret-Wert in die Zwischenablage der Kali, ohne ihn an den Browser zu geben. Request wie `secrets/reveal` (13.3): `{ ref: 'input', seq }` (Eingabe ohne Echo) oder `{ ref: 'claim', claim_key }` (Secret-Wert eines Claims).

```ts
// Antwort 202
interface CopyResult { copied: true; target: 'kali'; clear_after_s: 30; tool: 'xclip' | 'xsel' | 'wl-copy' }
```

Ablauf im Daemon (ctl-Operation `clip.copy`, nur für die Web-API erlaubt): Wert auflösen, eigene Secrets nie kopieren (enthält der Wert eines, 403 `policy`), Werkzeug wählen (bei `WAYLAND_DISPLAY` `wl-copy`, sonst bei `DISPLAY` `xclip -selection clipboard` oder `xsel --clipboard --input`, was vorhanden ist), den Wert nur über stdin übergeben (nie in argv, nie im Log), die Umgebung der grafischen Sitzung des Benutzers verwenden (`DISPLAY`, `WAYLAND_DISPLAY`, `XAUTHORITY`, `XDG_RUNTIME_DIR` aus der eigenen Umgebung oder aus `/proc/<pid>/environ` eines Prozesses derselben UID mit grafischer Sitzung, nie eines fremden Benutzers). Nach 30 s liest der Daemon die Zwischenablage zurück und leert sie, wenn noch derselbe Inhalt darin ist (Vergleich über einen Hash, ohne den Wert zu behalten). Nur Profil lab, nie im Präsentationsmodus (403 `policy`). Fehler: 404 (unbekannt oder kein Secret), 403 `policy`, 422 (Wert mit Steuerzeichen, 18.12), 503 `clipboard_tool` (kein Werkzeug), 503 `clipboard_session` (keine grafische Sitzung gefunden).

### 18.8 Additive Felder an bestehenden Antworten [v0.1]

Alle neuen Felder sind Pflichtfelder in der Antwort (Wert `null`, wenn es ihn nicht gibt, 1.2).

| Antwort | neue Felder |
|---|---|
| `Status.operator` (4) | `own_secrets: number \| null`: Zahl der eigenen Secrets (Einstellungen «Eigene Secrets: ••••••••, 2 Einträge»); `null` bei gesperrtem Tresor. Werte und Labels nie |
| `TerminalState` (4, 5) | `ordinal: number \| null`, `label: string \| null` (wie `TermRef`); `opened_at: string \| null`; `web_pause_left_s: number \| null`: restliches Web-Pausenbudget in der gleitenden Stunde (E117, höchstens 1800), `null` bei `held`, `off` und ohne Projekt |
| `Status.scope_warning` (4) | siehe 18.4 |
| `GraphView` (7) | `as_of: string`: Zeit der Generation (Lagebild «Stand 16:54») |
| `OosItem` (7) | `source: UnitBrief \| null` (erste Quelle, «nmap -6 15:20»); `punycode: string \| null`; `note: 'same_mac' \| 'forged_callback' \| null` mit `related: string \| null` (Host im Scope, etwa «gleiche MAC wie .101») |
| `HostNode`, `HostSummary` (7, 8) | `ports: number[]`: bis 12 Ports, offene zuerst, aufsteigend (Host-Tabelle «22 · 445»); `conflict_brief: { predicate: string; port: number \| null } \| null` («Konflikt: Dienstname 445») |
| `HostDetail` (8) | `candidate_claims: string[]`: Claims, deren Annehmen (`d.claim.confirm`) bzw. Verwerfen (`d.claim.reject`) einen Host im Nebel ein- oder ausfärbt (Screen 3, `.103`); `access_by: { source: 'decision' \| 'keystep' \| 'value'; decision_id: string \| null; ts: string \| null } \| null` («root, per Entscheid 16:46»); `first_source: UnitBrief \| null` («Quelle: nmap -O · 15:10») |
| `ServiceView` (8) | `banner: string \| null` (HTTP-Titel bzw. Zusatzinfo, Zieldaten), `from_target: boolean`, `suspect: boolean` («! Injection-Verdacht · vom Ziel angeboten») |
| `NextItem` `ctx_suggestion`, `ctx_unknown` (9) | `terminal: TermRef \| null`; `from_ts: string \| null` («Wirkt rückwirkend ab 16:52:31»); `excerpt: { unit_id: string; lines: [number, number]; text: string[]; ctrl: boolean; note: 'second_callback' \| 'callback' \| null; ts: string \| null } \| null` («Darum mehrdeutig: zweiter Callback im Output, 16:53:02», höchstens 4 Zeilen, Secrets maskiert) |
| `TimelineItem` (10) | `terminal: TermRef \| null` für alle Typen; `command`: `result: { hosts_new: number; services: number; values: number; out_of_scope: number; conflicts: number }` («1 Host, 23 Services · 141 Werte übernommen», «0 übernommen, +17 ausserhalb», «1 Widerspruch»); `decision`: `detail: string \| null` (Zielbezug als Text, etwa «Zugriff root auf 192.168.56.101», «tcp/445 · netbios-ssn»), `reason: string \| null`, `ref: string \| null` (`cmd_ref` bei `d.unit.distrust`), `effect: { rejected: number; weakened: number } \| null`; `segment`: `evaluate_after: string \| null` («wird frühestens 16:58:31 ausgewertet»); `keystep`: `host_id: string \| null`, `decision_id: string` |
| Kopf einer Einheit (11) | `terminal: TermRef \| null`; `chain_break_line: number \| null` (erste Zeile, ab der die Kette nicht passt, sonst `null`) |
| Warteliste (13) | pro Datei `size: number \| null` (Bytes, per `lstat` ohne Folgen von Symlinks); `reason` ist einer der Codes `outside_workspace`, `symlink`, `hardlink`, `owner`, `not_regular`, `other_fs`, `path`, `too_large` |

### 18.9 Ereignisse [v0.1]

| Ereignis | Wann | Reaktion der UI |
|---|---|---|
| `prefs` `{}` | nach jedem `PUT /ui/prefs` | Vorlieben nachladen, Theme und Dichte sofort setzen |
| `suggestion` `{ project_id, open }` | nach einer Neuauswertung, wenn sich die Zahl offener Denkanstösse geändert hat | `/next` nachladen |
| `changes` mit `entities.finding` | nach jedem `d.finding.*` | Findings-Liste und offenes Finding nachladen |

`PUT /ui/seen` und `PUT /ui/scope-ack` lösen kein Ereignis aus; `scope-ack` wirkt in anderen Tabs beim nächsten `/status`.

### 18.10 Fehlercodes [v0.1]

`ApiErrorCode` bekommt zwei Codes mit festen Texten: `clipboard_tool` (503, «In der Kali fehlt ein Werkzeug für die Zwischenablage: xclip, xsel oder wl-copy installieren.») und `clipboard_session` (503, «Keine grafische Sitzung in der Kali gefunden. Am Kali-Desktop anmelden.»). Neue 422-`type`-Werte: `severity_required`, `basis_required`, `same_request`, `subject`, `attack`, `cve`.

### 18.11 Nicht in v0.1

KI-Denkanstoss (`POST /ai/denkanstoss`, 501 bis v0.1-KI; der Knopf «Denkanstoss anfordern (KI)» ist gesperrt und nennt den Grund), Export und Screenshot (501; Dialoge mit Hinweis, Knöpfe gesperrt), Prüfziel-Status `d.goal.status` und KI-Hypothesen `d.hypothesis` (501 bis v0.2), Aufdecken eigener Secrets (nie über HTTP), Übernehmen aus der Warteliste (nur `ariadne import`).

### 18.12 Präzisierungen aus dem Bau v0.1-Oberfläche (Teil «backend-ui»)

> Stand 2026-10-18. Die Umsetzung hat folgende Stellen festgelegt, die oben offen oder mehrdeutig waren. Nichts davon lockert eine Regel aus 1.1 oder 1.3.

| Stelle | Festlegung |
|---|---|
| Vorlieben (18.2) | Datei `state_dir/ui_prefs.json` als `{"prefs": {...}, "updated_ns": N}`; ein ungültiges Feld fällt einzeln auf seinen Standard zurück, eine ungültige Datei (auch über 4 KiB, Symlink, fremder Besitzer) ergibt alle Standardwerte. `null` gilt im `PUT` nicht als Wert (422 `null`); ohne Feld 422 `missing`. Gleichzeitige `PUT` werden nacheinander geschrieben. Das Ereignis `prefs` steht in `SSE_EVENTS` des Servers. |
| «Neu seit» (18.3) | `PUT` nimmt keinen Körper oder `{}`; jedes Feld ergibt 422. `seen_at` liegt in `state.db`, Tabelle `ui_state(key, value, updated_ns)`. `hosts` ohne Platzhalter-Hosts (`ctx:`), sortiert nach `first_seen`; `access` nur für Hosts, deren Zugriff jetzt `user` oder `admin` ist; `items` im Profil customer ohne `candidate_group`. |
| Scope-Quittung (18.4) | `PUT /ui/scope-ack` antwortet `202 { accepted: true }`; gespeichert wird die volle `cmd_id`. `acked` ist wahr, wenn genau der Befehl der aktuellen Warnung quittiert ist. `targets[].value` ist das getippte Ziel (`raw` aus `activity.target_scope`). |
| Terminals (18.8) | `opened_at` ist die Zeit des ersten Ereignisses des Terminals **im offenen Projekt** (nicht der Verbindungsaufbau); `ordinal`, `label` und `opened_at` sind `null`, solange das Terminal nichts ins Projekt geschrieben hat (Vorlauf, `held`). `web_pause_left_s` ist die längste Web-Pause in Sekunden, die der Daemon jetzt annähme (gleiche Rechnung wie die Prüfung bei `pause`). |
| Findings (18.5) | Bezüge prüft der Server gegen die **Entscheide im Journal** (nicht gegen die nachziehende Projektion): ein zweites Entfernen desselben Belegs oder ein Ändern nach dem Löschen ergibt sofort 409. Denselben Beleg zweimal anhängen: 409. `same_request` (422) gilt für `d.finding.update` und `d.finding.evidence.*` auf ein unbekanntes `finding_id`, wenn dieselbe Anfrage ein `d.finding.create` enthält (die `finding_id` entsteht erst beim Einreihen); sonst 409. `null` in `d.finding.update` lässt ein Feld unverändert (eine Schwere lässt sich nicht entfernen, nur ändern). Eine widerrufene Anlage behält ihre Nummer wie ein gelöschtes Finding. `history` nennt nur aktive Entscheide. Labels von Belegen: Terminal («T1 scan»), Befehl bzw. Datei (gekürzt auf 80 Zeichen, Secrets maskiert), «Zeile N» bzw. «Zeilen N bis M» (für Menschen ab 1 gezählt), Wert; **ohne Uhrzeit** (die steht in `ts`, die UI zeigt sie in Lokalzeit). Ein Beleg mit Zeilen ausserhalb der Einheit ist `missing`. `finding_id` mit anderen Zeichen als Hex und Bindestrich: 404. |
| Kopieren (18.7) | Eine Eingabe gilt nur als Secret, wenn sie verdeckt ist (ohne Echo, E104); sonst 404. Vor dem Kopieren wird die Eingabe wie getippt bearbeitet (Backspace/DEL löschen, Ctrl-U leert, Enter fällt weg). Enthält der Wert danach noch Steuer-, Format- oder Trennzeichen, kopiert der Daemon nichts (422). Werkzeuge sucht der Daemon in seinem `PATH` und in `/usr/local/bin:/usr/bin:/bin`; scheitert das Werkzeug (keine Verbindung zum Display), gilt `clipboard_session`. Lässt sich die Zwischenablage nach der Frist nicht zurücklesen (kein `wl-paste`), wird sie trotzdem geleert. Beim Ende des Daemons werden offene Fristen sofort abgearbeitet. `clear_after_s` nennt die eingestellte Frist (30). |
| Denkanstösse (18.6, 12) | Vor der Prüfung von `d.suggestion.*` wartet der Server, bis die Auswertung alle gespeicherten Entscheide verarbeitet hat (die Regel-Engine liest sie aus der Projektion); ein zweites «verwerfen» ergibt so sofort 409. |
| Ereignis `suggestion` (18.9) | Nach jedem Auswertungsdurchgang (gebündelt mit `inbox`) zählt der Server die offenen Denkanstösse; das Ereignis kommt nur, wenn sich die Zahl ändert. |
| Karte und Tabelle (18.8) | `as_of` ist die Zeit der jüngsten Generation. `conflict_brief` ist der erste offene Widerspruch des Hosts oder eines seiner Services (nach Kennung und Prädikat). `OosItem.note`: `same_mac` (gleiche MAC wie ein Host im Scope, `related` = dessen Kennung), sonst `forged_callback`, wenn die Adresse als Callback (`access.callback`) auftrat; `related` ist dann ein Callback im Scope aus derselben Kontextstufe (der echte neben dem fremden) oder `null`. `source` ist die Einheit der frühesten Erwähnung bzw. die erste Einheit des Hosts. |
| Host-Detail (18.8) | `access_by`: zuerst der jüngste aktive `d.status.access` auf den Host, sonst der jüngste Schlüsselschritt `foothold`/`privesc`, sonst `value` (früheste Zugriffs-Quelle); `null` ohne Zugriff. `candidate_claims` nur bei Hosts im Nebel, höchstens 20, Adressen und Namen zuerst. |
| Services (18.8) | `banner` ist `service.extrainfo` (etwa «workgroup: WORKGROUP»), `from_target` und `suspect`, wenn irgendein nicht verworfener Wert des Services so markiert ist. |
| Kontextvorschlag (18.8) | `from_ts` ist die Zeit des Blocks im Strom bei `from_off`. `excerpt.note` ist `second_callback` (zweiter Callback aus einer anderen Adresse in derselben Stufe, «Darum mehrdeutig») oder `callback` (die Zeile des vorgeschlagenen Callbacks); dazu additiv `excerpt.ts` (Zeit der Quelle). Solange die Zeilen einer offenen Einheit (laufender Listener) noch nicht gespeichert sind, ist `excerpt` `null`. Bei `ctx_unknown` ist `excerpt` in v0.1 immer `null`. |
| Zeitachse (18.8) | `result` zählt über die Evidenzgruppe des Befehls ohne misstraute Quellen: `values` = übernommene Werte (wie `adopted`), `services` = Services im Scope mit Werten aus dem Befehl, `out_of_scope` = stille Werte ausserhalb, `conflicts` = Werte in offenen Widersprüchen, `hosts_new` = Hosts im Scope, deren früheste Quelle aus diesem Befehl stammt. `evaluate_after` = letzte Ausgabe des Terminals plus 10 Minuten Stille (danach wertet die Pipeline ein offenes Segment aus), `null` bei `final`. `decision.detail` ist ein Text aus festen Wörtern und Kennungen (etwa «Zugriff root auf 192.168.56.101», «10.10.10.3 · service.product», der Titel eines Findings); `reason` ist der Grund des Menschen. |
| Kopf einer Einheit (18.8) | `chain_break_line`: Der Server prüft beim Öffnen die Ausgabe-Events des Terminals im Bereich der Einheit (höchstens 5000; Commitment, Hash, Verweis auf den Vorgänger) und nennt die erste Zeile ab dem ersten Fehler; `chain_ok` ist dann `false`, auch wenn der Kettenkopf stimmt. |
| Änderungen (7) | Schlüsselschritte melden sich in `projection_delta` als `keystep` (bis zu diesem Bau hiess die Entität dort `thread`, abweichend von 7); dazu `credential`, `url` und `other` für weitere Entitäten und `finding` (18.5). Ältere Einträge mit `thread` laufen nach 1000 Generationen aus. |
| Warteliste (18.8) | Gründe des Daemons ausserhalb der Liste (fehlt, keine Rechte, Sperrliste, Tresor) erscheinen als `path`, `symlink_or_not_dir` als `symlink`. `size` nur für reguläre Dateien (relativ zum Arbeitsordner, ohne Symlinks zu folgen). |
| Kontext setzen (5) | `ContextResult` hat additiv `decision_id: string \| null`: der geschriebene `d.ctx.set` bei `set` und `accept` (die Spalte bietet damit «Rückgängig» per `d.revoke`; danach erscheint der Kontextvorschlag wieder), `null` bei `push` und `pop` und wenn nichts gespeichert wurde. Der Live-Stapel eines laufenden Terminals bleibt nach dem Widerruf, wie er ist (nur die Auswertung folgt dem Widerruf). |
| Nummern der Klärungen (9) | Jeder Eintrag in `clarify` hat additiv `ordinal: number \| null`: stabile Nummer («K2»), vergeben beim ersten Auftreten (nach jeder Auswertung und bei `/next`) in der Reihenfolge der Liste und in `state.db` (Tabelle `ui_item`, ausserhalb der Hash-Kette) gemerkt. Erledigte Klärungen behalten ihre Nummer, die Nummer am Ring auf der Karte verschiebt sich nicht. |
| Zeitachse, Kontext (10) | `TimelineItem` vom Typ `context` hat additiv `host_label: string \| null` (Host der Stufe für «Kontext automatisch: 192.168.56.101 (auto)»), `stage_kind: StageKind \| null` (rechts «msf») und `user: string \| null`; `stack_label` bleibt. |
| Kopf einer Einheit (11) | `UnitView.tty: string \| null`: Gerät aus `term.open` («/dev/pts/2»; Belegansicht «Quelle pts/2 · Quell-IP …»), nur Pfade unter `/dev/`. |
| Denkanstösse, Encoder (18.6) | Strenger als die Tabelle in 18.6 (Einzelheiten [denkanstoesse.md](denkanstoesse.md) 6): `~` und `^` gelten als Metazeichen; ein führender Bindestrich ist bei `word`, `words`, `user` und `share` `invalid`; `$` ist bei `share` nur am Ende erlaubt; keine IPv6-Zonen-ID; keine URL mit IPv6-Host; keine URL mit Benutzerangabe. Vorlagen mit Anmeldeversuch (Standardkonten, Datenbank) gibt es nur im Profil lab. |
| Denkanstösse, Prüfziele (18.6) | Neue Prüfziel-IDs: `PZ-SMB-SHARES`, `PZ-NFS-EXPORTS`, `PZ-PORTS-TCP`, `PZ-PORTS-UDP`, `PZ-CRED-DEFAULT`, `PZ-SMTP-USER`, `PZ-DB-ZUGRIFF` (Katalog in [denkanstoesse.md](denkanstoesse.md) 5). |
| Denkanstösse, Entscheide (18.6, 12) | 409 `conflict`: unbekannter `suggestion_key`, `d.suggestion.dismiss` auf einen verworfenen, `d.suggestion.done` auf einen erledigten oder mit veralteter `basis`. 422 `basis_required`: `d.suggestion.done` ohne `basis`. |
| Denkanstösse, Belege (18.6) | `evidence[].label` lautet «nmap -sV · 14:02 · Zeile 6»: Werkzeug und Optionen, Lokalzeit des Daemons, Zeile für Menschen ab 1 gezählt (`lines[0] + 1`). In `CommandTemplate.values` ist der erste Eintrag das Werkzeug (`slot: 'tool'`, `target: false`); bei `searchsploit` ist jedes Wort von Produkt und Version ein eigener Wert. |

## Anhang: Lücken aus Briefing B.4 und wo sie jetzt stehen

| Lücke in B.4 | v2 |
|---|---|
| Felder für Terminal-Zustände, Leerlauf, Vorlauf und Herkunft fehlen in `/status` | `Status.terminals`, `idle`, `preroll` (mit Ausfallpuffer), `session.origin` |
| Pause und Fortsetzen pro Terminal fehlen, `PUT /rec` überholt | `POST /terminals/{tid}/pause`, `…/resume`; kein REC |
| `held` mit Slug | `TerminalState.held_slug` |
| Inbox-Modell weicht vom Backend ab | `/next` mit den echten Arten aus `inbox_item` |
| `adopted`, `distrusted`, `cmd_ref` fehlen in der Zeitachse | `TimelineItem` `command` |
| `d.unit.distrust` fehlt | `POST /decisions` mit `d.unit.distrust` (allein), Aufheben mit `d.revoke` |
| `rec` als Ereignis überholt, Ereignisse für Pause, `held`, Vorlauf, Kontext «auto», Scope-Warnung fehlen | `terminal` mit `change`, Scope-Warnung am Befehl in der Zeitachse |
| Herkunft der Sitzung, Volltextsuche, eigene Secrets aufdecken | `GET /session`, `GET /search`, 13.3 (eigene Secrets bewusst nicht) |
| Datei aus der Warteliste übernehmen, Export-Vorschau, Session abspielen, Phasenzuordnung | Abschnitt 15 |
