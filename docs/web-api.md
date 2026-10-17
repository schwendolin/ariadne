# Ariadne: HTTP-API der Web-Oberfläche (v2)

> **Verbindlich für den Bau v0.1-Server.** Stand 2026-10-17 (Phase 1, nach Prüfung überarbeitet: Peer-Bindung bei Weg B, `d.unit.distrust` über `/decisions`, Ereignisquellen). Ersetzt den Entwurf vom 2026-10-09 (v1). Grundlage sind die Entscheide vom 2026-10-15 (E22, E23, E26, E42, E45, E60, E72, E74, E86 bis E104), das [Konzept Fernzugriff](konzept-fernzugriff.md) (Regeln R1 bis R14, Tests T1 bis T16), die [Lösungsarchitektur](architektur.md) (7, 8.5, 8.6, 9.2), die Funktionsbeschreibung des Dashboards ([dashboard-funktionen.md](ui/dashboard-funktionen.md), Anhang B.4 und B.5) und der echte Datenbestand: `ingest/queries.py`, `ingest/schema_claims.py`, `ingest/schema_units.py`, `ingest/inputs.py`, `cli/views.py` und die ctl-Operationen in `daemon/core.py` und `daemon/ops_eval.py`.
>
> Das Dokument heisst «v2», weil sich das Modell gegenüber v1 grundlegend geändert hat (Daueraufnahme statt REC, Arbeitsliste «Als Nächstes» statt Inbox, Eingaben, Sitzungen mit Peer-Bindung). Der Pfad bleibt `/api/v1`; `GET /status` meldet `api_version: 2`. Später ist das OpenAPI-Schema der FastAPI-App der verbindliche Vertrag, und die UI erzeugt ihre Typen daraus (`openapi-typescript`). Die Svelte-Oberfläche (`webui/`) ändert sich in diesem Bau nicht; ihre Typen folgen dem Design des Nutzers.

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

## 1 Grundregeln

### 1.1 Transport und Sicherheit

Die Regeln R1 bis R3, R5 bis R8 und R12 aus dem Konzept Fernzugriff (5.4) und Architektur 7.2 gelten ohne Ausnahme. Es gibt keinen Schalter, der eine davon aufhebt.

| Thema | Regel | Regel-Nr. |
|---|---|---|
| Bindung | nur `127.0.0.1` oder `::1`, Standardport 7330 (`[ui] port` in `config.toml`, `0` nur für Tests). Jede andere Adresse lehnt die Konfiguration ab, der HTTP-Teil startet dann nicht (fail-closed), die Aufnahme läuft weiter. Nach dem Start prüft der Server `getsockname()`. Nur HTTP/1.1, kein TLS | R1, E89 |
| Peer | Jede TCP-Verbindung muss einem Socket desselben Benutzers gehören (UID über `/proc/net/tcp` bzw. `tcp6`), sonst wird sie ohne Antwort geschlossen. Jedes Token ist an einen Prozess gebunden (PID und Startzeit) und gilt nur, solange dieser lebt. **lokal** (Weg E): der Prozess hinter der Verbindung beim Tausch Code gegen Token (Browser in der Kali, gefunden über den Socket in `/proc/<pid>/fd`); jede spätere Verbindung muss zu genau diesem Prozess gehören. **über sshd** (Weg B): der sshd-Prozess der SSH-Verbindung, über die `ariadne remote serve code` den Code geholt hat; diese Verbindung trägt auch den Tunnel. Der sshd-Prozess ist nach dem Rechtewechsel nicht lesbar («nicht dumpable»), darum gilt: Eine Verbindung, deren Prozess lesbar ist, muss der gebundene sein; eine Verbindung ohne lesbaren Prozess wird nur bei einer sshd-Sitzung angenommen | R2 |
| Host | `Host` exakt `127.0.0.1:PORT`, `localhost:PORT` oder `[::1]:PORT`, sonst 421. Keine Ausnahme für `*.ts.net`, Tunnel-Dienste oder Lab-IPs | R3 |
| Fetch-Metadaten | `Sec-Fetch-Site` nur `same-origin` oder `none` (oder fehlend, etwa bei `curl`), sonst 403, auch für statische Dateien und `/api/v1/session` | R12 |
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
- **Secrets maskiert**: Secret-Werte als `"••••••••"` ohne Längenangabe. Klartext gibt es nur über eine ausdrückliche Aufdeck-Aktion für genau einen Wert (13.3), nur im Profil lab und nicht im Präsentationsmodus.
- **Eigene Secrets** (sudo-Passwort, Passphrase, Recovery-Code) ersetzt der Server an jedem Ausgang mit `Redactor.redact_json` (E72), auch in aufgedeckten Werten. Über HTTP gibt es sie nie im Klartext.
- **Präsentationsmodus** (Architektur 7.8): Der Server maskiert zusätzlich alle Secret-Bereiche in Logzeilen und Eingaben und verweigert jedes Aufdecken (403 `policy`).
- **Eingaben ohne Echo** (E104) erscheinen als `"••••••••"` (Abschnitt 10.3).

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

Eine Pause über 30 Minuten gibt es über das Web nicht (Briefing 9.10, kritische Operation): 403 `policy`; im Terminal geht sie mit `ariadne pause --minutes N` (bis 240). Den neuen Zustand zeigt die UI erst nach dem SSE-Ereignis `terminal` (bis dahin «wartet auf Bestätigung»; nach 5 s ohne Ereignis lädt sie `/status`). Fehler: 404 (Terminal unbekannt), 422.

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
  changes: { generation: number; entity: 'host' | 'service' | 'claim' | 'inbox' | 'keystep' | 'unit';
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
  suggestions: Suggestion[];          // «Denkanstösse»: v0.1 leer (Regeln und KI folgen), siehe 15
  suggestions_available: boolean;     // v0.1 false
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
  length: number;                     // Bytes
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
| `d.suggestion.done`, `d.suggestion.dismiss` | `{ suggestion_key, reason? }` | Denkanstoss erledigt, verworfen | [501 bis v0.2] |
| `d.finding`, `d.artifact`, `d.hypothesis`, `d.goal.status` | | Findings, Artefakte | [501 bis v0.2] |

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

Volltextsuche über die aufgenommene Ausgabe (ohne Prompt-Echo), als Phrase; bekannte Secrets maskiert (`queries.search`). `q` 1 bis 200 Zeichen, `limit` Standard 50, höchstens 200. Die Befehlspalette sucht Ansichten, Hosts und Befehle in den geladenen Daten selbst und ruft diese Route nur für den Rohlog.

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
| `suggestion` | `{ project_id, open: number }` | v0.2 |
| `project` | `{ project_id: string \| null, change: 'opened' \| 'closed' \| 'locked' \| 'unlocked', locked: boolean }` | **alle Daten verwerfen**, laufende Abrufe abbrechen, `/status` neu laden |
| `reset` | `{ reason: 'reparse' \| 'buffer' \| 'restart' }` (auch, wenn die Generation zurückspringt) | alles neu laden |
| `presentation` | `{ on: boolean }` | Kennzeichen, Logzeilen und offene Belege neu laden |
| `progress` | `{ job_id, kind, status, pct: number \| null, message: string \| null }` | v0.1 nur `reparse` (aus dem Daemon-Ereignis `job`; nach `done` folgt `reset` mit `reason: 'reparse'`); `message` ist fester deutscher Text, nie Ziel- oder Modelltext |

Der Strom läuft auch ohne Projekt und bei gesperrtem Projekt; dann kommen nur `terminal`, `project` und `presentation`.

## 15 Später

| Endpunkt | Zweck | Stand |
|---|---|---|
| `POST /p/{pid}/ai/denkanstoss` | KI-Denkanstoss auf Knopfdruck (Architektur 6.3): Lagebild, höchstens 4 Anstösse, Kosten, Ablehnung nie umformuliert; Job per SSE `progress` | [501 bis v0.1-KI] |
| `GET /p/{pid}/suggestions`, Denkanstösse aus Regeln | Regeln, Prüfziele, Befehlsvorlagen nur vom Server mit typisierten Platzhaltern (E68), Lernmodus | [501 bis v0.2]; v0.1 liefert `suggestions: []` in `/next` |
| `POST /p/{pid}/exports`, `GET …/exports` | Markdown-Export (Architektur 8.7), Vorlagen `cys` und `htb` | [501 bis v0.1-Export] |
| `POST /p/{pid}/screenshots` | Screenshot mit Countdown (`mode`, `delay_s`) | [501 bis v0.1-Screenshots] |
| `GET /p/{pid}/findings`, `d.finding` | Findings (Titel, Schwere, Belege, Massnahme, ATT&CK) | [501 bis v0.2] |
| `GET /p/{pid}/credentials`, `/cred-matrix`, `/credentials/{id}/copy` | Credentials, Matrix, Kopieren in die Kali-Zwischenablage | [501 bis v0.2] |
| `POST /p/{pid}/query`, `POST …/ai/frage` | DSL-Abfragen, Fragen an die Karte (E61) | [501 bis v0.2] |
| `GET /p/{pid}/blobs/{id}` | Bilder | [501 bis v0.2] |
| Datei aus der Warteliste übernehmen (`d.file.accept`) | Knopf statt `ariadne import` | [v0.2] |
| Session abspielen, Export-Vorschau, Phasenzuordnung | | [v0.2] bis [v0.4] |

Jede Route mit Marke «501» existiert in diesem Bau, durchläuft dieselbe Middleware und Anmeldung und antwortet dann `501 { error: { code: 'not_implemented', message: 'Kommt in einer späteren Version.' } }`.

## 16 Offene Punkte

1. **Kritische Operationen** (Architektur 7.2.7, Briefing 9.10): Scope erweitern, «kein Kundenauftrag», Klartext-Export, Pause über 30 Minuten. v0.1 antwortet 403 `policy` und verweist ins Terminal. Ein zweiter Kanal (Dialog auf dem Kali-Desktop mit Anzeige des anfragenden Prozesses) ist offen.
2. **Eigene Secrets aufdecken** (E99): über HTTP nie (13.3). Ob die UI sie überhaupt zeigen soll oder nur ihre Labels, entscheidet der Nutzer.
3. **Bezugspunkt «Neu seit»** (Briefing 13.1, Frage 2): ohne Browser-Speicher geht er beim Neuladen verloren. Vorschlag: `GET/PUT /p/{pid}/ui/seen` in `state.db`, wie die Positionen.
4. **Mehrere Tabs**: je ein Strom (höchstens 8 pro Sitzung). Später `BroadcastChannel`.
5. **Peer-Bindung bei Weg E**: Ob Firefox in der Kali alle Anfragen aus demselben Prozess stellt (Socket-Prozess), ist zu verifizieren. Wechselt der Prozess, endet die Sitzung (lieber neu anmelden als ein fremdes Token annehmen).
8. **Peer-Bindung bei Weg B**: Der sshd-Prozess der Sitzung ist für den eigenen Benutzer nicht lesbar (nach dem Rechtewechsel nicht «dumpable»), seine Sockets lassen sich ihm also nicht zuordnen. Gebunden wird darum an die SSH-Verbindung, die den Code geholt hat (PID über `ctl.sock` und die Eltern von `remote serve`), und jede Verbindung mit lesbarem Prozess muss genau dieser sein. Ein anderer, ebenfalls nicht lesbarer Prozess desselben Benutzers könnte ein gestohlenes Token benutzen, solange der Tunnel steht; ein solcher Prozess kann aber ohnehin `ctl.sock` erreichen und Codes holen (gleiche UID, Architektur 9.1 A4).
6. **Positionen bei Merge und Split**: Wer verschiebt gespeicherte Positionen, wenn sich die stärkste Kennung eines Hosts ändert? v0.1: die UI legt einen unbekannten Knoten neu.
7. **IP-Adressen in der URL** (Briefing 13.3): `?host=ip:default/…` steht im Browserverlauf. v0.1 erlaubt es; neutrale IDs wären eine spätere Änderung.

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
