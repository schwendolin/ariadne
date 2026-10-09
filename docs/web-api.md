# Ariadne: HTTP-API der Web-Oberfläche

> **Entwurf, Backend folgt.** Stand 2026-10-09. Dieses Dokument beschreibt die Schnittstelle zwischen `ariadned` und der Web-UI so, wie die UI sie heute erwartet. Der Daemon implementiert sie noch nicht. Die UI läuft bis dahin im Mock-Modus (`webui/src/lib/mock/`), der genau diesen Vertrag nachbildet. Grundlage sind die [Lösungsarchitektur](architektur.md), Abschnitte 5.3, 5.7 bis 5.10, 6.3, 7.2 bis 7.8 und 9, sowie die Verträge in `src/ariadne/events.py`, `ontology.py`, `parsers/api.py` und `scope/api.py`.
>
> Später ist das OpenAPI-Schema der FastAPI-App der verbindliche Vertrag, und die UI erzeugt ihre Typen daraus (`openapi-typescript`). Bis dahin spiegelt `webui/src/lib/api/types.ts` dieses Dokument. Wer hier etwas ändert, ändert dort mit.

## Inhalt

1. [Grundregeln](#1-grundregeln)
2. [Gemeinsame Typen](#2-gemeinsame-typen)
3. [Anmeldung](#3-anmeldung)
4. [Status, REC, Präsentation](#4-status-rec-präsentation)
5. [Terminals und Kontext](#5-terminals-und-kontext)
6. [Karte und Änderungsfeed](#6-karte-und-änderungsfeed)
7. [Listen](#7-listen)
8. [Belege](#8-belege)
9. [Entscheide](#9-entscheide)
10. [Abfragen](#10-abfragen)
11. [KI und Auslöser](#11-ki-und-auslöser)
12. [Ereignisstrom (SSE)](#12-ereignisstrom-sse)
13. [Offene Punkte](#13-offene-punkte)

## 1 Grundregeln

### 1.1 Transport und Sicherheit

| Thema | Regel |
|---|---|
| Bindung | `127.0.0.1:7330` (konfigurierbar), nur HTTP/1.1 über Loopback. Der Daemon prüft bei jeder Verbindung die UID des Clients |
| Präfix | alle Pfade unter `/api/v1`, projektbezogene unter `/api/v1/p/{pid}`. Alles andere ist die SPA (Abschnitt 1.5) |
| Anmeldung | `Authorization: Bearer <token>` auf jeder Route ausser `POST /session`. Keine Cookies, daher kein CSRF |
| Middleware vor jeder Route | `Host` exakt `127.0.0.1:7330` (sonst 421), `Sec-Fetch-Site` nur `same-origin` oder `none` (sonst 403, auch für statische Dateien), `Origin` bei `POST`, `PUT`, `DELETE` nur der eigene, kein CORS, `OPTIONS` ergibt 405, Tokenvergleich mit `hmac.compare_digest` |
| Header der SPA-Shell | `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob:; connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`, dazu `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin` |
| Header aller anderen Antworten | `Content-Security-Policy: default-src 'none'; sandbox`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff` |
| Logs | nur Metadaten. Kein Pfadparameter, keine Query, keine Bodies im Access-Log (Architektur 8.6) |

Die UI hält sich an die CSP ohne Ausnahme: kein Inline-Skript, kein Inline-Style, keine `data:`-URIs. Geprüft mit `vite preview`, das dieselben Header setzt.

### 1.2 Format

- JSON in UTF-8, `Content-Type: application/json`. Antworten ausser Blobs und SSE sind immer JSON, auch Fehler.
- **Zeitpunkte** als ISO-8601-String in UTC mit Mikrosekunden: `"2026-10-08T12:02:11.123456Z"`. Nanosekunden aus dem Journal (`ts_utc_ns`) gehen nie als JSON-Zahl über die Leitung, denn sie liegen über 2^53. Wo die exakte Ordnung zählt, kommt zusätzlich `ts_ns` als Dezimalstring.
- **Stream-Offsets** und Zeilennummern sind Ganzzahlen. Zeilen sind 0-basiert, Bereiche `[start, ende]` mit inklusivem Ende, wie `Span` in `parsers/api.py`.
- **Konfidenz** kommt als Zahl (0 bis 1, intern noisy-OR) und als Stufe `high | medium | low` (Grenzen 0.9 und 0.6). Die UI zeigt nur die Stufe.
- Felder, die es nicht gibt, sind `null`, nicht weggelassen. So bleibt das Schema für die UI stabil.
- Unbekannte Felder in Requests lehnt der Server mit 422 ab (`extra="forbid"` wie in `events.py`).

### 1.3 Bezeichner

| Bezeichner | Form | Hinweis |
|---|---|---|
| `pid` | UUIDv7 des Projekts | |
| `tid` | `terminal_id`, UUIDv7 | überall genau dieser Name (Architektur 5.3) |
| Kennung | `ip:default/10.10.10.3`, `fqdn:lame.htb`, `mac:...`, `svc:ip:default/10.10.10.3\|tcp/445`, `id:local:ip:default/10.10.10.4\|msfadmin`, `url:...` | Format aus `parsers/api.py` (`Ref`). Hosts und Services werden über ihre stärkste Kennung adressiert, nie über eine Entitäts-UUID, damit Merges und Reparse die Adresse nicht ändern |
| `fact_id` | gleich `claim_key` (64 Hex-Zeichen) | natürlicher Schlüssel, übersteht Reparse. Für Secrets ist es ein HMAC (Architektur 5.7) |
| `cmd_id` | `<terminal_id>@<stream_off des C-Markers>` | aus `ids.cmd_id` |
| `unit_id` | stabil pro Einheit | Befehl, Segment, Datei oder Bild |
| `blob_id` | zufällige ID | nie der SHA-256 (Architektur 5.1) |
| `suggestion_key` | `regel_id` plus sortierte natürliche Schlüssel | verworfen bleibt verworfen |

**Pfadsegmente.** Kennungen enthalten `/`, `:` und `|`. Die UI kodiert jedes Segment einzeln (`encodeURIComponent`), also `ip%3Adefault%2F10.10.10.3`. uvicorn dekodiert `%2F` vor dem Routing; Routen, deren letztes Segment eine Kennung ist, brauchen deshalb den Konverter `{host_id:path}`. Kennungen kommen nur als letztes Segment vor.

### 1.4 Fehler

Jeder Fehler hat dieses Format:

```ts
interface ApiErrorBody {
  error: {
    code: ApiErrorCode;
    message: string;              // deutscher Klartext, nie Zieldaten, nie Exception-Text
    detail?: { loc: (string | number)[]; type: string }[];   // nur bei 422, ohne Werte
    request_id?: string;
  };
}

type ApiErrorCode =
  | 'unauthorized'      // 401 Token fehlt, ist abgelaufen oder widerrufen
  | 'forbidden'         // 403 Host, Origin oder Sec-Fetch-Site falsch
  | 'policy'            // 403 Profil oder Policy verbietet es (z. B. Cloud-KI im Profil customer)
  | 'budget'            // 403 KI-Budget erschöpft
  | 'not_found'         // 404
  | 'no_project'        // 409 kein aktives Projekt
  | 'project_mismatch'  // 409 pid ist nicht das aktive Projekt
  | 'conflict'          // 409 Entscheid passt nicht mehr (verwaist, veraltet)
  | 'locked'            // 423 Projekt gesperrt, `ariadne unlock` nötig
  | 'validation'        // 422 Eingabe ungültig
  | 'rate_limited'      // 429 zu viele Codeversuche
  | 'llm_unavailable'   // 503 KI-Provider nicht erreichbar
  | 'internal';         // 500
```

Die UI übersetzt nur über `code`. `message` dient der Diagnose und erscheint nie ungeprüft im UI. Für jede projektbezogene Route gelten zusätzlich: 401, 409 `no_project` und `project_mismatch`, 423 `locked`. Sie stehen unten nicht jedes Mal dabei.

### 1.5 SPA-Auslieferung

Alle Pfade ausserhalb von `/api/` liefern die SPA-Shell `index.html` aus `src/ariadne/web/static/`, damit der History-Router funktioniert (`/karte`, `/inbox`, `/terminals`, `/zeitachse`, `/denkanstoesse`, `/findings`, jeweils mit Query wie `?host=` und `?fact=`). Statische Dateien unter `/assets/` mit Hash im Namen dürfen gecacht werden (`Cache-Control: public, max-age=31536000, immutable`), die Shell nicht.

## 2 Gemeinsame Typen

Literale stammen aus `events.py`, `ontology.py`, `parsers/api.py` und `scope/api.py`.

```ts
// events.py
type StageKind = 'local' | 'su' | 'ssh' | 'winrm' | 'remote' | 'revshell' | 'msf' | 'meterpreter' | 'db' | 'unknown';
type StageState = 'active' | 'suspended';
type StageSource = 'auto' | 'hotkey' | 'webui' | 'cli' | 'suggestion';
type Keystep = 'foothold' | 'privesc' | 'pivot' | 'loot';
type WorkStatus = 'open' | 'in_progress' | 'dead_end' | 'done' | 'out_of_scope';
type AccessLevel = 'none' | 'user' | 'admin';
type GapReason = 'rec_off' | 'buffer_overflow' | 'daemon_down' | 'project_switch'
               | 'sensitive_output' | 'locked' | 'disk_low' | 'shim_error';
type Profile = 'lab' | 'customer';

// parsers/api.py, scope/api.py
type Trust = 'user' | 'structured' | 'tool_text' | 'heuristic' | 'ai' | 'ocr';
type VerdictKind = 'in' | 'out' | 'excluded' | 'outside_window' | 'unknown';

// Architektur 5.7 und 5.9
type ClaimState = 'candidate' | 'auto' | 'confirmed' | 'rejected';
type ConfidenceLevel = 'high' | 'medium' | 'low';
type Knowledge = 'discovered' | 'scanned' | 'versions';
type Progress = 0 | 1 | 2 | 3 | 4 | 5;

// ontology.py (MapLayer ohne 'none') plus UI-Ebenen
type MapLayer = 'topology' | 'services' | 'creds' | 'attack' | 'web' | 'ad';
type GraphLayer = MapLayer | 'oos' | 'fog';
type Lens = 'karte' | 'faden';

interface StageView {           // Stage aus events.py, aufgelöst für die Anzeige
  depth: number;                // 0 = Kali
  kind: StageKind;
  host: string | null;          // eingegebene Kennung, z. B. 'ip:default/10.10.10.5'
  host_label: string | null;    // aufgelöster Host (Zieldaten!)
  host_id: string | null;       // stärkste Kennung des Hosts, falls bekannt
  user: string | null;
  state: StageState;
  source: StageSource;
  candidate: string | null;     // Ziel-Kandidat aus argv, unbestätigt
  opened_at: number;            // Stream-Offset
  scope: VerdictKind | null;
}

interface CommandRef {
  cmd_id: string;
  text: string | null;          // null, wenn die Shell den Text nicht lieferte
  started_at: string;
  ended_at: string | null;
  exit: number | null;
  src_ip: string | null;        // aus net.route
  origin: 'local' | 'remote_confirmed' | 'remote_reconstructed';   // Architektur 5.13
}

interface EvidenceRef { fact_id: string | null; label: string }
```

**progress** ist eine reine Funktion (Architektur 5.9) und wird nie direkt gesetzt:

| access | knowledge | progress |
|---|---|---|
| `admin` | beliebig | 5 |
| `user` | beliebig | 4 |
| `none` | `versions` | 3 |
| `none` | `scanned` | 2 |
| `none` | `discovered` | 1 |
| `none` | (nur erwähnt) | 0 |

## 3 Anmeldung

Architektur 7.2. `ariadne ui` holt über `ctl.sock` einen Einmalcode (128 Bit, 60 s, einmal gültig), schreibt eine Startdatei (0600) nach `$XDG_RUNTIME_DIR/ariadne/` und öffnet sie per `file://`. Die Startdatei leitet auf `http://127.0.0.1:7330/#c=<code>` weiter. Das Fragment geht nie an den Server. Die SPA liest es, entfernt es sofort per `history.replaceState` und tauscht den Code gegen ein Token. Das Token liegt nur in `sessionStorage`, nie in `localStorage`.

### POST /api/v1/session

Zweck: Einmalcode gegen ein Sitzungstoken tauschen. Einzige Route ohne Bearer.

```ts
// Request
interface SessionRequest { code: string }          // [A-Za-z0-9_-]{8,128}
// Response 200
interface SessionResponse {
  token: string;        // 256 Bit, base64url, mindestens 43 Zeichen
  expires_at: string;   // höchstens 12 h
}
```

Fehler: 401 `unauthorized` (Code unbekannt, abgelaufen, schon benutzt), 429 `rate_limited` (nach 5 Fehlversuchen pro Minute werden alle Codes ungültig), 422 `validation`.

### DELETE /api/v1/session

Zweck: eigenes Token widerrufen (Abmelden). Response 204. `ariadne ui --revoke` widerruft alle Tokens.

Die Web-UI fragt **nie** nach einer Passphrase. Entsperren geht nur per CLI (`ariadne unlock`). Eine Route dafür gibt es absichtlich nicht.

## 4 Status, REC, Präsentation

### GET /api/v1/status

Zweck: globaler Zustand für Kopfzeile und Projektwahl. Funktioniert auch ohne Projekt und bei gesperrtem Projekt.

```ts
interface Status {
  version: string;
  api: 1;
  operator_id: string;
  server_time: string;
  project: ProjectInfo | null;        // aktives Projekt, auch wenn gesperrt
  locked: boolean;
  rec: RecState;
  llm: LlmState;
  presentation: boolean;
  automode: AutomodeState | null;     // aus d.automode.set, null ohne Projekt
  learning_mode: boolean;             // Lernmodus der Denkanstösse (lab: an)
  generation: number | null;          // aktuelle Projektionsgeneration
}
interface ProjectInfo {
  id: string;
  slug: string;                       // im Profil customer ein Codename
  name: string;
  profile: Profile;
  created_at: string;
  scope_version: number;              // Version aus d.scope.update
  lab_guard: { public_targets: boolean; confirmed_not_customer: boolean } | null;  // Architektur 8.1
}
interface RecState {
  on: boolean;
  mode: 'off' | 'on' | 'waiting' | 'offline';   // waiting = REC an, Projekt gesperrt
  since: string | null;
  source: 'webui' | 'cli' | 'hotkey' | 'system' | null;   // RecSet.source
  terminals_recording: number;
}
interface LlmState {
  mode: 'off' | 'local' | 'cloud';
  model: string | null;               // z. B. 'claude-opus-5-5'
  available: boolean;
  budget: { month_limit_usd: number; month_used_usd: number } | null;
}
interface AutomodeState { enabled: boolean; parsers: string[]; auto_ctx: boolean }
```

Fehler: 401.

### PUT /api/v1/rec

Zweck: REC für alle Terminals umschalten. Schreibt `rec.set` mit `source = 'webui'`.

```ts
// Request
interface RecRequest { on: boolean }
// Response 202
interface Accepted { accepted: true }
```

Der neue Zustand kommt **nur** per SSE-Ereignis `rec`. Die UI zeigt bis dahin «wartet auf Bestätigung», denn auch Hotkey und CLI schalten REC. Bleibt `rec` 5 s aus, lädt die UI `/status` nach.

Fehler: 409 `no_project`. Bei gesperrtem Projekt ist REC an erlaubt (Modus `waiting`).

### PUT /api/v1/presentation

Zweck: Präsentationsmodus global schalten (Architektur 7.8). Request `{ on: boolean }`, Response 202, Bestätigung per SSE `presentation`. Maskiert wird auf dem Server.

## 5 Terminals und Kontext

### GET /api/v1/terminals

Zweck: alle Terminals mit Kontextstapel, für die Terminal-Ansicht. Global, weil Terminals vor dem ersten REC noch keinem Projekt gehören. Die UI zeigt nur Terminals mit `project_id` gleich dem aktiven Projekt oder `null`.

```ts
interface TerminalsResponse { terminals: Terminal[] }
interface Terminal {
  terminal_id: string;
  label: string | null;               // d.terminal.label
  tty: string | null;
  shell: string;
  alive: boolean;
  project_id: string | null;          // term.bind
  recording: boolean;
  paused_reason: GapReason | null;
  opened_at: string;
  last_activity: string | null;
  last_command: CommandRef | null;
  stack: StageView[];                 // unten immer Kali
  suggestion: { suggestion_key: string; host: string; user: string | null; reason: string } | null;  // ab v0.2
}
```

### POST /api/v1/terminals/{tid}/context

Zweck: Kontext setzen, eine Stufe darüber öffnen, die oberste schliessen oder einen Vorschlag annehmen. Der Server schreibt den passenden Entscheid (`d.ctx.set`, `d.ctx.push`, `d.ctx.pop`, `d.ctx.accept`) und setzt `stream_off` auf den aktuellen Offset, ausser `from_off` ist angegeben (rückwirkend).

```ts
type ContextOp =
  | { op: 'set'; depth?: number; host?: string | null; user?: string | null; kind?: StageKind; from_off?: number }
  | { op: 'push'; kind?: StageKind; host?: string | null; user?: string | null }
  | { op: 'pop' }
  | { op: 'accept'; suggestion_key: string };

// Response 200
interface ContextResult {
  decision_id: string;
  warnings: { code: 'scope_out' | 'scope_excluded' | 'scope_unknown' | 'host_unknown'; identifier: string }[];
}
```

`host` darf eine Kennung oder ein roher Wert sein (`10.10.10.9`, `web01`). Der Server normalisiert über `ariadne.scope.normalize`, speichert die eingegebene Kennung (nie eine Host-UUID) und löst erst in der Projektion auf (Architektur 3.5). Ein Ziel ausserhalb des Scopes ist erlaubt, ergibt aber eine Warnung.

Fehler: 404 `not_found` (Terminal unbekannt), 422 `validation` (`pop` auf Kali, Stufe existiert nicht), 409 `conflict` (Terminal an anderes Projekt gebunden), 423 `locked`.

## 6 Karte und Änderungsfeed

### GET /api/v1/p/{pid}/graph?layer=&lens=

Zweck: Graph-Projektion für die Karte. `layer` ist eine Komma-Liste aus `GraphLayer` (Standard `topology,services,attack,oos,fog`), `lens` ist `karte` (v0.1) oder `faden` (v0.2). `topology` ist immer dabei.

```ts
interface GraphView {
  project_id: string;
  generation: number;
  lens: Lens;
  layers: GraphLayer[];
  nodes: GraphNode[];
  edges: GraphEdge[];
  oos: { out: number; excluded: number; unknown: number; items: OosItem[] };   // am Rand zusammengefasst
}
type GraphNode = KaliNode | SegmentNode | HostNode | ServiceNode;

interface KaliNode { kind: 'kali'; id: 'kali'; label: string; addresses: string[] }

interface SegmentNode {
  kind: 'segment';
  id: string;                         // 'seg:default/10.10.10.0/24'
  label: string;
  cidr: string;
  scope: VerdictKind;
  origin: 'scope' | 'observed';       // aus dem Scope gezeichnet oder aus Funden
  via_pivot: string | null;           // Host-Kennung des Pivots
}

interface HostNode {
  kind: 'host';
  id: string;                         // stärkste Kennung
  segment: string | null;             // Compound-Eltern
  label: string;                      // Zieldaten!
  addresses: string[];
  names: string[];
  identifiers: { key: string; scope: VerdictKind; rule: string | null }[];
  scope: VerdictKind;                 // Urteil der Hauptkennung
  claim_state: ClaimState;            // candidate = Nebel
  confidence: ConfidenceLevel;
  knowledge: Knowledge;
  access: AccessLevel;
  work: WorkStatus;
  work_reason: string | null;         // Grund der Sackgasse
  progress: Progress;
  os: string | null;
  service_counts: { web: number; smb: number; db: number; remote: number; file: number; mail: number; other: number };
  services_total: number;
  conflicts: number;
  findings: number;
  hints: { total: number; high: number };
  ai: boolean;                        // mindestens ein angezeigter Wert vom Sprachmodell
  on_thread: boolean;
  tags: string[];
}

interface ServiceNode {
  kind: 'service';
  id: string;                         // 'svc:ip:default/10.10.10.3|tcp/445'
  host: string;
  proto: 'tcp' | 'udp';
  port: number;
  name: string | null;                // service.name
  product: string | null;             // service.product
  version: string | null;             // service.version
  class: 'web' | 'smb' | 'db' | 'remote' | 'file' | 'mail' | 'other';
  state: 'open' | 'filtered' | 'closed';
  claim_state: ClaimState;
  confidence: ConfidenceLevel;
  work: WorkStatus;
  conflicts: number;
  ai: boolean;
  cves: string[];                     // hint.cve
}

type GraphEdge = ThreadEdge | ReachEdge;
interface ThreadEdge {                // der Faden: d.keystep.mark in Reihenfolge
  kind: 'thread';
  id: string;
  seq: number;                        // ab 1, lückenlos
  step: Keystep;
  source: string;                     // Kali, Host oder Segment des vorigen Schritts
  target: string;                     // gleich source bei privesc und loot auf demselben Host
  ts: string;
  decision_id: string;
  note: string | null;
  evidence: EvidenceRef | null;
}
interface ReachEdge {
  kind: 'reach';
  id: string;
  source: string;
  target: string;                     // meist ein Segment
  via: 'direct' | 'pivot' | 'tunnel';
}
interface OosItem {
  identifier: string;
  label: string;
  verdict: 'out' | 'excluded' | 'outside_window' | 'unknown';
  rule: string | null;
  mentions: number;
}
```

Regeln für den Server:

- Hosts mit Scope-Urteil ungleich `in` erscheinen nie als Knoten, nur in `oos`. Einschluss wird nie vererbt (Architektur 5.8).
- `fog` liefert Kandidaten im Scope aus `structured`- und `tool_text`-Parsern (Architektur 5.7). Ohne `fog` fehlen Knoten mit `claim_state = 'candidate'`.
- Prädikate mit Kartenebene `none` (`service.script`) erscheinen nicht. KI-Werte tragen `ai = true`.
- Kanten zeigen nur auf Knoten, die in derselben Antwort stehen.
- Bis 200 Hosts ohne Aggregation. Darüber folgt in v0.4 ein Feld `aggregate` (semantischer Zoom).

Fehler: 422 `validation` (unbekannte Ebene).

### GET/PUT /api/v1/p/{pid}/ui/positions/{lens}

Zweck: Knotenpositionen pro Projekt und Linse speichern (Architektur 7.5). Liegt in `state.db`, ausserhalb der Hash-Kette, kein Entscheid.

```ts
// GET Response 200, PUT Request
interface Positions {
  lens: Lens;                                           // nur im GET
  positions: Record<string, { x: number; y: number }>; // Schlüssel = Knoten-ID (stärkste Kennung)
  updated_at: string | null;                            // nur im GET
}
// PUT Response 202 { accepted: true }
```

Höchstens 5000 Einträge, Koordinaten als endliche Zahlen. Fehler: 422 `validation`.

### GET /api/v1/p/{pid}/changes?since=\<generation\>

Zweck: Änderungen seit einer Generation (Architektur 5.10). Die UI ruft das nach jedem SSE-Ereignis `changes` auf und lädt gezielt nach.

```ts
interface ChangeSet {
  project_id: string;
  from: number;
  to: number;
  reset: boolean;            // since liegt ausserhalb von projection_delta: alles neu laden
  changes: Change[];         // aufsteigend nach generation
}
interface Change {
  generation: number;
  entity: 'host' | 'service' | 'claim' | 'credential' | 'suggestion' | 'finding'
        | 'terminal' | 'timeline' | 'inbox' | 'thread' | 'note';
  entity_key: string;        // Kennung, claim_key, suggestion_key ...
  change: 'added' | 'updated' | 'removed';
}
```

Höchstens 5000 Änderungen pro Antwort, sonst `reset = true`. `added` bei `host`, `service` und `credential` blendet die UI auf der Karte ein («+3 Hosts seit 14:02»). Fehler: 422 `validation` (since fehlt oder negativ).

## 7 Listen

Alle Listen sind projektbezogen und enthalten Zieldaten. Die UI zeigt jeden String über `displaySafe()`.

### GET /api/v1/p/{pid}/hosts

Zweck: Host-Tabelle und Lagebild-Streifen.

```ts
interface HostsResponse { hosts: HostSummary[] }
interface HostSummary extends Omit<HostNode, 'kind'> { first_seen: string; last_seen: string }
```

### GET /api/v1/p/{pid}/hosts/{host_id}

Zweck: Host-Detail für die Schublade (Architektur 7.4). `host_id` ist die stärkste Kennung, als letztes Pfadsegment kodiert (Abschnitt 1.3).

```ts
interface HostDetail extends HostSummary {
  services: ServiceView[];
  credentials: CredentialView[];
  facts: Fact[];                      // Claims aller Kennungen des Hosts und seiner Services
  conflicts_detail: Conflict[];
  note: { text: string; updated_at: string } | null;   // d.note.set, Markdown
  shots: Shot[];
  commands: (CommandRef & { terminal_id: string; unit_id: string })[];   // Befehle in diesem Kontext
}
interface Fact {
  fact_id: string;                    // = claim_key
  claim_key: string;
  subject: string;                    // beobachtete Kennung
  subject_label: string;
  predicate: string;                  // aus ontology.py
  value: string | number | boolean;
  state: ClaimState;
  confidence: number;
  confidence_level: ConfidenceLevel;
  trust: Trust;                       // stärkste Vertrauensklasse unter den Belegen
  parser: string | null;              // 'nmap.xml', 'llm.extract@1' ...
  ai: boolean;
  offered_by_target: boolean;         // Credential aus Banner, HTML-Kommentar oder KI (Architektur 6.4.8)
  scope: VerdictKind;
  sources_count: number;
  first_seen: string;
  last_seen: string;
  conflict_key: string | null;
  injection_suspect: boolean;
}
interface Conflict {
  conflict_key: string;
  subject: string;
  predicate: string;
  values: { value: string; claim_key: string; fact_id: string; sources_count: number; trust: Trust }[];
  resolved: { choice: string | null; keep_open: boolean } | null;
}
interface Shot {
  blob_id: string;
  taken_at: string;
  mode: 'window' | 'monitor' | 'region';
  window_title: string | null;
  terminal_id: string | null;
  note: string | null;
}
```

Fehler: 404 `not_found`.

### GET /api/v1/p/{pid}/services

Zweck: Service-Tabelle, gruppierbar («alle SMB»).

```ts
interface ServicesResponse { services: ServiceView[] }
interface ServiceView {
  service_id: string;
  host_id: string;
  host_label: string;
  proto: 'tcp' | 'udp';
  port: number;
  name: string | null;
  product: string | null;
  version: string | null;
  class: ServiceNode['class'];
  state: 'open' | 'filtered' | 'closed';
  claim_state: ClaimState;
  confidence_level: ConfidenceLevel;
  scope: VerdictKind;
  work: WorkStatus;
  auth_capable: boolean;
  conflicts: number;
  ai: boolean;
  cves: string[];
  fact_id: string | null;             // Beleg für service.state
}
```

### GET /api/v1/p/{pid}/credentials

Zweck: Credential-Tabelle. Secrets sind **immer maskiert**. Klartext gibt es nur über die beiden Routen darunter.

```ts
interface CredentialsResponse { credentials: CredentialView[] }
interface CredentialView {
  credential_id: string;
  identity: { realm: string; name: string };   // realm 'local:<host-kennung>', 'ad:<domäne>', 'app:<service>'
  secret_kind: 'password' | 'ntlm' | 'crypt' | 'hash' | 'key' | 'ticket' | 'token' | 'empty';
  secret_masked: string;                        // '••••••••' ohne Längenangabe, '(leer)' bei empty
  origin: 'target_offered' | 'cracked' | 'dumped' | 'observed' | 'user';
  claim_state: ClaimState;
  ai: boolean;
  valid_on: { service_id: string; label: string; result: 'ok' | 'admin' }[];
  untested: number;                             // ungetestete Kombinationen im Scope (Lagebild)
  fact_id: string | null;
}
```

#### POST /api/v1/p/{pid}/credentials/{credential_id}/reveal

Zweck: ein Secret einzeln aufdecken. Response `{ value: string }`. Nur im Profil lab und ausserhalb des Präsentationsmodus. Fehler: 403 `policy`.

#### POST /api/v1/p/{pid}/credentials/{credential_id}/copy

Zweck: «Kopieren ohne Anzeigen» (Architektur 7.8). Der Daemon legt den Wert per `xclip` mit `x-kde-passwordManagerHint=secret` in die Zwischenablage und leert sie nach 30 s. Response 202. Der Wert geht nie an den Browser.

### GET /api/v1/p/{pid}/cred-matrix (v0.2)

Zweck: Credential-Matrix (Architektur 5.12). Zeilen sind Credentials, Spalten auth-fähige Services im Scope.

```ts
interface CredMatrix {
  credentials: { credential_id: string; label: string; secret_kind: CredentialView['secret_kind'] }[];
  services: { service_id: string; label: string }[];
  cells: {
    credential_id: string;
    service_id: string;
    result: 'ok' | 'admin' | 'fail' | 'untested' | 'locked_out';
    attempts: number;
    last: string | null;
    evidence: EvidenceRef | null;
  }[];
  lockout: { realm: string; failures: number; threshold: number | null }[];   // Warnung bei Schwelle minus zwei
}
```

### GET /api/v1/p/{pid}/timeline?types=&terminal=&host=&cursor=&limit=

Zweck: Zeitachse. Neueste zuerst, `limit` Standard 200, höchstens 1000, `cursor` aus der vorigen Antwort.

```ts
interface TimelinePage { items: TimelineItem[]; next_cursor: string | null }
interface TimelineItem {
  id: string;
  ts: string;
  type: 'command' | 'segment' | 'rec' | 'context' | 'screenshot' | 'decision' | 'keystep' | 'file' | 'gap' | 'ai';
  terminal_id: string | null;
  host_id: string | null;
  host_label: string | null;
  title: string;                      // Zieldaten möglich (Befehlstext, Dateiname)
  detail: string | null;
  exit: number | null;
  facts: number;                      // Fakten aus dieser Einheit
  evidence: EvidenceRef | null;
}
```

Remote-Segmente heissen nie «ausgeführt», sondern «rekonstruiert», solange es keine Echo-Bestätigung gibt (Architektur 5.13). Fehler: 422 `validation`.

### GET /api/v1/p/{pid}/inbox

Zweck: offene Kandidaten, Konflikte, Kontextfragen und verwaiste Entscheide, gruppiert nach auslösender Einheit (Architektur 5.7).

```ts
interface InboxView {
  open: number;
  groups: InboxGroup[];               // neueste zuerst
  automode: AutomodeState;
}
interface InboxGroup {
  group_id: string;
  kind: 'unit' | 'context' | 'conflict' | 'merge' | 'orphan' | 'mass';   // mass: ab 256 neuen Hosts pro Einheit
  title: string;                      // z. B. Befehlstext (Zieldaten!)
  ts: string;
  unit: { unit_id: string; cmd_id: string | null; text: string | null; terminal_id: string | null; parser: string | null } | null;
  items: InboxItem[];
  summary: { hosts: number; services: number; credentials: number; other: number; out_of_scope: number; low_confidence: number };
}
interface InboxItem {
  item_id: string;
  type: 'claim' | 'conflict' | 'context' | 'merge' | 'orphan';
  claim_key: string | null;
  fact_id: string | null;
  subject: string;
  subject_label: string;
  predicate: string;
  value: string | number | boolean | null;
  confidence_level: ConfidenceLevel;
  scope: VerdictKind;
  trust: Trust;
  parser: string | null;
  ai: boolean;
  offered_by_target: boolean;
  state: ClaimState;
  conflict: Conflict | null;
  context: { terminal_id: string; terminal_label: string | null; from_off: number; candidate: string | null; kind: StageKind } | null;
  merge: { identifiers: string[]; reason: string } | null;
  orphan: { decision_id: string; kind: string; reason: string } | null;
}
```

Die Sammelbestätigung der UI bestätigt nur `claim`-Einträge mit Scope `in` und Konfidenz über `low`. `summary.out_of_scope` und `summary.low_confidence` zeigt sie getrennt an. Werte ausserhalb des Scopes bleiben Hinweise und werden nie Ziel.

### GET /api/v1/p/{pid}/suggestions?status=

Zweck: Denkanstösse aus Regeln und KI (Architektur 6.1, 6.3). `status` ist `open` (Standard), `all`.

```ts
interface SuggestionsResponse { suggestions: Suggestion[] }
interface Suggestion {
  suggestion_key: string;
  origin: { type: 'rule'; rule_id: string } | { type: 'ai'; model: string; call_id: string; prompt_version: string };
  kind: 'question' | 'hypothesis' | 'goal' | 'hint';
  goal_id: string | null;             // Prüfziel, z. B. 'PZ-AUTH-ANON'
  title: string;
  reasoning: string;
  subjects: { id: string; label: string; kind: 'host' | 'service' | 'credential' }[];
  evidence: EvidenceRef[];
  criteria: { confirmed: string; refuted: string } | null;
  stages: SuggestionStage[];          // Lernmodus: Frage, Richtung, Befehle
  status: 'open' | 'done' | 'dismissed';
  created_at: string;
  injection_suspect: boolean;
}
interface SuggestionStage {
  level: 1 | 2 | 3;
  kind: 'question' | 'direction' | 'commands';
  text: string | null;
  commands: CommandTemplateView[];    // nur Stufe 3, nur aus der Befehlsbibliothek
}
interface CommandTemplateView {
  template_id: string;
  title: string;
  renderable: boolean;                // false: Wert mit Sonderzeichen, Befehl wird nicht erzeugt
  reason: string | null;
  parts: { text: string; from_target: boolean }[];   // Anteile aus Zieldaten markiert
  copy_text: string | null;           // exakt das, was kopiert wird, ohne Zeilenumbruch am Ende
  values: { name: string; value: string }[];         // bei renderable=false einzeln kopierbar
}
```

Befehle rendert **nur der Server**, mit typisierten Platzhaltern und Kontext-Encodern (Architektur 6.1). Die UI setzt nie selbst Werte in Befehle ein und hängt beim Kopieren nie einen Zeilenumbruch an. Es gibt keinen Ausführen-Knopf.

### GET /api/v1/p/{pid}/findings

Zweck: Findings (Architektur 7.4). Ein Fakt ist kein Finding: Findings entstehen nur über `d.finding`.

```ts
interface FindingsResponse { findings: Finding[] }
interface Finding {
  finding_id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  assets: { id: string; label: string; kind: 'host' | 'service' }[];
  description: string;
  evidence: EvidenceRef[];
  mitigation: string;
  attack_ids: string[];               // MITRE ATT&CK, z. B. 'T1210'
  cves: string[];
  status: 'draft' | 'final';
  created_at: string;
  updated_at: string;
}
```

### GET /api/v1/p/{pid}/files/pending

Zweck: Warteliste des Watchers (Architektur 4.1). Response `{ files: { path: string; size: number; reason: string; seen_at: string }[] }`. Übernehmen geht über einen Entscheid (offen, siehe Abschnitt 13).

## 8 Belege

### GET /api/v1/p/{pid}/facts/{fact_id}/sources

Zweck: Belegansicht (Architektur 7.6). Zu jedem Fakt die Stellen, aus denen er stammt.

```ts
interface FactSources { fact: Fact; sources: SourceView[] }
type SourceView =
  | {
      t: 'stream';
      terminal_id: string;
      terminal_label: string | null;
      unit_id: string;
      cmd: CommandRef | null;          // null bei Remote-Segmenten
      context: StageView[];            // Kontextstapel zum Zeitpunkt
      off: [number, number];           // Byte-Bereich im Rohstrom
      lines: [number, number];         // Zeilen in der Einheit, Ende inklusiv
      parser: string;
      trust: Trust;
      truncated: boolean;
      partial: boolean;                // REC begann mitten im Befehl
    }
  | { t: 'file'; blob_id: string | null; path: string; sha256: string; lines: [number, number] | null; xpath: string | null; parser: string; trust: Trust }
  | { t: 'image'; blob_id: string; bbox: [number, number, number, number]; width: number; height: number; taken_at: string; window_title: string | null }
  | { t: 'ai'; call_id: string; model: string; quote_in: SourceView | null }   // Zitat muss wörtlich in quote_in stehen
  | { t: 'user'; decision_id: string; ts: string; operator_id: string };
```

Das entspricht den Provenienz-Zeigern aus Architektur 5.5, ergänzt um die Angaben für die Anzeige. Fehler: 404 `not_found`.

### GET /api/v1/p/{pid}/streams/{tid}/lines?unit=&from=&count=&reveal_hidden=

Zweck: bereinigte Logzeilen mit Farbspannen. Mit `unit` zählen die Zeilen innerhalb der Einheit (passend zu `SourceView.lines`), ohne `unit` über den ganzen Strom. `count` höchstens 2000. Die UI lädt seitenweise (400 Zeilen) für die virtuelle Liste.

```ts
interface LinesPage {
  terminal_id: string;
  unit_id: string | null;
  total: number;
  from: number;
  lines: LogLine[];
}
interface LogLine {
  n: number;
  text: string;                       // ohne ANSI und OSC, Steuerzeichen bleiben als Zeichen (UI macht sie sichtbar)
  sgr: { col_start: number; col_end: number; fg: string | null; bg: string | null; bold: boolean; concealed: boolean }[];
  prompt_echo: boolean;               // Bereich A bis C
  concealed: boolean;
  overwritten: boolean;
  masked: { col_start: number; col_end: number; kind: string }[];   // vom Server ersetzte Bereiche
}
```

- Farben als Namen (`red`, `bright_red`, ...). Hex-Farben sind erlaubt, die UI zeigt aber nur benannte Farben an.
- Verdeckter und überschriebener Text kommt nur mit `reveal_hidden=true` als Text, sonst ersetzt der Server ihn durch einen Platzhalter.
- **Maskierung auf dem Server:** eigene Secrets (`[REDACTED:own:<label>]`) und im Präsentationsmodus bekannte Secrets werden durch `••••••••` ersetzt, ohne Längenangabe. `masked` nennt die Bereiche im ausgelieferten Text.

Fehler: 404 `not_found`, 422 `validation`.

### GET /api/v1/p/{pid}/streams/{tid}/log.txt?unit=

Zweck: «Ganzes Log» als Textdatei mit sichtbar gemachten Escapes (wie `cat -v`). `Content-Type: text/plain; charset=utf-8`, `Content-Disposition: attachment`. Rohbytes gibt es nur als `log.raw` mit Warnung in der UI. Bis die Route existiert, setzt die UI die Datei aus `/lines` zusammen.

### GET /api/v1/p/{pid}/blobs/{blob_id}

Zweck: Bilder (Screenshots) für die UI. Die UI holt sie per `fetch` mit Bearer und zeigt sie als `blob:`-URL (die CSP erlaubt `img-src blob:`).

- Nur `image/png`, `image/jpeg`, `image/webp`, nach der Neukodierung im Worker (Architektur 4.3).
- Alles andere kommt als `application/octet-stream` mit `Content-Disposition: attachment`. Nie `image/svg+xml`, nie HTML.
- Header: `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'; sandbox`.

Fehler: 404 `not_found`.

## 9 Entscheide

### POST /api/v1/p/{pid}/decisions

Zweck: **einziger Schreibweg** der UI (Architektur 7.1). Jede Aktion ist ein Entscheid in Schicht 3 mit Operator-ID und UTC. Der Server setzt `operator_id`, `ts_utc_ns` und `origin = 'webui'` selbst. Mehrere Entscheide (Sammelbestätigung) gehen in einer Transaktion: alle oder keiner.

```ts
interface DecisionRequest {
  decisions: DecisionInput[];         // 1 bis 500
}
type DecisionInput = { [K in DecisionKind]: { kind: K; payload: DecisionPayloads[K]; client_ref?: string } }[DecisionKind];

// Response 201
interface DecisionResponse {
  results: { decision_id: string; seq: number; ts: string; client_ref: string | null }[];
}
```

`client_ref` (UUID der UI) macht Wiederholungen idempotent: derselbe `client_ref` innerhalb von 10 min liefert das frühere Ergebnis.

**Entscheid-Arten.** Die Namen und Felder sind die Modelle aus `src/ariadne/events.py`. Entscheide verweisen nur auf natürliche Schlüssel (`claim_key`, Kennungen, `cmd_id`), nie auf Zeilen-IDs.

| `kind` | Modell in events.py | Nutzlast | UI-Aktion |
|---|---|---|---|
| `d.claim.confirm` | `DClaim` | `{ claim_key, reason? }` | Inbox «a», Sammelbestätigung |
| `d.claim.reject` | `DClaim` | `{ claim_key, reason? }` | Inbox «x» |
| `d.claim.edit` | `DClaimEdit` | `{ claim_key, value }` | Inbox «e» |
| `d.entity.merge` | `DEntityMerge` | `{ identifiers: string[2..], reason? }` | Merge-Vorschlag annehmen |
| `d.entity.split` | `DEntitySplit` | `{ identifiers: string[2..], reason? }` | Host trennen |
| `d.keystep.mark` | `DKeystepMark` | `{ terminal_id?, stream_off?, step, host?, note? }` | Schlüsselschritt in der Host-Schublade |
| `d.status.work` | `DStatusWork` | `{ subject, value: WorkStatus, reason? }` | Arbeitsstand |
| `d.status.access` | `DStatusAccess` | `{ subject, value: AccessLevel }` | Zugriff übersteuern |
| `d.note.set` | `DNoteSet` | `{ subject, text }` (bis 100 000 Zeichen) | Notiz |
| `d.tag.add`, `d.tag.remove` | `DTag` | `{ subject, tag }` (bis 64 Zeichen) | Tags |
| `d.scope.update` | `DScopeUpdate` | `{ version, toml }` | Projekteinstellungen (kritisch, siehe unten) |
| `d.automode.set` | `DAutomodeSet` | `{ enabled, parsers?, auto_ctx? }` | Automodus-Schalter der Inbox |
| `d.conflict.resolve` | `DConflictResolve` | `{ conflict_key, choice?, keep_open? }` | Konflikt wählen oder bewusst offen lassen |
| `d.terminal.label` | `DTerminalLabel` | `{ terminal_id, label }` (bis 64 Zeichen) | Terminal umbenennen |
| `d.revoke` | `DRevoke` | `{ decision_id, reason? }` | Rückgängig |
| `d.suggestion.done`, `d.suggestion.dismiss` | `DSuggestion` | `{ suggestion_key, reason? }` | Denkanstoss erledigt oder verworfen |
| `d.lab.not_customer` | `DLabNotCustomer` | `{ scope_version }` | «Das ist kein Kundenauftrag» (kritisch) |
| `d.finding` | `DGeneric` | Vorschlag unten | Findings |
| `d.artifact`, `d.hypothesis`, `d.goal.status` | `DGeneric` | folgen mit v0.2 und v0.3 | |

Die Kontext-Entscheide `d.ctx.set`, `d.ctx.push`, `d.ctx.pop` und `d.ctx.accept` laufen über `POST /terminals/{tid}/context` (Abschnitt 5), weil nur der Daemon den aktuellen Stream-Offset kennt. Über `/decisions` lehnt der Server sie mit 422 ab.

**Vorschlag für `d.finding`** (in `events.py` noch `DGeneric`):

```ts
interface DFinding {
  finding_id: string;                 // von der UI erzeugt, z. B. 'F-<base36>'
  action: 'create' | 'update' | 'delete';
  title?: string;
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
  assets?: string[];                  // Kennungen
  description?: string;
  mitigation?: string;
  attack_ids?: string[];
  evidence?: string[];                // fact_ids
}
```

**Kritische Entscheide** (`d.scope.update` mit Erweiterung, `d.lab.not_customer`, später Cloud-Freigabe und Klartext-Export) verlangen eine zweite Bestätigung über einen Kanal, den ein Hintergrundprozess nicht bedienen kann (Architektur 7.2.7). Der Server antwortet zuerst mit 409 `conflict` und `detail: [{ loc: ['confirm'], type: 'confirmation_required' }]`; der genaue Ablauf ist offen (Abschnitt 13).

Fehler: 422 `validation` (Schema, unbekannte Art, `d.ctx.*`), 409 `conflict` (Claim, Konflikt oder Denkanstoss unbekannt bzw. verwaist), 403 `policy`, 423 `locked`.

Auf jeden erfolgreichen Entscheid folgt ein SSE-Ereignis `changes`, bei Inbox-Wirkung zusätzlich `inbox`. Die UI aktualisiert sich über diese Ereignisse, nicht über die Antwort.

## 10 Abfragen

### POST /api/v1/p/{pid}/query

Zweck: Filterleiste und später Fragen an die Karte (Architektur 5.12). Ausführbar ist nur die DSL, nie SQL.

```ts
interface QueryRequest { dsl: QueryDsl }
interface QueryDsl {
  from: 'hosts' | 'services' | 'endpoints' | 'identities' | 'credentials' | 'cred_tests' | 'hints'
      | 'activity' | 'mentions' | 'findings' | 'goals';            // Sichten v_host, v_service ...
  where?: QueryCond;
  select?: string[];                  // Feld-Allowlist pro Sicht
  order?: { field: string; dir: 'asc' | 'desc' }[];
  limit?: number;                     // Standard 100, höchstens 1000
}
type QueryCond =
  | { field: string; op: 'eq' | 'ne' | 'lt' | 'lte' | 'gt' | 'gte' | 'in' | 'contains' | 'prefix' | 'is_null'; value?: string | number | boolean | (string | number)[] }
  | { all: QueryCond[] }
  | { any: QueryCond[] }
  | { not: QueryCond };

// Response 200
interface QueryResult {
  columns: string[];
  rows: (string | number | boolean | null)[][];
  truncated: boolean;
  sql_preview: string;                // rein informativ, nie ausführbar
}
```

Der Executor läuft mit `mode=ro`, `PRAGMA query_only=ON`, Authorizer und Zeitlimit (Architektur 5.12). Credentials nur über `v_credential` maskiert. Fehler: 422 `validation` (Feld nicht erlaubt, Tiefe über 8), 408 bei Zeitlimit (Code `internal` mit `detail type 'timeout'`, offen).

## 11 KI und Auslöser

Auslöser antworten mit 202 und einem Job. Fortschritt und Ergebnis kommen per SSE `progress`, neue Denkanstösse zusätzlich per `suggestion`.

```ts
interface Job {
  job_id: string;
  kind: 'ai.denkanstoss' | 'ai.frage' | 'export' | 'screenshot' | 'reparse';
  status: 'queued' | 'running' | 'done' | 'failed' | 'refused';
}
```

### POST /api/v1/p/{pid}/ai/denkanstoss

Zweck: KI-Denkanstoss auf Knopfdruck (Architektur 6.3). Das Modell sieht nur das deterministisch erzeugte Lagebild, keinen Rohtext.

```ts
interface DenkanstossRequest { host_ids?: string[] }   // optionaler Fokus
// Response 202: Job
```

Ergebnis: höchstens vier Denkanstösse, validiert (IDs existieren, Hosts im Scope, keine URLs, IPs oder Shell-Metazeichen im Freitext). Verstösse werden verworfen und als Injection-Verdacht gezählt. `status = 'refused'` bei `stop_reason = refusal`; Ariadne formuliert abgelehnte Anfragen nicht um.

Fehler: 403 `policy` (KI aus, Profil customer ohne Freigabe), 403 `budget`, 503 `llm_unavailable` (Job wartet trotzdem in der Queue, wenn der Provider später erreichbar ist), 409 `conflict` (ein Denkanstoss läuft schon).

### POST /api/v1/p/{pid}/ai/frage (v0.2)

Zweck: Frage in normaler Sprache in DSL übersetzen. Request `{ question: string }` (bis 500 Zeichen), Ergebnis per `progress` mit `result: { dsl: QueryDsl }`. Die UI zeigt die Abfrage an und führt sie erst nach Klick über `/query` aus.

### POST /api/v1/p/{pid}/screenshots

Zweck: Screenshot anfordern (Architektur 4.3). Request `{ mode: 'window' | 'monitor' | 'region'; delay_s?: number }` (Standard 3 s, damit die UI nicht selbst im Bild ist). Response 202 Job.

### POST /api/v1/p/{pid}/webshots (v0.3)

Zweck: Webseiten-Screenshot über den Scope-Proxy (Architektur 4.4). Request `{ url: string; confirm_dns?: boolean }`. Fehler: 403 `policy` (Scope nicht `in`).

### POST /api/v1/p/{pid}/exports, GET /api/v1/p/{pid}/exports

Zweck: Markdown-Export nach `<projekt>/exports/<UTC>/` (Architektur 8.7) und Liste der Exporte.

```ts
// POST Request
interface ExportRequest {
  template: 'cys' | 'htb';
  credentials: 'masked' | 'plain';    // plain nur im Profil lab und als kritische Operation
}
// POST Response 202: Job; Ergebnis in progress.result: { export_dir: string; files: number; chain_head: string }
// GET Response 200
interface ExportsResponse { exports: { export_dir: string; created_at: string; template: string; chain_head: string }[] }
```

Die UI bietet im Profil customer keinen Browser-Download an, nur den Pfad. Fehler: 403 `policy`.

## 12 Ereignisstrom (SSE)

### GET /api/v1/p/{pid}/events

Zweck: Invalidierungen in Echtzeit (Architektur 7.3). Der Strom enthält **nie Daten oder Secrets**, nur Hinweise, was neu zu laden ist. Daten holt die UI per REST.

- `EventSource` kann keinen Bearer senden. Die UI liest den Strom mit einem eigenen `fetch`-Client (`webui/src/lib/api/sse.ts`).
- Request-Header: `Authorization: Bearer`, `Accept: text/event-stream`, `Last-Event-ID` beim Wiederverbinden.
- Response: `Content-Type: text/event-stream`, `Cache-Control: no-store`, `X-Accel-Buffering: no`.
- Jede Nachricht hat `id:` (aufsteigend pro Daemon-Lauf), `event:` und genau eine `data:`-Zeile mit einem JSON-Objekt.
- Der Server bündelt in 250-ms-Fenstern: ein nmap-Import ergibt ein `changes`, nicht 3000.
- Herzschlag alle 15 s als Kommentar `: hb`. Die UI verbindet neu, wenn 45 s lang nichts kommt.
- Ringpuffer für `Last-Event-ID`. Liegt die ID ausserhalb, sendet der Server zuerst `reset`.
- Backoff der UI: 1, 2, 4, 8, 16, 30 s, mit 20 % Streuung, nach erfolgreichem Verbindungsaufbau zurück auf 1 s. `retry:` vom Server ersetzt den Startwert.
- 401 beendet den Strom, die UI zeigt die Anmeldung.
- Der Strom funktioniert auch bei gesperrtem Projekt; dann kommen nur `rec`, `terminal`, `presentation` und `project`.
- Bei einem Projektwechsel sendet der Server `project` und schliesst den Strom.

```
id: 1042
event: changes
data: {"generation":43,"entities":{"host":1,"claim":3,"inbox":1}}

: hb

```

| Ereignis | Daten | Reaktion der UI |
|---|---|---|
| `changes` | `{ generation: number; entities: Partial<Record<Change['entity'], number>> }` | `GET /changes?since=<eigene Generation>`, dann gezielt nachladen, neue Knoten einblenden |
| `rec` | `RecState` | REC-Knopf und Laufzeit; erst jetzt wechselt die Anzeige |
| `terminal` | `{ terminal_id; change: 'opened' \| 'closed' \| 'context' \| 'command' \| 'label' \| 'bind' \| 'gap' }` | `/terminals` und Zeitachse nachladen |
| `inbox` | `{ open: number }` | `/inbox` nachladen, Zähler in der Navigation |
| `suggestion` | `{ suggestion_key; change: 'added' \| 'updated' \| 'removed'; open: number }` | `/suggestions` nachladen |
| `progress` | `{ job_id; kind: Job['kind']; status: Job['status']; pct: number \| null; message: string \| null; result?: object }` | Fortschritt anzeigen, bei `done` Ergebnis übernehmen |
| `presentation` | `{ on: boolean }` | Banner, Credentials und offene Belege neu laden |
| `project` | `{ project_id: string \| null; locked: boolean }` | **alle Stores verwerfen**, laufende Abrufe abbrechen, Blob-URLs freigeben, `/status` neu laden, neu abonnieren |
| `reset` | `{ reason: 'reparse' \| 'buffer' \| 'restart'; generation: number \| null }` | alles neu laden |

`message` in `progress` ist ein fester deutscher Text des Daemons, nie Modell- oder Zieltext.

## 13 Offene Punkte

1. **Globaler Strom.** Ohne offenes oder bei gesperrtem Projekt fragt die UI `/status` alle 5 s ab. Ein globaler Strom `GET /api/v1/events` (nur `rec`, `terminal`, `project`, `presentation`) wäre sauberer.
2. **Bestätigung kritischer Operationen** (Architektur 7.2.7): Ablauf und Route für die zweite Bestätigung festlegen, z. B. `POST /api/v1/confirmations/{id}` mit pinentry auf dem Desktop.
3. **`d.finding`, `d.artifact`, `d.hypothesis`, `d.goal.status`** in `events.py` typisieren; der Vorschlag für `d.finding` steht in Abschnitt 9.
4. **Warteliste übernehmen:** Entscheid für «Datei aus der Warteliste importieren» fehlt im Katalog (Vorschlag `d.file.accept { path }`).
5. **Zeitlimit der DSL:** eigener Fehlercode `timeout` (408) oder `internal` mit Detail.
6. **Mehrere Tabs:** jeder Tab hält einen eigenen SSE-Strom; bei HTTP/1.1 sind pro Origin nur etwa 6 Verbindungen offen. Später `BroadcastChannel` oder `SharedWorker`.
7. **Linse Faden (v0.2):** `GraphView` für `lens = 'faden'` mit Zeitachse statt Segmenten.
8. **Positionen bei Merge und Split:** Wer verschiebt gespeicherte Positionen, wenn sich die stärkste Kennung eines Hosts ändert?
