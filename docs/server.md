# The OpenTunnel server

`crates/opentunnel-server` is the whole hosted service in one async Rust
binary (Tokio, rustls with `ring`, hyper, MySQL on PlanetScale through sqlx), run as one machine per Fly
region against one shared database ([Multiple regions](#multiple-regions)). It replaced the Cloudflare
Worker, its Durable Objects, its certificate Workflow, and the TCP relay on
AWS without changing anything clients see: the HTTP API, the bridge protocol
([protocol.md](protocol.md)), hostnames, tokens, and certificates are the same.

## Request flow

```text
visitor ──TLS──▶ :443 ─┬─ SNI <route>.<id>.opentunnel.xyz ─▶ tunnel <id> ─▶ bridge WebSocket ─▶ client (terminates TLS)
                       └─ SNI opentunnel.xyz ─▶ rustls (server certificate) ─▶ HTTP API · bridge upgrade · website
         ──HTTP─▶ :80  ─▶ /health, otherwise 301 to https://opentunnel.xyz
```

1. `relay::accept` reads an optional PROXY protocol header (Fly's
   `proxy_proto` handler supplies the visitor's address) and then TLS records
   until the ClientHello is complete (64 KiB and 10 s limits), without
   consuming anything it cannot replay.
2. SNI equal to the domain: the bytes already read are replayed into rustls,
   which serves HTTP/1.1 and HTTP/2 (ALPN) with the server's own certificate.
3. SNI `<id>.<domain>` or `<route>.<id>.<domain>`: the tunnel picks the bridge
   that claimed the route, sends `open` and the ClientHello as data frames,
   then copies both directions in 32 KiB frames. Visitor reads wait while the
   bridge's send queue is full (backpressure); a visitor that stops reading for
   30 s is reset so it cannot stall the bridge. `end` half-closes, `reset`
   aborts with an RST. A connection with no traffic either way for 15 minutes,
   or for 60 s once either direction has ended (a visitor that closed while the
   target never ends, or the reverse), is reset on both sides, and every socket
   has TCP keepalive, so peers that vanish without a FIN never hold a
   connection. Anything else (unknown tunnel, no bridge, certificate
   not ready, deeper names) is closed, exactly as before.
4. No bridge for the route on this machine: the visitor is forwarded to the
   machine that has one ([Multiple regions](#multiple-regions)), and only if
   no machine has it, to the legacy Worker (migration) or closed.

## Where each Worker feature went

| Worker | Server |
| --- | --- |
| `fetch` routing in `index.ts`, Effect `HttpApi` handlers | `http.rs`: same paths, methods, status codes, JSON bodies and key order, the 415/400 payload behaviour, `/health`, `/openapi.json` (captured from the Worker) |
| `connect(socket)` and `/api/relay` (AWS relay) | `relay.rs` on :443 directly; the AWS relay is no longer needed |
| `tls-client-hello.ts` | `sni.rs` (a line-for-line port, with fuzz-style tests) |
| `TunnelObject` record, token hash, `info`/`certificate`/`bindCertificate`/`remove` | `service.rs`; records keep the Durable Object's `StoredTunnel` JSON shape (`record.rs`) |
| Hibernating bridge WebSockets and attachments | `bridge.rs` sessions; per-tunnel state in `service.rs` (`Entry`) |
| Stale bridge retirement on attach and connect | Same rule (`idle_timeout_ms + heartbeat_ms`), plus a sweep every heartbeat |
| Durable Object alarm (renewal) | `alarm_at` per tunnel in MySQL, fired by `jobs::run_alarms`; same `alarm`, `scheduleRenewal`, `onAttached` logic |
| `CertificateWorkflow` (ZeroSSL, EAB, DNS-01, retries, `describeError`) | `acme.rs` + `dns.rs` + durable, leased `jobs` rows resumed after restarts; transient failures retried for a day, others three times (see below) |
| Workflow instance named after the certificate ID | Job keyed by certificate ID (`ensure_issuance` adds it only if missing) |
| Cloudflare-managed certificate for `opentunnel.xyz` | `jobs::ServerCertificates`: the same ACME issuance for the domain, renewed 30 days before expiry, hot-swapped |
| Static assets | `website.rs`: `dist/website` in memory, Cloudflare's HTML handling (`/index.html` → `/`), ETags |
| Pipelines `EVENTS` binding | `analytics.rs`: identical event envelopes and payloads, posted in batches to `ANALYTICS_URL` |

Two things changed by necessity: analytics no longer carry `country` and
`colo` (they came from Cloudflare's request metadata), and a tunnel's `state`
in the API is computed from live bridges, so it is never stale after a
restart.

## Storage

MySQL 8, in production the PlanetScale database `opentunnel` (org
`anomalyco`, AWS us-east-1, next to Fly's `iad`), reached through
`DATABASE_URL` with TLS (`sqlx`, rustls with `ring`, Mozilla's roots). Tables
(`store.rs`, all `utf8mb4` with binary collation, so IDs stay case-sensitive):

- `tunnels`: `id`, `record` (the `StoredTunnel` JSON exactly as serialized:
  token hash, hostname, certificate state, CSR and identifiers,
  `lastConnectedAt`, `renewal`, `deletedAt`, ...; `LONGTEXT` because MySQL's
  `JSON` type would reorder keys), `revision`, `deleted` and `issuing`
  (derived from the record for queries), `alarm_at`, `region` (reserved), and
  `local_update`, which is 0 while a row is exactly as imported so a later
  import may refresh it.
- `jobs`: issuance jobs (`issue`, `renew`, `server`) with a status
  (`pending`, `done`, `failed`, `abandoned`), attempts, the next run time, and
  a lease (`lease_owner`, `lease_until`).
- `server_certificates`: the domain's key, CSR, certificate and expiry.
- `meta`: the API certificate's current job, and the local test CA when
  `ISSUER=local`.
- `bridges` (schema 2): the registry of attached bridges, one row per tunnel,
  route and machine (`bridge_id`, `region`, the machine's internal `address`,
  `updated_at`).
- `schema_migrations`: the schema version.

The schema keeps to what Vitess allows: a primary key on every table, no
foreign keys, triggers or stored procedures. On startup the server creates
missing tables with `CREATE TABLE IF NOT EXISTS` and records the version; once
the database is at its version it runs no DDL at all (so PlanetScale's safe
migrations may be turned on afterwards; later schema changes then go through a
deploy request). A database at a newer version is refused. Schema 2 only adds
the `bridges` table; with safe migrations on, create it through a deploy
request (the statement is in `store.rs`) before deploying, or the new server
keeps retrying at startup.

Nothing assumes a single writer, so two servers on one database stay correct:

- Every tunnel write names the `revision` it read (`UPDATE ... WHERE revision
  = ?`). If an import or another server changed the row meanwhile, the write
  fails, the cached record is dropped and reloaded on next use, and the
  request answers 503 so the client retries. Within one process, writes to a
  tunnel are still serialized by its entry lock.
- Imports insert first and otherwise lock the existing row
  (`SELECT ... FOR UPDATE`) to compare it, retrying on deadlocks.
- A due alarm is cleared with `UPDATE ... WHERE alarm_at = <the value read>`,
  so it fires once.
- Jobs are claimed with a conditional update that sets a two-minute lease,
  extended every 40 s while the ACME order runs; results are recorded only by
  the lease holder (checked again right before recording). An expired lease (a
  crashed server) is taken over. The owner is `FLY_MACHINE_ID`, so a restarted
  machine takes its own jobs back at once; a clean shutdown also releases
  them. `tests/cluster.rs` runs 30 jobs on two servers and checks each ran
  once.
- Orphaned-issuance reconcile runs on every machine; it only adds jobs keyed
  by certificate ID (insert-if-absent), so concurrent runs add each once.
- Failed attempts are classified (`retry.rs`). Transient ones (timeouts,
  resets, 5xx, 429 with `Retry-After`, bodies that are not JSON, no nonce,
  `badNonce`, an authorization still pending) are retried with exponential
  backoff and jitter (from `ISSUANCE_RETRY_DELAY_MS`, at most an hour apart)
  until a day after the job was queued; permanent ones (`rejectedIdentifier`,
  `badCSR`, missing configuration, ...) fail at once; anything else gets three
  attempts. The tunnel shows `issuing`/`challenge` until the job ends, so
  clients keep polling. Within an attempt, nonce requests and POST-as-GET reads
  are repeated a few times, valid authorizations and already finalized orders
  of a reused order are skipped, and a challenge record that already exists in
  Cloudflare is used and deleted like a created one.
- The CA hands a pending authorization to every new order for its identifier.
  ZeroSSL's validation sometimes never finishes (the challenge stays
  `processing`), and such an authorization came back to every attempt for a
  day. So an attempt answers challenges only after the records propagated,
  polls the authorizations for up to 60 intervals, and deactivates (RFC 8555
  §7.5.2) any still pending at its end, whatever the error; an order that
  arrives with a challenge already in progress or a failed authorization is
  abandoned for a fresh one (after deactivating the stuck ones). Challenge
  records, one name shared by a hostname and its wildcard, are deleted only
  once every answered authorization is valid, invalid or deactivated; if a
  deactivation fails they are left in place. A failed validation's error
  (`ACME authorization for <name> ended in invalid: <type>: <detail>`) is
  logged and recorded; it gets three attempts.
- A job whose tunnel was deleted or bound another certificate ends as
  `abandoned` (checked before each attempt and after a failed one), which
  does not count as a failure.
- The reconcile also queues again (a compare-and-set from `failed` to
  `pending`) first issuance that gave up early on a transient error, when the
  tunnel is not deleted and still shows that certificate as failed; it shows
  `issuing` again. The requeued job starts a new retry window, so it is
  requeued at most once. First issuance queued before the deactivation fix
  (`AUTHZ_PENDING_FIX_MS`) whose last attempt ended on a pending authorization,
  failed or still retrying, is likewise queued once more with a fresh window
  (a job a server is running is left alone).
- The legacy pull-through import is the same insert-first import, so two
  machines importing one tunnel at once insert it once.
- The domain's key is created insert-if-absent and its job is requested with a
  compare-and-set on `meta`.

When the database is unavailable the server keeps running: the pool (10
connections, 5 s acquire timeout, connections checked before use and
recycled after 30 minutes) reconnects on its own, every statement gives up
after 10 s, and API calls that need storage answer 503
(`{"_tag":"ServiceUnavailableError","message":"storage unavailable"}`). Tunnels
with an attached bridge keep their record in memory, so visitor traffic and
token checks for them never touch the database; a bridge that attaches during
an outage is accepted from a cached record. At startup the server waits,
retrying, until the database answers.

Back it up with `opentunnel-server export <file>` (or
`POST /api/admin/export`); `opentunnel-server import <file>` writes an export
into the database at `DATABASE_URL`. PlanetScale's own backups also cover it.

## Configuration

Every flag also reads an environment variable (`opentunnel-server --help`).

| Variable | Default | |
| --- | --- | --- |
| `OPENTUNNEL_DOMAIN` | `opentunnel.xyz` | API domain; tunnels are `<id>.<domain>` |
| `TLS_LISTEN` / `HTTP_LISTEN` | `0.0.0.0:8443` / `0.0.0.0:8080` (`[::]` in the image) | `HTTP_LISTEN=off` disables HTTP |
| `HTTP_MODE` | `redirect` | `serve` runs the whole app on plain HTTP (development, tests) |
| `PROXY_PROTOCOL` | `false` | require a PROXY v1/v2 header on :443 (`true` on Fly) |
| `DATABASE_URL` | | secret: `mysql://user:password@host/opentunnel?ssl-mode=VERIFY_IDENTITY` (PlanetScale's "MySQL" connection string). TLS with certificate checks is the default and is required unless the host is loopback |
| `WEBSITE_DIR` | `/app/website` | |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | | serve this certificate for the domain instead of issuing one |
| `ISSUER` | `acme` | `local` is an insecure built-in CA for development and tests |
| `LOCAL_CA_FILE` | | with `ISSUER=local`, write the CA certificate here for clients to trust |
| `ACME_URL` | ZeroSSL DV90 | |
| `ACME_EMAIL` | `acme@opentunnel.xyz` | |
| `ACME_EAB_KID`, `ACME_EAB_HMAC_KEY` | | secrets: ZeroSSL external account binding |
| `ACME_ACCOUNT_KEY_JWK` | | secret: the account's P-256 private JWK (`opentunnel-server account-key` makes one) |
| `ACME_CA_BUNDLE` | | extra roots for the ACME server (Pebble) |
| `ACME_DNS_PROPAGATION_TIMEOUT_MS` | `10000` | wait for public resolvers to see the TXT records; 0 skips |
| `DNS_PROVIDER` | `cloudflare` | or `challtestsrv` (Pebble's test DNS) |
| `CLOUDFLARE_ZONE_ID` | the opentunnel.xyz zone | |
| `CLOUDFLARE_API_TOKEN` | | secret: DNS edit on the zone, only for DNS-01 |
| `ISSUANCE_CONCURRENCY` | `4` | ACME orders at once |
| `ANALYTICS_URL`, `ANALYTICS_TOKEN` | | the platform event stream's HTTP endpoint and bearer token; analytics are off without the URL |
| `ADMIN_TOKEN` | | secret: enables `POST /api/admin/{import,export,stats}` |
| `INTERNAL_LISTEN` | `off` | the internal listener for other machines (`[::]:9000` on Fly, bound to `FLY_PRIVATE_IP`); `off` runs a single machine without the registry |
| `INTERNAL_TOKEN` | | secret shared by all machines, required with `INTERNAL_LISTEN` |
| `INTERNAL_ADDRESS` | `[FLY_PRIVATE_IP]:<port>` | where other machines reach this one |
| `FLY_MACHINE_ID`, `FLY_REGION`, `FLY_PRIVATE_IP` | random, `local`, | set by Fly: the registry's machine ID (also the job lease owner), region, and 6PN address |
| `CLUSTER_HEARTBEAT_MS` | `60000` | registry heartbeat; rows older than three are ignored |
| `CONNECTION_IDLE_TIMEOUT_MS` | `900000` | a tunnel connection with no traffic either way for this long is reset |
| `HALF_CLOSE_TIMEOUT_MS` | `60000` | once either direction of a tunnel connection has ended, the other is reset after this long without traffic |
| `METRICS_LISTEN` | `off` | Prometheus metrics at `/metrics` (`[::]:9091` on Fly, unauthenticated, not in `[[services]]`); see [Observability](#observability) |
| `SHUTDOWN_DRAIN_MS` | `10000` | after SIGTERM, how long the server keeps accepting and serving while bridges move elsewhere |
| `LOG_FORMAT` | `text` | `json` writes one JSON object per line (`json` on Fly) |
| `LEGACY_WORKER_URL`, `RELAY_TOKEN`, `LEGACY_EXPORT_TOKEN` | | TEMPORARY, migration only ([cutover.md](cutover.md)) |

Set secrets with `fly secrets set NAME=value ... -a opentunnel`.

## Operations

- `fly logs -a opentunnel`; `RUST_LOG=opentunnel_server=debug` for per-connection detail. Metrics and
  JSON logs: [Observability](#observability).
- `POST /api/admin/stats` (bearer `ADMIN_TOKEN`) returns tunnel, alarm, job,
  attached-bridge and legacy-forward counts. The top-level connection and
  bridge counts are the answering machine's; `machine` has its ID, region and
  forwarding counters (`forwarded_out`, `forwarded_in`, `forward_failures`)
  and live Tokio tasks and open file descriptors (`tasks`, `fds`, which should
  follow open connections and bridges, not grow over time), and `cluster` the registry's view: bridges in total, per region, and per
  machine. The request lands on the machine nearest the caller's Cloudflare
  colo.
- At startup the open file soft limit is raised to the hard limit (logged as
  `open file limit`); when it is reached anyway, accept loops pause 500 ms
  between attempts and log at most every 10 s.
- Deploys are blue-green (`fly.toml`): a new machine starts next to each old
  one; once all are healthy, Fly cordons the old machines (the proxy stops
  sending them new connections), waits 10 s and stops them. On SIGTERM (or
  SIGINT) a machine removes its registry rows, sends every bridge `drain` and
  closes it with 1012 (clients reconnect with backoff, to the new machines),
  and does the same at once to any bridge that arrives later. For
  `SHUTDOWN_DRAIN_MS` (10 s) it keeps accepting connections and answering the
  API, since the proxy may still route new connections to it (a host migration
  stops a machine without cordoning it); HTTP/1.1 responses then carry
  `Connection: close` and idle connections are closed, so Cloudflare moves its
  pooled connections elsewhere. Then it stops listening, gives open requests
  up to 10 s, releases its jobs and exits (`kill_timeout` is 30 s). Closing
  the listener at once instead fails connections the proxy still sends, which
  Cloudflare reports as 525. Issuance jobs resume where they stopped, on any
  machine.
- The domain certificate is requested on first start and checked hourly;
  until it exists, TLS to the domain fails while tunnel traffic works.

## Observability

### Metrics

Every machine serves Prometheus metrics (OpenMetrics text) at `GET /metrics` on
`METRICS_LISTEN` (`[::]:9091`). It needs no token: no `[[services]]` entry
exposes the port, so only Fly's scraper and the private network reach it, and
nothing in it is secret. `fly.toml`'s `[metrics]` section has Fly scrape it
every 15 s into its managed Prometheus, which adds `app`, `region`, `host` and
`instance` labels. No metric has a per-tunnel label.

| Metric | Type | Labels | |
| --- | --- | --- | --- |
| `opentunnel_process_open_fds`, `opentunnel_process_max_fds` | gauge | | open descriptors and the soft limit |
| `opentunnel_tokio_tasks` | gauge | | live Tokio tasks (follows connections and bridges) |
| `opentunnel_process_resident_memory_bytes` | gauge | | from `/proc/self/statm` |
| `opentunnel_uptime_seconds` | gauge | | |
| `opentunnel_accept_errors_total` | counter | `error` (`emfile`, `other`) | failed accepts; `emfile` is running out of descriptors |
| `opentunnel_api_tls_handshakes_total` | counter | `result` (`ok`, `failed`, `timeout`) | TLS for the API domain; through Cloudflare a failed handshake is a 525 |
| `opentunnel_bridges_attached` | gauge | | |
| `opentunnel_bridge_attaches_total` | counter | `result` (`ok`, `bad_token`, `cert_not_ready`, `invalid_route`, `route_conflict`, `error`) | |
| `opentunnel_bridge_detaches_total` | counter | `reason` (`client_close`, `drop`, `idle_retire`, `drain`, `delete`, `server_close`) | attached bridges that ended |
| `opentunnel_visitor_connections_open` | gauge | | public tunnel connections held here (including forwarded ones) |
| `opentunnel_visitor_connections_total` | counter | `outcome` (`served_local`, `forwarded_out`, `forwarded_in`, `legacy_relay`, `rejected_unknown_tunnel`, `rejected_unknown_route`, `rejected_no_bridge`, `rejected_cert_not_ready`, `rejected_bad_hello`, `rejected_timeout`, `error`) | a forwarded visitor counts on both machines (`forwarded_out`, `forwarded_in`) |
| `opentunnel_visitor_bytes_total` | counter | `direction` (`in`, `out`) | counted on the machine with the bridge |
| `opentunnel_visitor_connection_duration_seconds` | histogram | | connections carried over a bridge here |
| `opentunnel_cluster_forward_failures_total` | counter | `reason` (`refused`, `connect`, `timeout`, `io`) | |
| `opentunnel_cluster_registry_lookups_total` | counter | `result` (`hit`, `miss`, `error`) | the route location cache |
| `opentunnel_db_query_duration_seconds` | histogram | `operation` (the `Store` method) | |
| `opentunnel_db_errors_total` | counter | `operation` | failed and timed out statements |
| `opentunnel_db_pool_connections` | gauge | `state` (`idle`, `in_use`) | |
| `opentunnel_acme_attempts_total` | counter | `kind` (`issue`, `renew`, `server`), `outcome` (`success`, `retry`, `failed`, `abandoned`) | `failed` gave up; `abandoned`: the tunnel no longer wants it |
| `opentunnel_acme_failures_total` | counter | `kind`, `class` (`network`, `timeout`, `http_5xx`, `http_429`, `bad_body`, `nonce`, `bad_nonce`, `authz_pending`, `dns`, `rejected`, `other`) | every failed attempt |
| `opentunnel_acme_issuance_duration_seconds` | histogram | `kind`, `outcome` | one attempt |
| `opentunnel_certificate_jobs` | gauge | `status` (`pending`, `failed`: in the last 24 h) | the whole database, refreshed every minute on every machine (so take `max`, not `sum`) |
| `opentunnel_certificates_expiring` | gauge | | ready certificates of tunnels with a bridge here that expire within 14 days |

Fly's built-in `fly_instance_*` series (memory, CPU, `fly_instance_filefd_*`)
sit next to them.

Where to see them: Grafana at [fly-metrics.net](https://fly-metrics.net)
(Explore, the Prometheus data source), or the Prometheus API:

```bash
TOKEN=$(fly auth token)   # or a read-only token from `fly tokens create readonly`, sent as `FlyV1 <token>`
curl -s -G https://api.fly.io/prometheus/anomaly-807/api/v1/query -H "Authorization: FlyV1 $TOKEN" \
  --data-urlencode 'query=opentunnel_process_open_fds{app="opentunnel"}' | jq '.data.result[] | [.metric.region, .value[1]]'
```

Queries for the signals of past incidents:

```promql
# Descriptors as a fraction of the limit, per machine (the fd leak): alert above 0.5
max by (region) (opentunnel_process_open_fds{app="opentunnel"} / opentunnel_process_max_fds{app="opentunnel"})
# Tasks and memory growing while bridges and connections do not
opentunnel_tokio_tasks{app="opentunnel"}
opentunnel_tokio_tasks{app="opentunnel"} / (opentunnel_bridges_attached{app="opentunnel"} + opentunnel_visitor_connections_open{app="opentunnel"} + 1)
opentunnel_process_resident_memory_bytes{app="opentunnel"}
rate(opentunnel_accept_errors_total{app="opentunnel",error="emfile"}[5m]) > 0
# Certificate attempts failing, by class, and issuance that gave up
sum by (class) (increase(opentunnel_acme_failures_total{app="opentunnel"}[1h]))
sum(increase(opentunnel_acme_attempts_total{app="opentunnel",outcome="failed"}[1d]))
  / sum(increase(opentunnel_acme_attempts_total{app="opentunnel",outcome=~"success|failed"}[1d]))
max(opentunnel_certificate_jobs{app="opentunnel",status="failed"})
sum(opentunnel_certificates_expiring{app="opentunnel"}) > 0
# API TLS handshakes failing (Cloudflare 525s). 525s whose Host is a tunnel hostname are not these: requests
# for <id>.opentunnel.xyz sent to Cloudflare (mostly scanners) reach this server with that SNI and are closed
# when the tunnel has no bridge, like any visitor.
sum by (region, result) (rate(opentunnel_api_tls_handshakes_total{app="opentunnel",result!="ok"}[5m]))
# Visitors turned away, by reason; forwarding between machines failing
sum by (outcome) (rate(opentunnel_visitor_connections_total{app="opentunnel",outcome=~"rejected.*|error"}[5m]))
sum by (region, reason) (rate(opentunnel_cluster_forward_failures_total{app="opentunnel"}[5m]))
# Slow storage, per operation
histogram_quantile(0.99, sum by (le, operation) (rate(opentunnel_db_query_duration_seconds_bucket{app="opentunnel"}[5m])))
```

### Logs

On Fly (`LOG_FORMAT=json`) every line on stderr is one JSON object:
`timestamp`, `level`, `message`, `target`, the event's fields, then `machine`
and `region`. Fields keep the same names everywhere: `tunnel`, `conn`,
`route`, `certificate`, `kind`, `attempt`, `error`, `error_class`, `status`.
Tokens, keys and the database URL are never logged.

- Each failed certificate attempt is a `warn` "certificate issuance attempt
  failed" with `attempt`, `error_class`, the HTTP `status` of an ACME error
  and `error` (which includes the ACME problem document or the start of the
  response body); retries are `info` "retrying certificate issuance", and
  giving up is an `error` "certificate issuance gave up".
- Descriptor use crossing 50% and 80% of the limit is a `warn` (repeated every
  ten minutes while it stays there), with `fds`, `limit` and `tasks`.
- Failed accepts are logged at most every ten seconds, with `error_class`
  (`emfile`) and how many were `suppressed`.
- Per-connection messages are `debug` (`RUST_LOG=opentunnel_server=debug`).

```bash
fly logs -a opentunnel -r iad --no-tail | sed 's/^[^{]*//' | jq -c 'select(.level != "info")'
fly logs -a opentunnel | sed 's/^[^{]*//' | jq -c 'select(.message | test("certificate issuance")) | {region, attempt, error_class, status, error}'
```

(`fly logs` prefixes each line with the time, region and machine; the `sed`
strips it.)

## Multiple regions

Ten machines, one in each of `iad`, `ord`, `sjc`, `gru`, `lhr`, `fra`, `bom`,
`sin`, `nrt` and `syd`, behind one anycast IPv4/IPv6. Fly sends each TCP
connection to the nearest machine: a visitor to the one nearest the visitor,
and a client's bridge (through Cloudflare, which proxies `opentunnel.xyz`) to
the one nearest the client's Cloudflare colo. The two meet through a registry
in MySQL and forwarding over Fly's private network (6PN). The code is
`cluster.rs`; with `INTERNAL_LISTEN=off` none of it runs.

```text
visitor ─▶ machine B (syd) ── no bridge here ── registry: tunnel/route → machine A
             │                                                     │
             └── TCP over 6PN to A:9000 ──▶ "OPENTUNNEL-FORWARD/1 <secret> <id> <route> <visitor>\n"
                                              + ClientHello ◀── "1" ── then raw bytes both ways
client ─▶ Cloudflare ─▶ machine A (iad) ─▶ bridge attached, rows in `bridges`
```

- **Registry.** On attach, the machine upserts one `bridges` row per route
  (tunnel, route, machine, bridge ID, region, internal address) and deletes
  them when the bridge closes or is retired as silent. Every heartbeat (60 s)
  it refreshes `updated_at` on all its rows, records bridges whose upsert
  failed (database outage), retries failed removals, and closes local bridges
  of tunnels deleted elsewhere. Readers ignore rows older than three
  heartbeats, so a crashed machine's rows expire after at most three minutes;
  a machine deletes all rows with its own ID at startup and on clean shutdown,
  and anyone deletes rows untouched for thirty heartbeats.
- **Forwarding.** A visitor for a route with no local bridge: look up the
  route's freshest row on another machine (cached 30 s, a miss 10 s), connect
  to its internal address, send the header (shared secret, tunnel, route, the
  visitor's address from PROXY v2) and the buffered ClientHello. The receiver
  parses the ClientHello itself and routes it exactly like a local visitor
  (`max_conns`, backpressure, analytics, the `open` message with the real
  visitor address), but never forwards again. It answers `1` before the stream
  or `0` when it has no bridge; on `0` or a failed connection the sender drops
  its cache entry (and skips an unreachable machine for 30 s), looks up once
  more, and otherwise falls back to the legacy Worker (if configured) or
  closes. The sender then copies both directions (`net::splice`, 32 KiB
  buffers, half-closes passed on, the same idle and half-close timeouts as
  local visitors); a reset or timeout on one side resets the other.
- **Control.** The internal listener also serves a small HTTP/1.1 API,
  authenticated with `Authorization: Bearer <INTERNAL_TOKEN>` (compared in
  constant time): `GET /internal/tunnel/<id>/routes` (the routes this
  machine's live bridges hold, after retiring silent ones) and `POST
  /internal/tunnel/<id>/close` (a deletion). Deleting a tunnel on any machine
  closes its bridges on every machine in the registry and removes its rows.
  Attaching checks the registry for the requested routes on other machines
  and asks those machines whether they still hold them; only a live answer is
  a `route_conflict`, so a crashed or draining machine's leftover rows never
  block a client that moved. Two machines accepting the same route in the same
  instant is possible; visitors then go to the newer row and nothing breaks.
- **Cached records.** A machine caches tunnel records for routing, so the
  database stays off the visitor path. With other machines writing, API calls,
  attaches, alarms and certificate updates read the record again (one query),
  and routing re-reads a cached record only while it is missing or its
  certificate is not ready. During a database outage the cached copy is used.
- **The internal port** binds only the machine's 6PN address and is not in
  `fly.toml`'s services, so it is unreachable from the Internet.

Failure modes:

| What | Effect |
| --- | --- |
| A machine restarts (deploy) | Its rows are removed first, its bridges get `drain`/1012 and reattach to the new or next-nearest machine within seconds; forwards to it fail over to the new location after one refused attempt |
| A machine crashes | Forwards to it fail fast (connection refused or 3 s timeout), the sender skips it for 30 s; its rows expire after three heartbeats; its clients reconnect elsewhere and attach at once (the route check cannot reach it, so it does not count) |
| 6PN between two machines fails | Visitors for that pair are closed (or go to the legacy Worker); local traffic is unaffected |
| Database unavailable | Local visitors and attached bridges keep working from memory; lookups for remote bridges fail (closed); registry changes are retried by the heartbeat |
| A delete's close request does not arrive | The owning machine's heartbeat sees the tunnel deleted and closes its bridges within a minute |

Latency: PlanetScale is in us-east-1, ~200 ms from `syd`. The visitor path
reads the database only on a tunnel's first visitor per machine (record load
and, without a local bridge, one registry lookup per 30 s); attaching costs a
few queries.

### Deploying

```bash
fly secrets set --app opentunnel --stage INTERNAL_TOKEN=$(openssl rand -hex 32)
fly deploy --app opentunnel                  # blue-green: new machines next to the old ones, then the old ones stop
fly scale vm shared-cpu-1x --memory 1024 --app opentunnel   # if existing machines kept the old size
for region in ord sjc gru lhr fra bom sin nrt syd; do
  fly scale count 1 --region $region --app opentunnel --yes
done                                         # or: fly machine clone <iad machine> --region <region>
fly status --app opentunnel                  # ten machines, one per region, all passing checks
curl -s -X POST https://opentunnel.xyz/api/admin/stats -H "authorization: Bearer $ADMIN_TOKEN" | jq .cluster
```

`fly scale count` for a region keeps the other regions as they are. Every
machine must have `INTERNAL_TOKEN` before it runs with `INTERNAL_LISTEN`
(staged secrets apply on the next deploy), and the first deploy of this
version creates the `bridges` table (schema 2; see [Storage](#storage)).

## Tests

The storage, service, API contract and end-to-end tests need a MySQL 8 server
whose user may create databases; each test creates its own `ot_test_*`
database. Without `TEST_DATABASE_URL` they print a note and skip.

```bash
docker run -d --name ot-mysql -e MYSQL_ROOT_PASSWORD=opentunnel -e MYSQL_DATABASE=opentunnel -p 3306:3306 mysql:8.0
export TEST_DATABASE_URL=mysql://root:opentunnel@127.0.0.1:3306/opentunnel
cargo test -p opentunnel-server
docker rm -f ot-mysql    # when done; it holds the test databases
```

- `cargo test -p opentunnel-server`: storage (revisions, imports, concurrent
  alarms, job leases, the registry), unit tests (SNI, PROXY protocol, CSRs,
  analytics, renewal scheduling with a manual clock, stale bridges, routing,
  imports), the API contract replay against the Worker's recorded responses,
  the Rust client end to end (provisioning, passthrough, shared tunnels,
  restarts, migrated tunnels, renewal on attach, a database outage), the
  migration paths against a fake Worker, and two servers on one database
  (`tests/cluster.rs`: forwarding, route conflicts and deletes across
  machines, a crashed machine, a restart, and jobs running once), and
  connections whose peers vanish (`tests/leaks.rs`: visitors that close while
  the target never ends, silent visitors, a bridge that goes away, partial
  ClientHellos; tasks and descriptors return to their baseline).
- ACME against Pebble with external account binding and DNS-01 through
  pebble-challtestsrv:

  ```bash
  docker run -d --network host ghcr.io/letsencrypt/pebble-challtestsrv -dnsserver 127.0.0.1:8053 -management 127.0.0.1:8055 -http01 "" -https01 "" -tlsalpn01 "" -doh ""
  docker run -d --network host ghcr.io/letsencrypt/pebble -config /test/config/pebble-config-external-account-bindings.json -dnsserver 127.0.0.1:8053
  ISSUER=acme ACME_URL=https://localhost:14000/dir ACME_CA_BUNDLE=pebble.minica.pem \
    ACME_EAB_KID=kid-1 ACME_EAB_HMAC_KEY=zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W \
    ACME_ACCOUNT_KEY_JWK="$(opentunnel-server account-key)" DNS_PROVIDER=challtestsrv \
    ACME_DNS_PROPAGATION_TIMEOUT_MS=0 ACME_POLL_INTERVAL_MS=500 opentunnel-server
  ```

  (`pebble.minica.pem` is `/test/certs/pebble.minica.pem` in the Pebble image.)
