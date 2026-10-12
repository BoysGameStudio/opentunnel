//! Prometheus metrics, served on `METRICS_LISTEN` (`GET /metrics`, OpenMetrics text) for Fly's managed
//! Prometheus, which adds the `app`, `region`, `host` and `instance` labels. Labels are a small fixed set: never
//! a tunnel, route or address. See `docs/server.md`, "Observability".
//!
//! Counters live in one process-wide registry; gauges that are cheap to compute (descriptors, tasks, memory,
//! bridges) are sampled when scraped, and the job counts are refreshed every minute by [`run_monitor`].

use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use http_body_util::Full;
use hyper::header::{CONTENT_TYPE, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::Registry;
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

use crate::acme::{Problem, Transient};
use crate::net::AcceptErrors;

type Labels = [(&'static str, &'static str); 1];
type Labels2 = [(&'static str, &'static str); 2];
type Histograms<L> = Family<L, Histogram, fn() -> Histogram>;

const CONTENT: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

pub struct Metrics {
    registry: Registry,
    started: Instant,

    open_fds: Gauge,
    fd_limit: Gauge,
    tasks: Gauge,
    resident_memory: Gauge,
    uptime: Gauge<f64, AtomicU64>,
    accept_errors: Family<Labels, Counter>,

    bridges_attached: Gauge,
    bridge_attaches: Family<Labels, Counter>,
    bridge_detaches: Family<Labels, Counter>,

    visitors_open: Gauge,
    visitor_connections: Family<Labels, Counter>,
    visitor_bytes: Family<Labels, Counter>,
    visitor_duration: Histogram,

    forward_failures: Family<Labels, Counter>,
    registry_lookups: Family<Labels, Counter>,

    db_duration: Histograms<Labels>,
    db_errors: Family<Labels, Counter>,
    db_connections: Family<Labels, Gauge>,

    acme_attempts: Family<Labels2, Counter>,
    acme_failures: Family<Labels2, Counter>,
    acme_duration: Histograms<Labels2>,
    certificate_jobs: Family<Labels, Gauge>,
    certificates_expiring: Gauge,
}

fn db_histogram() -> Histogram {
    Histogram::new([0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 10.0])
}

fn acme_histogram() -> Histogram {
    Histogram::new([1.0, 5.0, 15.0, 30.0, 60.0, 120.0, 300.0, 600.0])
}

impl Metrics {
    fn new() -> Self {
        let mut registry = Registry::with_prefix("opentunnel");
        let metrics = Self {
            registry: Registry::default(),
            started: Instant::now(),
            open_fds: Gauge::default(),
            fd_limit: Gauge::default(),
            tasks: Gauge::default(),
            resident_memory: Gauge::default(),
            uptime: Gauge::default(),
            accept_errors: Family::default(),
            bridges_attached: Gauge::default(),
            bridge_attaches: Family::default(),
            bridge_detaches: Family::default(),
            visitors_open: Gauge::default(),
            visitor_connections: Family::default(),
            visitor_bytes: Family::default(),
            visitor_duration: Histogram::new([0.1, 1.0, 10.0, 60.0, 300.0, 900.0, 3600.0, 14400.0]),
            forward_failures: Family::default(),
            registry_lookups: Family::default(),
            db_duration: Family::new_with_constructor(db_histogram),
            db_errors: Family::default(),
            db_connections: Family::default(),
            acme_attempts: Family::default(),
            acme_failures: Family::default(),
            acme_duration: Family::new_with_constructor(acme_histogram),
            certificate_jobs: Family::default(),
            certificates_expiring: Gauge::default(),
        };
        let r = &mut registry;
        r.register(
            "process_open_fds",
            "Open file descriptors",
            metrics.open_fds.clone(),
        );
        r.register(
            "process_max_fds",
            "The open file descriptor soft limit",
            metrics.fd_limit.clone(),
        );
        r.register("tokio_tasks", "Live Tokio tasks", metrics.tasks.clone());
        r.register(
            "process_resident_memory_bytes",
            "Resident memory",
            metrics.resident_memory.clone(),
        );
        r.register(
            "uptime_seconds",
            "Seconds since the process started",
            metrics.uptime.clone(),
        );
        r.register(
            "accept_errors",
            "Failed accepts on the listeners, by error (emfile: out of descriptors)",
            metrics.accept_errors.clone(),
        );
        r.register(
            "bridges_attached",
            "Bridges attached to this machine",
            metrics.bridges_attached.clone(),
        );
        r.register(
            "bridge_attaches",
            "Bridge attach attempts, by result",
            metrics.bridge_attaches.clone(),
        );
        r.register(
            "bridge_detaches",
            "Attached bridges that ended, by reason",
            metrics.bridge_detaches.clone(),
        );
        r.register(
            "visitor_connections_open",
            "Public tunnel connections open on this machine",
            metrics.visitors_open.clone(),
        );
        r.register(
            "visitor_connections",
            "Public tunnel connections, by outcome",
            metrics.visitor_connections.clone(),
        );
        r.register(
            "visitor_bytes",
            "Bytes carried for visitors over local bridges (in: from visitors, out: to visitors)",
            metrics.visitor_bytes.clone(),
        );
        r.register(
            "visitor_connection_duration_seconds",
            "How long visitor connections carried over a local bridge lasted",
            metrics.visitor_duration.clone(),
        );
        r.register(
            "cluster_forward_failures",
            "Forwarding attempts to another machine that failed, by reason",
            metrics.forward_failures.clone(),
        );
        r.register(
            "cluster_registry_lookups",
            "Route lookups in the registry cache, by result",
            metrics.registry_lookups.clone(),
        );
        r.register(
            "db_query_duration_seconds",
            "Storage operation duration, by operation",
            metrics.db_duration.clone(),
        );
        r.register(
            "db_errors",
            "Failed storage operations, by operation",
            metrics.db_errors.clone(),
        );
        r.register(
            "db_pool_connections",
            "Database pool connections, by state (idle, in_use)",
            metrics.db_connections.clone(),
        );
        r.register(
            "acme_attempts",
            "Certificate issuance attempts, by kind and outcome (success, retry, failed, abandoned)",
            metrics.acme_attempts.clone(),
        );
        r.register(
            "acme_failures",
            "Failed certificate issuance attempts, by kind and error class",
            metrics.acme_failures.clone(),
        );
        r.register(
            "acme_issuance_duration_seconds",
            "Certificate issuance attempt duration, by kind and outcome",
            metrics.acme_duration.clone(),
        );
        r.register(
            "certificate_jobs",
            "Certificate jobs pending, and failed in the last 24 hours (refreshed every minute)",
            metrics.certificate_jobs.clone(),
        );
        r.register(
            "certificates_expiring",
            "Certificates of tunnels with a bridge here that expire within 14 days (or have expired)",
            metrics.certificates_expiring.clone(),
        );
        Self {
            registry,
            ..metrics
        }
    }
}

static METRICS: LazyLock<Metrics> = LazyLock::new(Metrics::new);

pub fn get() -> &'static Metrics {
    &METRICS
}

// --- Recording ---------------------------------------------------------------------------------------------

pub fn accept_error(error: &std::io::Error) {
    let class = if matches!(error.raw_os_error(), Some(libc::EMFILE | libc::ENFILE)) {
        "emfile"
    } else {
        "other"
    };
    get().accept_errors.get_or_create(&[("error", class)]).inc();
}

/// An attach answered: `ok`, or the `attach_error` code (`bad_token`, `route_conflict`, ...).
pub fn bridge_attach(result: &'static str) {
    get()
        .bridge_attaches
        .get_or_create(&[("result", result)])
        .inc();
}

/// An attached bridge ended: `client_close`, `drop`, `idle_retire`, `drain`, `delete` or `server_close`.
pub fn bridge_detach(reason: &'static str) {
    get()
        .bridge_detaches
        .get_or_create(&[("reason", reason)])
        .inc();
}

/// Why an attached bridge's session ended, from the close the server sent (if any) and whether the client
/// completed the close handshake.
pub fn detach_reason(server_close: Option<u16>, clean: bool) -> &'static str {
    match server_close {
        Some(1012) => "drain",
        Some(1000) => "delete",
        Some(1001) => "idle_retire",
        Some(_) => "server_close",
        None if clean => "client_close",
        None => "drop",
    }
}

/// A visitor connection was served or turned away. Outcomes: `served_local`, `forwarded_out`,
/// `forwarded_in`, `legacy_relay`, `rejected_unknown_tunnel`, `rejected_unknown_route`, `rejected_no_bridge`,
/// `rejected_cert_not_ready`, `rejected_bad_hello`, `rejected_timeout`, `error`.
pub fn visitor(outcome: &'static str) {
    get()
        .visitor_connections
        .get_or_create(&[("outcome", outcome)])
        .inc();
}

/// The outcome for a connection `service.route` turned away.
pub fn rejected_outcome(tunnel_exists: bool, outcome: &str) -> &'static str {
    match (tunnel_exists, outcome) {
        (false, _) => "rejected_unknown_tunnel",
        (_, "certificate_not_ready") => "rejected_cert_not_ready",
        (_, "unknown_route") => "rejected_unknown_route",
        _ => "rejected_no_bridge",
    }
}

/// The outcome for a connection whose ClientHello could not be read.
pub fn hello_outcome(error: &anyhow::Error) -> &'static str {
    if error.to_string().contains("timeout") {
        "rejected_timeout"
    } else {
        "rejected_bad_hello"
    }
}

/// A connection carried over a local bridge ended.
pub fn visitor_finished(duration: Duration, bytes_in: u64, bytes_out: u64) {
    let metrics = get();
    metrics.visitor_duration.observe(duration.as_secs_f64());
    metrics
        .visitor_bytes
        .get_or_create(&[("direction", "in")])
        .inc_by(bytes_in);
    metrics
        .visitor_bytes
        .get_or_create(&[("direction", "out")])
        .inc_by(bytes_out);
}

/// Counts an open visitor connection until dropped.
pub struct OpenVisitor(());

impl Drop for OpenVisitor {
    fn drop(&mut self) {
        get().visitors_open.dec();
    }
}

pub fn visitor_open() -> OpenVisitor {
    get().visitors_open.inc();
    OpenVisitor(())
}

/// A forward to another machine failed: `refused`, `connect`, `timeout` or `io`.
pub fn forward_failure(reason: &'static str) {
    get()
        .forward_failures
        .get_or_create(&[("reason", reason)])
        .inc();
}

pub fn forward_error_reason(error: &anyhow::Error) -> &'static str {
    let text = format!("{error:#}");
    if text.contains("timed out") || text.contains("no answer") {
        "timeout"
    } else if error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .any(|error| {
            matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::HostUnreachable
            )
        })
    {
        "connect"
    } else {
        "io"
    }
}

/// A registry lookup: `hit` (cache), `miss` (database), or `error`.
pub fn registry_lookup(result: &'static str) {
    get()
        .registry_lookups
        .get_or_create(&[("result", result)])
        .inc();
}

pub fn db_operation(operation: &'static str, elapsed: Duration, ok: bool) {
    let metrics = get();
    metrics
        .db_duration
        .get_or_create(&[("operation", operation)])
        .observe(elapsed.as_secs_f64());
    if !ok {
        metrics
            .db_errors
            .get_or_create(&[("operation", operation)])
            .inc();
    }
}

/// One issuance attempt ended: `success`, `retry` (failed, tried again later) or `failed` (gave up).
pub fn acme_attempt(kind: &'static str, outcome: &'static str, elapsed: Duration) {
    let metrics = get();
    let labels = [("kind", kind), ("outcome", outcome)];
    metrics.acme_attempts.get_or_create(&labels).inc();
    metrics
        .acme_duration
        .get_or_create(&labels)
        .observe(elapsed.as_secs_f64());
}

pub fn acme_failure(kind: &'static str, class: &'static str) {
    get()
        .acme_failures
        .get_or_create(&[("kind", kind), ("class", class)])
        .inc();
}

// --- Error classes -------------------------------------------------------------------------------------------

/// ACME problem types that mean the CA refused the request for good.
const REJECTED_PROBLEMS: &[&str] = &[
    "rejectedIdentifier",
    "unsupportedIdentifier",
    "badCSR",
    "caa",
    "badSignatureAlgorithm",
    "badPublicKey",
    "externalAccountRequired",
    "accountDoesNotExist",
    "invalidContact",
    "unsupportedContact",
    "malformed",
    "unauthorized",
    "incorrectResponse",
    "connection",
    "dns",
];

/// The class of a failed issuance attempt, for metrics and logs: `network`, `timeout`, `http_5xx`,
/// `http_429`, `bad_body`, `nonce`, `bad_nonce`, `authz_pending`, `dns`, `rejected` or `other`. Unlike
/// `retry::classify`, which decides whether to try again, this says what went wrong.
pub fn error_class(error: &anyhow::Error) -> &'static str {
    let text = format!("{error:#}");
    // The DNS provider's failures, before the generic HTTP ones (its requests are HTTP too).
    if text.contains("DNS record")
        || text.contains("identical record already exists")
        || text.contains("api.cloudflare.com")
        || text.contains("DNS challenge")
    {
        return "dns";
    }
    for cause in error.chain() {
        if let Some(problem) = cause.downcast_ref::<Problem>() {
            return problem_class(problem.status, &problem.kind);
        }
        if let Some(transient) = cause.downcast_ref::<Transient>() {
            return message_class(&transient.message);
        }
        if let Some(error) = cause.downcast_ref::<reqwest::Error>() {
            if error.is_timeout() {
                return "timeout";
            }
            if let Some(status) = error.status() {
                return status_class(status.as_u16());
            }
            if error.is_decode() || error.is_body() {
                return "bad_body";
            }
            if error.is_connect() || error.is_request() {
                return "network";
            }
        }
        if let Some(error) = cause.downcast_ref::<std::io::Error>()
            && error.kind() == std::io::ErrorKind::TimedOut
        {
            return "timeout";
        }
    }
    message_class(&text)
}

fn problem_class(status: u16, kind: &str) -> &'static str {
    let kind = kind.rsplit(':').next().unwrap_or_default();
    match kind {
        "badNonce" => "bad_nonce",
        "rateLimited" => "http_429",
        "serverInternal" => "http_5xx",
        kind if REJECTED_PROBLEMS.contains(&kind) => "rejected",
        _ => status_class(status),
    }
}

fn status_class(status: u16) -> &'static str {
    match status {
        429 => "http_429",
        500..=599 => "http_5xx",
        408 => "timeout",
        _ => "other",
    }
}

/// The class from an error's text, for errors without a typed cause (and recorded `last_error`s).
pub fn message_class(text: &str) -> &'static str {
    if text.contains("DNS record") || text.contains("identical record already exists") {
        return "dns";
    }
    if text.contains("no nonce") {
        return "nonce";
    }
    if text.contains("badNonce") {
        return "bad_nonce";
    }
    if text.contains("authorization ended in pending") || text.contains("order ended in") {
        return "authz_pending";
    }
    if text.contains("timed out") || text.contains("timeout") {
        return "timeout";
    }
    if text.contains("error decoding response body")
        || text.contains("could not be read")
        || text.contains("expected value at line")
    {
        return "bad_body";
    }
    if text.contains("rateLimited") || text.contains("| HTTP 429") || text.contains("(429 ") {
        return "http_429";
    }
    if text.contains("status server error") || text.contains("| HTTP 5") {
        return "http_5xx";
    }
    if text.contains("acme:error:") {
        return "rejected";
    }
    if text.contains("error sending request")
        || text.contains("connection closed")
        || text.contains("connection reset")
    {
        return "network";
    }
    "other"
}

// --- Sampling and rendering ----------------------------------------------------------------------------------

/// `opentunnel_certificates_expiring` counts certificates that expire within this long.
pub const EXPIRING_WITHIN_MS: u64 = 14 * crate::clock::DAY_MS;

/// Values read from the running service when scraped.
#[derive(Debug, Default, Clone, Copy)]
pub struct Sample {
    pub bridges: usize,
    pub pool_size: u32,
    pub pool_idle: usize,
    pub expiring_certificates: usize,
}

/// The open file soft limit.
pub fn fd_limit() -> Option<u64> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit only writes the struct passed to it.
    (unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0).then_some(limit.rlim_cur)
}

/// Resident memory in bytes, from `/proc/self/statm`.
pub fn resident_memory() -> Option<u64> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    // SAFETY: sysconf has no preconditions.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    Some(pages * u64::try_from(page).ok()?)
}

fn as_i64(value: impl TryInto<i64>) -> i64 {
    value.try_into().unwrap_or(i64::MAX)
}

/// The metrics in the OpenMetrics text format.
pub fn render(sample: Sample) -> String {
    let metrics = get();
    if let Some(fds) = crate::net::open_fds() {
        metrics.open_fds.set(as_i64(fds));
    }
    if let Some(limit) = fd_limit() {
        metrics.fd_limit.set(as_i64(limit));
    }
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        metrics
            .tasks
            .set(as_i64(handle.metrics().num_alive_tasks()));
    }
    if let Some(resident) = resident_memory() {
        metrics.resident_memory.set(as_i64(resident));
    }
    metrics.uptime.set(metrics.started.elapsed().as_secs_f64());
    metrics.bridges_attached.set(as_i64(sample.bridges));
    let idle = as_i64(sample.pool_idle);
    metrics
        .db_connections
        .get_or_create(&[("state", "idle")])
        .set(idle);
    metrics
        .db_connections
        .get_or_create(&[("state", "in_use")])
        .set((i64::from(sample.pool_size) - idle).max(0));
    metrics
        .certificates_expiring
        .set(as_i64(sample.expiring_certificates));
    let mut text = String::new();
    encode(&mut text, &metrics.registry).expect("encoding to a string does not fail");
    text
}

pub fn set_certificate_jobs(pending: u64, failed: u64) {
    let jobs = &get().certificate_jobs;
    jobs.get_or_create(&[("status", "pending")])
        .set(as_i64(pending));
    jobs.get_or_create(&[("status", "failed")])
        .set(as_i64(failed));
}

// --- The endpoint and the monitor ------------------------------------------------------------------------------

pub type Sampler = Arc<dyn Fn() -> Sample + Send + Sync>;

/// Serves `GET /metrics` until the listener fails. Unauthenticated: it binds a port no `[[services]]` entry
/// exposes, so only Fly's scraper and the private network reach it, and nothing in it is secret.
pub async fn serve(listener: TcpListener, sampler: Sampler) {
    let mut errors = AcceptErrors::new("metrics accept failed");
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                errors.failed(error).await;
                continue;
            }
        };
        let sampler = sampler.clone();
        tokio::spawn(async move {
            let handler = hyper::service::service_fn(move |request: Request<_>| {
                let sampler = sampler.clone();
                async move { Ok::<_, std::convert::Infallible>(respond(&request, &sampler)) }
            });
            let served = hyper::server::conn::http1::Builder::new()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(Duration::from_secs(10))
                .serve_connection(TokioIo::new(stream), handler)
                .await;
            if let Err(error) = served {
                debug!(%error, "metrics connection failed");
            }
        });
    }
}

fn respond<B>(request: &Request<B>, sampler: &Sampler) -> Response<Full<bytes::Bytes>> {
    if request.method() != Method::GET || request.uri().path() != "/metrics" {
        let mut response = Response::new(Full::new(bytes::Bytes::from_static(b"not found\n")));
        *response.status_mut() = StatusCode::NOT_FOUND;
        return response;
    }
    let mut response = Response::new(Full::new(bytes::Bytes::from(render(sampler()))));
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(CONTENT));
    response
}

/// Binds `METRICS_LISTEN` as configured (Fly's scraper must reach it; nothing public does).
pub async fn bind(address: &str) -> Result<Option<TcpListener>> {
    match address {
        "" | "off" => Ok(None),
        address => {
            let address: SocketAddr = address.parse().context("METRICS_LISTEN")?;
            let listener = TcpListener::bind(address)
                .await
                .with_context(|| format!("binding {address}"))?;
            info!(%address, "serving metrics at /metrics");
            Ok(Some(listener))
        }
    }
}

/// Descriptor use as a fraction of the limit, at the levels that are logged: 0 below half, 1 from half, 2
/// from 80%.
pub fn fd_level(open: u64, limit: u64) -> u8 {
    if limit == 0 {
        return 0;
    }
    match open * 100 / limit {
        80.. => 2,
        50.. => 1,
        _ => 0,
    }
}

/// Warns when descriptor use crosses half and 80% of the limit (again every ten minutes while it stays
/// there), and refreshes the certificate job counts every minute.
pub async fn run_monitor(store: crate::store::Store, clock: crate::clock::Clock) {
    const REPEAT: Duration = Duration::from_secs(600);
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    let mut level = 0u8;
    let mut warned_at: Option<Instant> = None;
    let mut jobs_at: Option<Instant> = None;
    loop {
        interval.tick().await;
        if let (Some(open), Some(limit)) = (crate::net::open_fds(), fd_limit()) {
            let open = open as u64;
            let current = fd_level(open, limit);
            let repeat = warned_at.is_none_or(|at| at.elapsed() >= REPEAT);
            if current > level || (current > 0 && repeat) {
                let tasks = tokio::runtime::Handle::current()
                    .metrics()
                    .num_alive_tasks();
                warn!(
                    fds = open,
                    limit,
                    percent = open * 100 / limit.max(1),
                    tasks,
                    "open file descriptors are at {}% of the limit",
                    if current == 2 { 80 } else { 50 }
                );
                warned_at = Some(Instant::now());
            } else if current < level {
                info!(fds = open, limit, "open file descriptors are back down");
            }
            level = current;
        }
        if jobs_at.is_none_or(|at| at.elapsed() >= Duration::from_secs(60)) {
            jobs_at = Some(Instant::now());
            let since = clock.now_ms().saturating_sub(crate::clock::DAY_MS);
            match store.job_counts(since).await {
                Ok((pending, failed)) => set_certificate_jobs(pending, failed),
                Err(error) => {
                    debug!(error = %format!("{error:#}"), "counting certificate jobs failed")
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_issuance_errors() {
        let problem = |status, kind: &str| {
            anyhow::Error::new(Problem {
                status,
                kind: if kind.is_empty() {
                    String::new()
                } else {
                    format!("urn:ietf:params:acme:error:{kind}")
                },
                retry_after: None,
                message: "x".into(),
            })
            .context("issuing")
        };
        assert_eq!(error_class(&problem(400, "badNonce")), "bad_nonce");
        assert_eq!(error_class(&problem(429, "rateLimited")), "http_429");
        assert_eq!(error_class(&problem(429, "")), "http_429");
        assert_eq!(error_class(&problem(502, "")), "http_5xx");
        assert_eq!(error_class(&problem(500, "serverInternal")), "http_5xx");
        assert_eq!(error_class(&problem(400, "rejectedIdentifier")), "rejected");
        assert_eq!(error_class(&problem(400, "badCSR")), "rejected");
        assert_eq!(error_class(&problem(404, "")), "other");
        let transient = |message: &str| {
            anyhow::Error::new(Transient {
                message: message.into(),
                retry_after: None,
            })
        };
        assert_eq!(
            error_class(&transient("ACME server returned no nonce (HTTP 503)")),
            "nonce"
        );
        assert_eq!(
            error_class(&transient("ACME authorization ended in pending")),
            "authz_pending"
        );
        assert_eq!(
            error_class(&transient(
                "ACME order response could not be read (expected value at line 1 column 1): <html>"
            )),
            "bad_body"
        );
        // Recorded production failures, as text.
        for (reason, class) in [
            ("ACME server returned no nonce", "nonce"),
            (
                "error decoding response body for url (https://acme.zerossl.com/v2/DV90): expected value at line 1 column 1",
                "bad_body",
            ),
            (
                "fetching the ACME directory: error sending request for url (https://acme.zerossl.com/v2/DV90): operation timed out",
                "timeout",
            ),
            (
                "HTTP status server error (502 Bad Gateway) for url (https://acme.zerossl.com/v2/DV90)",
                "http_5xx",
            ),
            (
                "ACME request to https://acme.zerossl.com/v2/DV90/authz/x failed | HTTP 502 | <html>",
                "http_5xx",
            ),
            ("ACME authorization ended in pending", "authz_pending"),
            ("An identical record already exists.", "dns"),
            ("DNS record creation failed", "dns"),
            (
                "error sending request for url (https://api.cloudflare.com/client/v4/zones/z/dns_records)",
                "dns",
            ),
            (
                "fetching the ACME directory: error sending request for url (https://acme.zerossl.com/v2/DV90)",
                "network",
            ),
            (
                "urn:ietf:params:acme:error:rejectedIdentifier: invalid | HTTP 400 | {}",
                "rejected",
            ),
            (
                "urn:ietf:params:acme:error:badNonce: stale | HTTP 400 | {}",
                "bad_nonce",
            ),
            ("ACME authorization ended in invalid", "other"),
        ] {
            assert_eq!(error_class(&anyhow::anyhow!("{reason}")), class, "{reason}");
        }
    }

    #[test]
    fn names_detach_reasons_and_outcomes() {
        assert_eq!(detach_reason(None, true), "client_close");
        assert_eq!(detach_reason(None, false), "drop");
        assert_eq!(detach_reason(Some(1012), false), "drain");
        assert_eq!(detach_reason(Some(1000), true), "delete");
        assert_eq!(detach_reason(Some(1001), false), "idle_retire");
        assert_eq!(detach_reason(Some(1008), true), "server_close");
        assert_eq!(
            rejected_outcome(false, "no_bridge"),
            "rejected_unknown_tunnel"
        );
        assert_eq!(rejected_outcome(true, "no_bridge"), "rejected_no_bridge");
        assert_eq!(
            rejected_outcome(true, "certificate_not_ready"),
            "rejected_cert_not_ready"
        );
        assert_eq!(
            hello_outcome(&anyhow::anyhow!("ClientHello timeout")),
            "rejected_timeout"
        );
        assert_eq!(
            hello_outcome(&anyhow::anyhow!("invalid PROXY protocol header")),
            "rejected_bad_hello"
        );
        assert_eq!(fd_level(10, 100), 0);
        assert_eq!(fd_level(50, 100), 1);
        assert_eq!(fd_level(85, 100), 2);
        assert_eq!(fd_level(1, 0), 0);
    }

    #[tokio::test]
    async fn serves_metrics() {
        bridge_attach("ok");
        bridge_detach("drop");
        visitor("served_local");
        visitor_finished(Duration::from_millis(1500), 10, 20);
        db_operation("tunnel", Duration::from_millis(3), false);
        acme_attempt("issue", "retry", Duration::from_secs(2));
        acme_failure("issue", "nonce");
        let _open = visitor_open();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let sampler: Sampler = Arc::new(|| Sample {
            bridges: 3,
            pool_size: 4,
            pool_idle: 1,
            expiring_certificates: 2,
        });
        let server = tokio::spawn(serve(listener, sampler));
        crate::install_crypto_provider();
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let response = client
            .get(format!("http://{address}/metrics"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert!(
            response.headers()[CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with("application/openmetrics-text")
        );
        let text = response.text().await.unwrap();
        for line in [
            "opentunnel_bridges_attached 3",
            "opentunnel_db_pool_connections{state=\"in_use\"} 3",
            "opentunnel_certificates_expiring 2",
            "# TYPE opentunnel_bridge_attaches counter",
            "# TYPE opentunnel_visitor_connection_duration_seconds histogram",
            "# TYPE opentunnel_process_open_fds gauge",
            "# TYPE opentunnel_tokio_tasks gauge",
            "# EOF",
        ] {
            assert!(text.contains(line), "{line} missing from\n{text}");
        }
        for prefix in [
            "opentunnel_bridge_attaches_total{result=\"ok\"} ",
            "opentunnel_bridge_detaches_total{reason=\"drop\"} ",
            "opentunnel_visitor_connections_total{outcome=\"served_local\"} ",
            "opentunnel_visitor_bytes_total{direction=\"out\"} ",
            "opentunnel_db_errors_total{operation=\"tunnel\"} ",
            "opentunnel_db_query_duration_seconds_bucket{le=\"0.005\",operation=\"tunnel\"} ",
            "opentunnel_acme_attempts_total{kind=\"issue\",outcome=\"retry\"} ",
            "opentunnel_acme_failures_total{kind=\"issue\",class=\"nonce\"} ",
            "opentunnel_visitor_connections_open ",
            "opentunnel_process_max_fds ",
            "opentunnel_process_resident_memory_bytes ",
            "opentunnel_uptime_seconds ",
        ] {
            assert!(
                text.lines().any(|line| line.starts_with(prefix)),
                "{prefix} missing from\n{text}"
            );
        }
        let missing = client
            .get(format!("http://{address}/other"))
            .send()
            .await
            .unwrap();
        assert_eq!(missing.status(), 404);
        server.abort();
    }
}
