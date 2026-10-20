//! Background work that replaces the certificate Workflow and the Durable Object alarms: durable issuance jobs
//! (resumed after a restart), renewal alarms, the sweep for silent bridges, and the API domain's certificate.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use opentunnel::protocol::api::CertificateState;
use tokio::task::JoinSet;
use tracing::{debug, error, info, warn};

use crate::acme::Challenge;
use crate::clock::{DAY_MS, HOUR_MS, MINUTE_MS};
use crate::crypto::uuid;
use crate::issuer::Issuer;
use crate::retry;
use crate::service::{RENEW_BEFORE_MS, Service};
use crate::store::{Job, JobKind, LEASE_MS, ServerCertificate};
use crate::tls;

/// Attempts per job for failures that are not known to be transient, like the Workflow step's two retries.
/// Transient ones are retried for `retry::RETRY_WINDOW_MS`.
pub const ATTEMPTS: u32 = 3;
const PERSIST_FAILED: &str = "Failed to persist certificate state: tunnel or certificate not found";
/// Imported issuance gets this long to finish on the Worker before this server takes it over.
pub const ORPHAN_GRACE_MS: u64 = 15 * MINUTE_MS;
/// Without a known reason to wake earlier (a due job or alarm, or a local notification), the job runner and the
/// alarm loop look at the database again after this long plus up to as much again of jitter, which spreads the
/// machines' polls apart. Jobs and alarms added elsewhere are run by the machine that added them (it is
/// notified); polling only covers machines that went away, and leases and compare-and-set keep it safe.
const POLL_MS: u64 = 30_000;

/// The CA cool-down: this many failures in a row that point at the CA (or one rate limit) stop new issuance
/// for a while, starting at a minute and doubling up to an hour while attempts keep failing.
const COOLDOWN_FAILURES: u32 = 5;
const COOLDOWN_MIN_MS: u64 = MINUTE_MS;
const COOLDOWN_MAX_MS: u64 = HOUR_MS;
/// In `meta`, `<until> <cool-down>` (Unix ms, ms), so every machine pauses together.
const COOLDOWN_KEY: &str = "ca_cooldown";
/// How often a machine reads the shared cool-down again.
const COOLDOWN_REFRESH_MS: u64 = 15_000;

/// Failure classes (`metrics::error_class`) that say the CA is struggling or limiting us, rather than one
/// tunnel's request being wrong or the DNS provider failing.
fn ca_trouble(class: &str) -> bool {
    matches!(
        class,
        "network" | "timeout" | "http_5xx" | "http_429" | "bad_body" | "nonce" | "bad_nonce"
    )
}

/// The CA cool-down as one machine knows it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Cooldown {
    /// CA failures in a row since the last success or cool-down.
    pub failures: u32,
    /// The last cool-down's length; 0 after a success.
    pub cooldown_ms: u64,
    /// No new issuance before this (Unix ms).
    pub until: u64,
}

impl Cooldown {
    /// Records a failed attempt of `class`. Returns whether a cool-down starts.
    pub fn failed(&mut self, class: &str, retry_after_ms: Option<u64>, now: u64) -> bool {
        if !ca_trouble(class) {
            return false;
        }
        self.failures += 1;
        if class != "http_429" && self.failures < COOLDOWN_FAILURES {
            return false;
        }
        self.cooldown_ms = if self.cooldown_ms == 0 {
            COOLDOWN_MIN_MS
        } else {
            (self.cooldown_ms * 2).min(COOLDOWN_MAX_MS)
        };
        self.until = self.until.max(
            now + self
                .cooldown_ms
                .max(retry_after_ms.unwrap_or(0).min(COOLDOWN_MAX_MS)),
        );
        self.failures = 0;
        true
    }

    /// Records a success: the CA works again. Returns whether a cool-down was in effect.
    pub fn succeeded(&mut self) -> bool {
        let was = self.cooldown_ms > 0;
        *self = Self::default();
        was
    }

    fn encode(&self) -> String {
        format!("{} {}", self.until, self.cooldown_ms)
    }

    /// Merges the shared state: the later end and the longer cool-down.
    fn merge(&mut self, stored: &str) {
        let mut fields = stored
            .split(' ')
            .map(|field| field.parse::<u64>().unwrap_or(0));
        let (until, cooldown) = (fields.next().unwrap_or(0), fields.next().unwrap_or(0));
        self.until = self.until.max(until);
        self.cooldown_ms = self.cooldown_ms.max(cooldown);
    }
}

/// At shutdown, how long attempts get to clean up before the leases are released anyway.
const RELEASE_WAIT: Duration = Duration::from_secs(15);

fn poll_wait() -> u64 {
    POLL_MS + (retry::jitter() * POLL_MS as f64) as u64
}

pub struct Jobs {
    pub service: Service,
    pub issuer: Arc<Issuer>,
    pub concurrency: usize,
    /// Delay before the second attempt; it doubles for each one after.
    pub retry_delay_ms: u64,
    pub server: Option<Arc<ServerCertificates>>,
    /// This process's name on job leases.
    pub owner: String,
    /// Jobs running here, by certificate ID.
    running: Mutex<HashMap<String, JobKind>>,
    /// The CA cool-down, and when the shared one was last read.
    cooldown: Mutex<(Cooldown, u64)>,
    /// Set at shutdown: no new jobs start.
    stopping: std::sync::atomic::AtomicBool,
}

/// The lease owner for this process: the Fly machine ID, which survives restarts so a restarted server takes
/// its own jobs back at once, or a random name.
pub fn lease_owner() -> String {
    std::env::var("FLY_MACHINE_ID")
        .ok()
        .filter(|id| !id.is_empty())
        .unwrap_or_else(|| format!("process-{}", uuid()))
}

impl Jobs {
    pub fn new(
        service: Service,
        issuer: Arc<Issuer>,
        concurrency: usize,
        retry_delay_ms: u64,
        server: Option<Arc<ServerCertificates>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            service,
            issuer,
            concurrency: concurrency.max(1),
            retry_delay_ms,
            server,
            owner: lease_owner(),
            running: Mutex::new(HashMap::new()),
            cooldown: Mutex::new((Cooldown::default(), 0)),
            stopping: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Runs due jobs forever, `concurrency` at a time.
    pub async fn run(self: Arc<Self>) {
        let mut tasks = JoinSet::new();
        loop {
            let next = match self.start_due(&mut tasks).await {
                Ok(next) => next,
                Err(error) => {
                    error!(%error, "failed to start certificate jobs");
                    None
                }
            };
            let poll = poll_wait();
            let wait = next.map_or(poll, |at| at.saturating_sub(self.service.now()).min(poll));
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(wait.max(50))) => {}
                _ = self.service.jobs.notified() => {}
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
    }

    /// Claims and starts due jobs while there is room. Returns when the next job not yet due may be taken.
    async fn start_due(self: &Arc<Self>, tasks: &mut JoinSet<()>) -> Result<Option<u64>> {
        let running = self.running.lock().expect("running lock").len();
        if self.stopping.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(None);
        }
        if running >= self.concurrency {
            // A finishing task wakes the runner.
            return Ok(None);
        }
        let store = &self.service.store;
        let limit = self.concurrency + running + 1;
        let now = self.service.now();
        // Due jobs come first, renewals before first issuance.
        let schedule = store.job_schedule(&self.owner, now, limit).await?;
        let mut next = schedule.iter().map(|(_, at, _)| *at).find(|at| *at > now);
        if next.is_none() && schedule.len() == limit {
            // Every listed job is due, so there may be more: look again soon.
            next = Some(now + 1_000);
        }
        let cooling_until = self.cooling_until(now).await;
        let cooling = cooling_until > now;
        if cooling {
            next = Some(next.map_or(cooling_until, |next| next.min(cooling_until)));
        }
        let due = schedule
            .into_iter()
            .filter(|(_, at, _)| *at <= now)
            .map(|(id, _, kind)| (id, kind));
        for (id, kind) in due {
            {
                let mut running = self.running.lock().expect("running lock");
                if running.len() >= self.concurrency {
                    break;
                }
                // One slot stays free for renewals, so first issuance cannot take them all.
                let issuing = running
                    .values()
                    .filter(|kind| **kind == JobKind::Issue)
                    .count();
                if kind == JobKind::Issue && issuing >= self.issue_slots() {
                    continue;
                }
                // While the CA cools down: no first issuance, and one renewal at a time, which also finds out
                // whether it works again.
                if cooling && (kind == JobKind::Issue || running.len() > issuing) {
                    continue;
                }
                if running.insert(id.clone(), kind).is_some() {
                    continue;
                }
            }
            // Another server may have taken it since it was listed.
            let job = match store.claim_job(&id, &self.owner, self.service.now()).await {
                Ok(Some(job)) => job,
                Ok(None) => {
                    self.running.lock().expect("running lock").remove(&id);
                    continue;
                }
                Err(error) => {
                    self.running.lock().expect("running lock").remove(&id);
                    return Err(error);
                }
            };
            let jobs = self.clone();
            tasks.spawn(async move {
                let id = job.certificate_id.clone();
                if let Err(error) = jobs.execute(job).await {
                    error!(%error, certificate = %id, "certificate job failed to record its result");
                }
                jobs.running.lock().expect("running lock").remove(&id);
                jobs.service.jobs.notify_one();
            });
        }
        Ok(next)
    }

    /// The end of the CA cool-down (Unix ms; in the past when there is none), from the shared state at most
    /// `COOLDOWN_REFRESH_MS` old.
    async fn cooling_until(&self, now: u64) -> u64 {
        let (local, read_at) = *self.cooldown.lock().expect("cooldown lock");
        if now.saturating_sub(read_at) < COOLDOWN_REFRESH_MS {
            return local.until;
        }
        match self.service.store.meta(COOLDOWN_KEY).await {
            Ok(stored) => {
                let mut cooldown = self.cooldown.lock().expect("cooldown lock");
                if let Some(stored) = stored {
                    cooldown.0.merge(&stored);
                }
                cooldown.1 = now;
                cooldown.0.until
            }
            Err(error) => {
                warn!(%error, "reading the CA cool-down failed");
                local.until
            }
        }
    }

    /// Feeds an attempt's outcome to the CA cool-down, and shares a change with every machine.
    async fn cooldown_outcome(&self, result: Result<(), &anyhow::Error>) {
        let now = self.service.now();
        let shared = {
            let (cooldown, _) = &mut *self.cooldown.lock().expect("cooldown lock");
            match result {
                Ok(()) => cooldown.succeeded().then(|| cooldown.encode()),
                Err(error) => {
                    let class = crate::metrics::error_class(error);
                    let retry_after = error
                        .chain()
                        .find_map(|cause| cause.downcast_ref::<crate::acme::Problem>())
                        .and_then(|problem| problem.retry_after)
                        .map(|retry| retry.as_millis() as u64);
                    if cooldown.failed(class, retry_after, now) {
                        crate::metrics::acme_cooldown();
                        warn!(
                            cooldown_ms = cooldown.cooldown_ms,
                            until = %crate::clock::iso(cooldown.until),
                            error_class = class,
                            "the CA keeps failing; pausing new certificate issuance"
                        );
                        Some(cooldown.encode())
                    } else {
                        None
                    }
                }
            }
        };
        if let Some(value) = shared
            && let Err(error) = self.service.store.set_meta(COOLDOWN_KEY, &value).await
        {
            warn!(%error, "sharing the CA cool-down failed");
        }
    }

    /// Jobs of first issuance that may run at once: all but one slot, which renewals keep.
    fn issue_slots(&self) -> usize {
        if self.concurrency > 1 {
            self.concurrency - 1
        } else {
            self.concurrency
        }
    }

    /// At shutdown: starts no more jobs, and ends the attempts running, each after deleting its challenge
    /// records (a process that exits mid-attempt leaves them in the zone).
    pub fn stop(&self) {
        self.stopping
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.issuer.stop();
    }

    /// Gives up this process's job leases, on shutdown, once the attempts running have cleaned up (at most
    /// `RELEASE_WAIT`), so another machine resumes them at once.
    pub async fn release(&self) {
        let deadline = tokio::time::Instant::now() + RELEASE_WAIT;
        while !self.running.lock().expect("running lock").is_empty()
            && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if let Err(error) = self.service.store.release_leases(&self.owner).await {
            warn!(%error, "releasing job leases failed");
        }
    }

    /// Runs every due job to completion, for tests.
    pub async fn run_due(self: &Arc<Self>) -> Result<usize> {
        let due = self
            .service
            .store
            .claim_due_jobs(&self.owner, self.service.now(), 100)
            .await?;
        let count = due.len();
        for job in due {
            self.execute(job).await?;
        }
        Ok(count)
    }

    /// One attempt of a job, and what follows from it.
    async fn execute(&self, job: Job) -> Result<()> {
        let service = &self.service;
        let tunnel = job.tunnel_id.clone();
        let certificate_id = job.certificate_id.clone();
        let kind = job.kind;
        let owner = &self.owner;
        let started = std::time::Instant::now();
        if let Err(reason) = self.permitted(&job) {
            return self.refuse(&job, reason, started).await;
        }
        if !self.wanted(&job).await {
            return self.abandon(&job, None, started).await;
        }
        let issue = self
            .issuer
            .issue(&job.identifiers, &job.csr, async |challenge: Challenge| {
                // Only first issuance shows the challenge; a renewal keeps showing the current certificate.
                if kind != JobKind::Issue {
                    return Ok(());
                }
                let Some(tunnel) = &tunnel else { return Ok(()) };
                let state = CertificateState::Challenge {
                    token: challenge.token,
                    key: challenge.key,
                };
                if !service
                    .update_certificate(tunnel, &certificate_id, state)
                    .await?
                {
                    anyhow::bail!(PERSIST_FAILED);
                }
                Ok(())
            });
        // Keep the lease while the order runs, so no other server takes the job over.
        tokio::pin!(issue);
        let mut renew = tokio::time::interval(Duration::from_millis(LEASE_MS / 3));
        renew.tick().await;
        let result = loop {
            tokio::select! {
                result = &mut issue => break result,
                _ = renew.tick() => {
                    match service.store.extend_lease(&job.certificate_id, owner, service.now()).await {
                        Ok(true) => {}
                        Ok(false) => warn!(certificate = %job.certificate_id, "lost the lease on a certificate job"),
                        Err(error) => warn!(%error, certificate = %job.certificate_id, "extending a job lease failed"),
                    }
                }
            }
        };
        // A server that lost its lease (it could not extend it in time) leaves the results to the one that
        // took the job over.
        if let Ok(false) = service
            .store
            .extend_lease(&job.certificate_id, owner, service.now())
            .await
        {
            warn!(certificate = %job.certificate_id, "lost the lease on a certificate job; not recording its result");
            return Ok(());
        }
        let now = service.now();
        if let Err(error) = &result
            && error.downcast_ref::<crate::acme::Stopped>().is_some()
        {
            // Shutting down: nothing failed, and the lease is released for another machine to resume.
            info!(certificate = %job.certificate_id, "certificate issuance stopped for shutdown");
            return Ok(());
        }
        self.cooldown_outcome(result.as_ref().map(drop)).await;
        match result {
            Ok(issued) => {
                crate::metrics::acme_attempt(kind.as_str(), "success", started.elapsed());
                match (&job.kind, &job.tunnel_id) {
                    (JobKind::Server, _) => {
                        if let Some(server) = &self.server {
                            server.installed(&job, &issued).await?;
                        }
                    }
                    (_, Some(tunnel)) => {
                        let state = CertificateState::Ready {
                            certificate: issued.certificate,
                            chain: issued.chain,
                            expiry: issued.expiry,
                        };
                        if !service
                            .update_certificate(tunnel, &job.certificate_id, state)
                            .await?
                        {
                            warn!(tunnel, certificate = %job.certificate_id, "issued certificate is no longer wanted");
                        }
                    }
                    (_, None) => {}
                }
                service
                    .store
                    .finish_job(&job.certificate_id, owner, "done", None, now)
                    .await
                    .map(drop)
            }
            Err(error) => {
                let reason = format!("{error:#}");
                // The tunnel was deleted or issued another certificate meanwhile: nobody wants this one.
                if reason.contains(PERSIST_FAILED) || !self.wanted(&job).await {
                    return self.abandon(&job, Some(reason), started).await;
                }
                let error_class = crate::metrics::error_class(&error);
                let status = error
                    .chain()
                    .find_map(|cause| cause.downcast_ref::<crate::acme::Problem>())
                    .map(|problem| problem.status);
                // The reason includes the ACME problem document (or the start of the response body).
                warn!(
                    certificate = %job.certificate_id,
                    tunnel = job.tunnel_id.as_deref(),
                    kind = kind.as_str(),
                    attempt = job.attempts + 1,
                    error_class,
                    status,
                    error = %reason,
                    "certificate issuance attempt failed"
                );
                crate::metrics::acme_failure(kind.as_str(), error_class);
                let attempts = job.attempts + 1;
                let class = retry::classify(&error);
                if let Some(at) = retry::next_attempt(
                    class,
                    attempts,
                    self.retry_delay_ms,
                    job.created_at,
                    now,
                    retry::jitter(),
                ) {
                    crate::metrics::acme_attempt(kind.as_str(), "retry", started.elapsed());
                    info!(certificate = %job.certificate_id, attempt = attempts, ?class, error_class, in_ms = at - now, "retrying certificate issuance");
                    return service
                        .store
                        .retry_job(&job.certificate_id, owner, attempts, at, reason, now)
                        .await
                        .map(drop);
                }
                crate::metrics::acme_attempt(kind.as_str(), "failed", started.elapsed());
                error!(
                    certificate = %job.certificate_id,
                    tunnel = job.tunnel_id.as_deref(),
                    kind = kind.as_str(),
                    attempt = attempts,
                    ?class,
                    error_class,
                    status,
                    error = %reason,
                    "certificate issuance gave up"
                );
                if let (JobKind::Issue | JobKind::Renew, Some(tunnel)) = (&job.kind, &job.tunnel_id)
                {
                    // The tenant sees a summary; the full error (with what the CA answered) stays in the log and
                    // the job.
                    let state = CertificateState::Failed {
                        reason: public_reason(&error),
                    };
                    service
                        .update_certificate(tunnel, &job.certificate_id, state)
                        .await?;
                }
                service
                    .store
                    .finish_job(&job.certificate_id, owner, "failed", Some(reason), now)
                    .await
                    .map(drop)
            }
        }
    }

    /// Whether the job asks only for names it may: a tunnel's own hostname and wildcard, with a CSR for exactly
    /// those, or the API domain for the server's own certificate. Checked right before every order, whatever
    /// queued the job (a bind, a renewal, an imported record, the reconcile).
    fn permitted(&self, job: &Job) -> Result<(), String> {
        let domain = self.service.domain.to_ascii_lowercase();
        match (&job.kind, &job.tunnel_id) {
            (JobKind::Issue | JobKind::Renew, Some(tunnel)) => {
                crate::csr::check_tunnel_request(tunnel, &domain, &job.identifiers, &job.csr)
            }
            (JobKind::Server, None) => {
                let names_domain =
                    |names: &[String]| names.len() == 1 && names[0].eq_ignore_ascii_case(&domain);
                let request = crate::csr::parse(&job.csr)
                    .ok_or_else(|| "the CSR does not parse or verify".to_owned())?;
                if names_domain(&job.identifiers) && names_domain(&request.identifiers) {
                    Ok(())
                } else {
                    Err(format!(
                        "a server certificate for {:?} is not for {domain}",
                        job.identifiers
                    ))
                }
            }
            _ => Err("a tunnel certificate without a tunnel".to_owned()),
        }
    }

    /// Ends a job that asks for names it may not, without ordering anything.
    async fn refuse(&self, job: &Job, reason: String, started: std::time::Instant) -> Result<()> {
        crate::metrics::acme_attempt(job.kind.as_str(), "refused", started.elapsed());
        error!(
            certificate = %job.certificate_id,
            tunnel = job.tunnel_id.as_deref(),
            kind = job.kind.as_str(),
            identifiers = ?job.identifiers,
            reason,
            "refused a certificate job for names it may not have"
        );
        let reason = format!("Certificate request refused: {reason}");
        if let (JobKind::Issue | JobKind::Renew, Some(tunnel)) = (&job.kind, &job.tunnel_id) {
            let state = CertificateState::Failed {
                reason: reason.clone(),
            };
            self.service
                .update_certificate(tunnel, &job.certificate_id, state)
                .await?;
        }
        self.service
            .store
            .finish_job(
                &job.certificate_id,
                &self.owner,
                "failed",
                Some(reason),
                self.service.now(),
            )
            .await
            .map(drop)
    }

    /// Whether the job's tunnel still waits for its certificate. When that cannot be read, it is assumed to.
    async fn wanted(&self, job: &Job) -> bool {
        let (JobKind::Issue | JobKind::Renew, Some(tunnel)) = (&job.kind, &job.tunnel_id) else {
            return true;
        };
        match self
            .service
            .wants_certificate(tunnel, &job.certificate_id)
            .await
        {
            Ok(wanted) => wanted,
            Err(error) => {
                warn!(%error, tunnel, certificate = %job.certificate_id, "checking whether a certificate is still wanted failed");
                true
            }
        }
    }

    /// Ends a job nobody wants any more (its tunnel was deleted or bound another certificate) without counting
    /// it as a failure.
    async fn abandon(
        &self,
        job: &Job,
        reason: Option<String>,
        started: std::time::Instant,
    ) -> Result<()> {
        crate::metrics::acme_attempt(job.kind.as_str(), "abandoned", started.elapsed());
        info!(
            certificate = %job.certificate_id,
            tunnel = job.tunnel_id.as_deref(),
            kind = job.kind.as_str(),
            "certificate is no longer wanted; abandoning its issuance"
        );
        self.service
            .store
            .finish_job(
                &job.certificate_id,
                &self.owner,
                "abandoned",
                reason,
                self.service.now(),
            )
            .await
            .map(drop)
    }
}

/// Fires due renewal alarms. Returns how many fired.
pub async fn fire_due_alarms(service: &Service) -> Result<usize> {
    Ok(fire_due_alarms_and_next(service).await?.0)
}

/// [`fire_due_alarms`], and when the next alarm is due.
async fn fire_due_alarms_and_next(service: &Service) -> Result<(usize, Option<u64>)> {
    let (due, next) = service
        .store
        .take_due_alarms_and_next(service.now())
        .await?;
    for id in &due {
        if let Err(error) = service.alarm(id).await {
            // Like a Durable Object alarm that throws: try again shortly.
            error!(%error, tunnel = %id, "renewal alarm failed");
            service
                .store
                .set_alarm(id, Some(service.now() + MINUTE_MS))
                .await?;
        }
    }
    // An alarm that failed was set a minute out, after the next one was read.
    let next = if due.is_empty() {
        next
    } else {
        Some(next.map_or(service.now() + MINUTE_MS, |next| {
            next.min(service.now() + MINUTE_MS)
        }))
    };
    Ok((due.len(), next))
}

pub async fn run_alarms(service: Service) {
    loop {
        let next = match fire_due_alarms_and_next(&service).await {
            Ok((_, next)) => next,
            Err(error) => {
                error!(%error, "renewal alarms failed");
                None
            }
        };
        let poll = poll_wait();
        let wait = next.map_or(poll, |at| at.saturating_sub(service.now()).min(poll));
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(wait.max(100))) => {}
            _ = service.alarms.notified() => {}
        }
    }
}

pub async fn run_sweeper(service: Service) {
    let mut interval = tokio::time::interval(Duration::from_millis(
        opentunnel::protocol::bridge::HEARTBEAT_MS,
    ));
    loop {
        interval.tick().await;
        if let Err(error) = service.sweep().await {
            error!(%error, "bridge sweep failed");
        }
    }
}

pub async fn run_reconcile(service: Service) {
    let mut interval = tokio::time::interval(Duration::from_secs(5 * 60));
    loop {
        interval.tick().await;
        match service.resume_orphaned_issuance(ORPHAN_GRACE_MS).await {
            Ok(0) => {}
            Ok(resumed) => info!(resumed, "resumed certificate issuance without a job"),
            Err(error) => error!(%error, "resuming certificate issuance failed"),
        }
        match service.store.prune_rate_limits(service.now()).await {
            Ok(0) => {}
            Ok(pruned) => debug!(pruned, "pruned rate limits"),
            Err(error) => warn!(%error, "pruning rate limits failed"),
        }
        match service.retry_failed_issuance().await {
            Ok(0) => {}
            Ok(requeued) => info!(
                requeued,
                "queued transiently failed certificate issuance again"
            ),
            Err(error) => error!(%error, "queueing failed certificate issuance again failed"),
        }
    }
}

/// How often one machine sweeps leftover challenge records, and how old they must be.
const DNS_SWEEP_EVERY_MS: u64 = 10 * MINUTE_MS;
const DNS_SWEEP_AGE_MS: u64 = HOUR_MS;
/// Records deleted per sweep at most, so a large backlog stays within Cloudflare's API limits.
const DNS_SWEEP_LIMIT: usize = 1_000;
/// In `meta`: `<owner> <until>`, the machine that sweeps.
const DNS_SWEEPER_KEY: &str = "dns_sweeper";

/// Every few minutes, on one machine at a time, deletes `_acme-challenge` TXT records older than an hour that
/// no running issuance uses: what attempts could not delete (a process killed mid-attempt, a deactivation that
/// failed, Cloudflare errors) would otherwise stay in the zone for good, and the zone has a record limit.
pub async fn run_dns_sweeper(jobs: Arc<Jobs>) {
    let Issuer::Acme(acme) = jobs.issuer.as_ref() else {
        return;
    };
    let Some(dns) = acme.dns().cloned() else {
        return;
    };
    loop {
        tokio::time::sleep(Duration::from_millis(
            DNS_SWEEP_EVERY_MS / 2 + (retry::jitter() * DNS_SWEEP_EVERY_MS as f64) as u64,
        ))
        .await;
        if jobs.stopping.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        match sweep_dns(&jobs, &dns).await {
            Ok(Some(0) | None) => {}
            Ok(Some(swept)) => info!(swept, "deleted leftover DNS challenge records"),
            Err(error) => {
                warn!(error = %format!("{error:#}"), "sweeping DNS challenge records failed")
            }
        }
    }
}

/// One sweep, if this machine holds the sweeper lease. `None` when another machine does.
pub async fn sweep_dns(jobs: &Jobs, dns: &crate::dns::DnsProvider) -> Result<Option<usize>> {
    let service = &jobs.service;
    let store = &service.store;
    let now = service.now();
    let current = store.meta(DNS_SWEEPER_KEY).await?;
    if let Some((owner, until)) = current.as_deref().and_then(|value| value.split_once(' '))
        && owner != jobs.owner
        && until.parse::<u64>().is_ok_and(|until| until > now)
    {
        return Ok(None);
    }
    let lease = format!("{} {}", jobs.owner, now + 2 * DNS_SWEEP_EVERY_MS);
    if !store
        .swap_meta(DNS_SWEEPER_KEY, current.as_deref(), &lease)
        .await?
    {
        return Ok(None);
    }
    let in_flight: std::collections::HashSet<String> = store
        .leased_job_identifiers(now)
        .await?
        .into_iter()
        .map(|identifier| {
            format!(
                "_acme-challenge.{}",
                identifier.trim_start_matches("*.").to_ascii_lowercase()
            )
        })
        .collect();
    let domain = service.domain.to_ascii_lowercase();
    dns.sweep(
        &domain,
        now.saturating_sub(DNS_SWEEP_AGE_MS),
        &in_flight,
        DNS_SWEEP_LIMIT,
        Duration::from_millis(250),
    )
    .await
    .map(Some)
}

/// The API domain's own certificate: issued through the same jobs, renewed 30 days before expiry, and served
/// from memory.
pub struct ServerCertificates {
    pub service: Service,
    pub name: String,
    pub resolver: Arc<tls::ServerCertificate>,
}

impl ServerCertificates {
    /// Serves the stored certificate, if any.
    pub async fn load(&self) -> Result<()> {
        if let Some(stored) = self.service.store.server_certificate(&self.name).await?
            && let (Some(certificate), Some(chain)) = (&stored.certificate, &stored.chain)
        {
            self.resolver
                .install(&format!("{certificate}\n{chain}"), &stored.private_key)?;
            info!(domain = %self.name, expiry = ?stored.expiry, "serving the stored certificate");
        }
        Ok(())
    }

    /// Starts issuance when there is no certificate or it is due for renewal and no job is pending.
    pub async fn ensure(&self) -> Result<()> {
        let store = &self.service.store;
        let now = self.service.now();
        let stored = store.server_certificate(&self.name).await?;
        let due = stored
            .as_ref()
            .and_then(|stored| stored.expiry.as_deref())
            .and_then(crate::clock::parse_iso)
            .is_none_or(|expiry| expiry.saturating_sub(RENEW_BEFORE_MS) <= now);
        if !due {
            return Ok(());
        }
        let job_key = format!("server_job:{}", self.name);
        let previous = store.meta(&job_key).await?;
        if let Some(job) = &previous
            && store.job_pending(job).await?
        {
            return Ok(());
        }
        let stored = match stored {
            Some(stored) => stored,
            None => {
                let key = rcgen::KeyPair::generate()?;
                let mut params = rcgen::CertificateParams::new(vec![self.name.clone()])?;
                params
                    .distinguished_name
                    .push(rcgen::DnType::CommonName, self.name.clone());
                let csr = params.serialize_request(&key)?.pem()?;
                let created = ServerCertificate {
                    private_key: key.serialize_pem(),
                    csr,
                    certificate: None,
                    chain: None,
                    expiry: None,
                };
                // Another server sharing the database may have stored one first; everyone uses that one.
                store
                    .create_server_certificate(&self.name, created, now)
                    .await?
            }
        };
        let id = format!("server_{}", uuid());
        if !store.swap_meta(&job_key, previous.as_deref(), &id).await? {
            // Another server requested it meanwhile.
            return Ok(());
        }
        store
            .add_job(
                Job {
                    certificate_id: id.clone(),
                    tunnel_id: None,
                    kind: JobKind::Server,
                    identifiers: vec![self.name.clone()],
                    csr: stored.csr,
                    attempts: 0,
                    created_at: now,
                },
                now,
            )
            .await?;
        self.service.jobs.notify_one();
        info!(domain = %self.name, "requested a certificate for the API domain");
        Ok(())
    }

    async fn installed(&self, job: &Job, issued: &crate::acme::Issued) -> Result<()> {
        let store = &self.service.store;
        let Some(stored) = store.server_certificate(&self.name).await? else {
            return Ok(());
        };
        if stored.csr != job.csr {
            return Ok(());
        }
        self.resolver.install(
            &format!("{}\n{}", issued.certificate, issued.chain),
            &stored.private_key,
        )?;
        store
            .save_server_certificate(
                &self.name,
                ServerCertificate {
                    certificate: Some(issued.certificate.clone()),
                    chain: Some(issued.chain.clone()),
                    expiry: Some(issued.expiry.clone()),
                    ..stored
                },
                self.service.now(),
            )
            .await?;
        info!(domain = %self.name, expiry = %issued.expiry, "installed a new certificate for the API domain");
        Ok(())
    }

    pub async fn run(self: Arc<Self>) {
        loop {
            // Another machine may have issued or renewed it.
            if let Err(error) = self.load().await {
                error!(%error, "loading the API domain certificate failed");
            }
            if let Err(error) = self.ensure().await {
                error!(%error, "ensuring the API domain certificate failed");
            }
            // Hourly, which also spaces out retries after a failed issuance; often while there is none.
            let wait = if self.resolver.is_installed() {
                HOUR_MS.min(DAY_MS)
            } else {
                10_000
            };
            tokio::time::sleep(Duration::from_millis(wait)).await;
        }
    }
}

/// What a tenant sees of a failed issuance: the kind of failure, never what a server answered (which could be
/// anything a URL the CA named returned). Worded so `analytics::certificate_failure` buckets it as the full error.
pub fn public_reason(error: &anyhow::Error) -> String {
    let full = format!("{error:#}");
    let status = error.chain().find_map(|cause| {
        cause
            .downcast_ref::<crate::acme::Problem>()
            .map(|problem| problem.status)
            .or_else(|| {
                cause
                    .downcast_ref::<reqwest::Error>()
                    .and_then(reqwest::Error::status)
                    .map(|status| status.as_u16())
            })
    });
    let detail = match crate::analytics::certificate_failure(&full) {
        "config" => "the server's ACME settings are required but missing".to_owned(),
        "acme_rate_limit" => {
            "the certificate authority rateLimited the request (HTTP 429)".to_owned()
        }
        "dns" => "the DNS challenge record could not be set".to_owned(),
        "acme_authorization" => {
            "the certificate authority did not validate the authorization".to_owned()
        }
        "acme_order" => "the ACME order did not complete".to_owned(),
        "persist" => "Failed to persist certificate state".to_owned(),
        "acme_http" => match status {
            Some(status) => format!("the certificate authority answered HTTP {status}"),
            None => match full.match_indices("HTTP ").find_map(|(index, _)| {
                let digits = full.get(index + 5..index + 8)?;
                digits
                    .bytes()
                    .all(|byte| byte.is_ascii_digit())
                    .then_some(digits)
            }) {
                Some(status) => format!("the certificate authority answered HTTP {status}"),
                None => "the certificate authority answered with an error".to_owned(),
            },
        },
        _ => format!(
            "the certificate authority could not be used ({})",
            crate::metrics::error_class(error)
        ),
    };
    format!("Certificate issuance failed: {detail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenants_see_the_kind_of_failure_without_what_servers_answered() {
        for (full, bucket) in [
            ("ACME_EAB_KID and ACME_EAB_HMAC_KEY are required", "config"),
            (
                "urn:ietf:params:acme:error:rateLimited: too many | HTTP 429 | {\"secret\":1}",
                "acme_rate_limit",
            ),
            ("creating the DNS record failed: <html>body</html>", "dns"),
            (
                "ACME authorization for x ended in invalid: dns: <body>",
                "acme_authorization",
            ),
            ("ACME order ended in invalid", "acme_order"),
            (
                "ACME request to https://ca/x failed | HTTP 500 | internal secrets",
                "acme_http",
            ),
            ("something else entirely: private", "other"),
        ] {
            let public = public_reason(&anyhow::anyhow!(full.to_owned()));
            assert!(
                !public.contains("secret")
                    && !public.contains("body")
                    && !public.contains("private"),
                "{public}"
            );
            assert_eq!(
                crate::analytics::certificate_failure(&public),
                bucket,
                "{public}"
            );
        }
    }

    #[test]
    fn the_ca_cools_down_after_failures_and_doubles_until_it_works() {
        let mut cooldown = Cooldown::default();
        // One tunnel's bad request or the DNS provider says nothing about the CA.
        for _ in 0..10 {
            assert!(!cooldown.failed("rejected", None, 0));
            assert!(!cooldown.failed("dns", None, 0));
        }
        for _ in 0..COOLDOWN_FAILURES - 1 {
            assert!(!cooldown.failed("http_5xx", None, 0));
        }
        assert!(cooldown.failed("timeout", None, 1_000));
        assert_eq!(cooldown.until, 1_000 + MINUTE_MS);
        // A rate limit starts the next one at once, twice as long, or as long as the CA asks (up to an hour).
        assert!(cooldown.failed("http_429", None, 2 * MINUTE_MS));
        assert_eq!(cooldown.cooldown_ms, 2 * MINUTE_MS);
        assert_eq!(cooldown.until, 4 * MINUTE_MS);
        assert!(cooldown.failed("http_429", Some(30 * MINUTE_MS), 5 * MINUTE_MS));
        assert_eq!(cooldown.until, 35 * MINUTE_MS);
        for _ in 0..10 {
            cooldown.failed("http_429", None, 0);
        }
        assert_eq!(cooldown.cooldown_ms, HOUR_MS);
        assert!(cooldown.succeeded());
        assert_eq!(cooldown, Cooldown::default());
        assert!(!cooldown.succeeded());

        let mut other = Cooldown::default();
        other.merge("5000 60000");
        other.merge("garbage");
        assert_eq!((other.until, other.cooldown_ms), (5_000, 60_000));
    }
}
