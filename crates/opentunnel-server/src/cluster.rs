//! Many machines sharing one database (Fly, one or more machines per region). A bridge attaches to whichever
//! machine is nearest its client and a visitor lands on whichever is nearest the visitor, so:
//!
//! - every machine knows which machine holds each bridge from the mesh (`mesh.rs`): links to every other
//!   machine carrying a replicated table of attached bridges and events about tunnels;
//! - a visitor for a route with no bridge here is forwarded over the private network to the machine holding
//!   it: a one-line header, then the ClientHello, then both directions copied as they are;
//! - route conflicts between machines are settled by asking the holder (a small HTTP API on the same internal
//!   listener), and deletes, creations and certificate changes reach every machine as mesh events.
//!
//! The internal listener only binds the private network, and every connection proves knowledge of the shared
//! secret without sending it (`peer_auth.rs`): mesh links by a challenge and response, forwards and control
//! requests by an HMAC over their fields, a timestamp and a nonce, each accepted once and only while fresh.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode, header};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::clock::Clock;
use crate::http::{Body, Stats, count, json_response, response};
use crate::mesh::{Event, Location, MESH_MAGIC, MESH_MAGIC_V1, Mesh, MeshConfig, Notice};
use crate::net::{self, AcceptErrors, Timeouts};
use crate::peer_auth::{self, Nonces, Secret};
use crate::relay::{self, Accepted, Origin};
use crate::service::Service;

/// The first line of a forwarded connection:
/// `OPENTUNNEL-FORWARD/2 <sender> <receiver> <timestamp> <nonce> <tunnel> <route> <visitor> <proof>\n`, the proof
/// an HMAC-SHA256 keyed with the shared secret over every other field.
pub const FORWARD_MAGIC: &[u8] = b"OPENTUNNEL-FORWARD/2 ";
/// TEMPORARY: the previous version's, `OPENTUNNEL-FORWARD/1 <secret> <tunnel> <route> <visitor>\n`.
pub const FORWARD_MAGIC_V1: &[u8] = b"OPENTUNNEL-FORWARD/1 ";
const FORWARD_LABEL: &str = "opentunnel forward/2";
/// Control requests carry `<sender> <receiver> <timestamp> <nonce> <proof>`, the proof over the method and path
/// too.
pub const CONTROL_AUTH: &str = "x-opentunnel-auth";
const CONTROL_LABEL: &str = "opentunnel control/2";
/// Internal connections that have not proven the secret yet, at once; more are closed at accept. Each holds at
/// most a header line, so this bounds what anyone on the private network can make a machine hold.
const UNAUTHENTICATED: usize = 256;
/// The receiving machine's answer, before any data: it has the bridge and the stream follows.
pub const FORWARD_ACCEPTED: u8 = b'1';
/// It has no bridge for the route (any more); the sender may look again.
pub const FORWARD_REFUSED: u8 = b'0';
const MAX_HEADER: usize = 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// The receiver may need to load the tunnel from the database before it answers.
const ACK_TIMEOUT: Duration = Duration::from_secs(10);
const CONTROL_TIMEOUT: Duration = Duration::from_secs(3);
pub struct Cluster {
    pub machine_id: String,
    pub region: String,
    pub mesh: Arc<Mesh>,
    secret: Secret,
    /// TEMPORARY: the secret itself, sent only to machines linked with the previous version's handshake (which
    /// sent it first).
    token: String,
    accept_v1: bool,
    nonces: Nonces,
    clock: Clock,
    http: reqwest::Client,
    pub stats: Arc<Stats>,
    notices: Mutex<Option<mpsc::UnboundedReceiver<Notice>>>,
    /// A check for tunnels deleted while a link was down is queued.
    reconcile_queued: AtomicBool,
}

#[derive(Serialize, Deserialize)]
struct HeldRoutes {
    routes: Vec<String>,
}

impl Cluster {
    pub fn new(
        machine_id: String,
        region: String,
        token: String,
        clock: Clock,
        stats: Arc<Stats>,
        mesh: MeshConfig,
    ) -> Result<Self> {
        anyhow::ensure!(
            !token.is_empty() && !token.contains(char::is_whitespace),
            "INTERNAL_TOKEN must be set (without whitespace) with INTERNAL_LISTEN"
        );
        let http = reqwest::Client::builder()
            .connect_timeout(CONTROL_TIMEOUT)
            .timeout(CONTROL_TIMEOUT)
            .pool_idle_timeout(Duration::from_secs(20))
            .pool_max_idle_per_host(2)
            .no_proxy()
            .build()?;
        let accept_v1 = mesh.accept_v1;
        let (mesh, notices) = Mesh::new(
            machine_id.clone(),
            region.clone(),
            token.clone(),
            clock.clone(),
            mesh,
        );
        Ok(Self {
            machine_id,
            region,
            mesh,
            secret: Secret::new(&token),
            token,
            accept_v1,
            nonces: Nonces::default(),
            clock,
            http,
            stats,
            notices: Mutex::new(Some(notices)),
            reconcile_queued: AtomicBool::new(false),
        })
    }

    pub fn set_address(&self, address: String) {
        self.mesh.set_address(address);
    }

    pub fn address(&self) -> &str {
        self.mesh.address()
    }

    /// TEMPORARY: whether a request of the previous version, which carries the secret itself, is accepted.
    fn authorized_v1(&self, token: &str) -> bool {
        self.accept_v1 && self.secret.matches(token)
    }

    /// Whether a signed request from `sender` comes from where that machine is linked: a request signed by a
    /// machine this one has no link with, or from another address, is refused.
    fn check_sender(&self, sender: &str, connection: SocketAddr) -> Result<()> {
        let Some(address) = self.mesh.peer_address(sender) else {
            bail!("{sender} is not linked");
        };
        let canonical = crate::limits::canonical;
        if address
            .parse::<SocketAddr>()
            .is_ok_and(|address| canonical(address.ip()) == canonical(connection.ip()))
        {
            Ok(())
        } else {
            bail!("{sender} is linked at {address}, not {connection}")
        }
    }

    /// `<sender> <receiver> <timestamp> <nonce>` and its proof over `label`, these and `fields`.
    fn sign(&self, label: &str, receiver: &str, fields: &[&str]) -> String {
        let timestamp = self.clock.now_ms().to_string();
        let nonce = peer_auth::nonce();
        let mut parts = vec![
            label,
            self.machine_id.as_str(),
            receiver,
            timestamp.as_str(),
            nonce.as_str(),
        ];
        parts.extend_from_slice(fields);
        let proof = self.secret.sign(&parts);
        format!("{} {receiver} {timestamp} {nonce} {proof}", self.machine_id)
    }

    /// Checks what [`sign`](Self::sign) made: addressed to this machine, fresh, never seen, and proven.
    fn verify(
        &self,
        label: &str,
        (sender, receiver, timestamp, nonce, proof): (&str, &str, &str, &str, &str),
        fields: &[&str],
    ) -> Result<()> {
        if receiver != self.machine_id {
            bail!("signed for another machine");
        }
        let now = self.clock.now_ms();
        let at: u64 = timestamp.parse().context("a signed timestamp")?;
        if !peer_auth::fresh(at, now) {
            bail!("a stale signature (clock {now}, signed {at})");
        }
        let mut parts = vec![label, sender, receiver, timestamp, nonce];
        parts.extend_from_slice(fields);
        if !self.secret.verify(&parts, proof) {
            bail!("a bad signature");
        }
        // Recorded only once the proof is right, so nobody else can fill the table.
        if !self.nonces.first_use(nonce, at, now) {
            bail!("a replayed signature");
        }
        Ok(())
    }

    /// Whether another machine has a live bridge for the tunnel, for the API's `state`.
    pub fn online_elsewhere(&self, tunnel: &str) -> bool {
        !self.mesh.holders(tunnel, &[]).is_empty()
    }

    // --- Forwarding --------------------------------------------------------------------------------------

    /// Carries a visitor to the machine holding the route. Gives the connection back when no machine has it.
    pub async fn forward(
        &self,
        accepted: Accepted,
        tunnel: &str,
        route: &str,
        timeouts: Timeouts,
    ) -> Option<Accepted> {
        let mut tried: Option<String> = None;
        for attempt in 0..2 {
            let Some(location) = self.mesh.locate(tunnel, route, tried.as_deref()) else {
                if attempt == 0 {
                    crate::metrics::mesh_lookup("miss");
                }
                return Some(accepted);
            };
            if attempt == 0 {
                crate::metrics::mesh_lookup("hit");
            }
            match self.open(&location, &accepted, tunnel, route).await {
                Ok(Some(internal)) => {
                    count(&self.stats.forwarded_out);
                    splice(accepted, internal, timeouts).await;
                    return None;
                }
                Ok(None) => {
                    crate::metrics::forward_failure("refused");
                    debug!(tunnel, route, machine = %location.machine_id, "the machine no longer holds the route");
                }
                Err(error) => {
                    let reason = crate::metrics::forward_error_reason(&error);
                    crate::metrics::forward_failure(reason);
                    warn!(tunnel, machine = %location.machine_id, address = %location.address, error = %format!("{error:#}"), error_class = reason, "forwarding failed");
                }
            }
            count(&self.stats.forward_failures);
            tried = Some(location.machine_id);
        }
        Some(accepted)
    }

    /// Connects, sends the header and the ClientHello, and waits for the answer. `None`: refused.
    async fn open(
        &self,
        location: &Location,
        accepted: &Accepted,
        tunnel: &str,
        route: &str,
    ) -> Result<Option<TcpStream>> {
        let mut stream =
            tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&location.address))
                .await
                .context("connecting timed out")??;
        let _ = stream.set_nodelay(true);
        net::keepalive(&stream);
        let mut header = Vec::with_capacity(256 + accepted.initial.len());
        let visitor = accepted.peer.to_string();
        if self.mesh.linked_v1(&location.machine_id) {
            // TEMPORARY: a machine of the previous version, which proved it holds the secret by sending it.
            header.extend_from_slice(FORWARD_MAGIC_V1);
            header.extend_from_slice(
                format!("{} {tunnel} {route} {visitor}\n", self.token).as_bytes(),
            );
        } else {
            let signed = self.sign(
                FORWARD_LABEL,
                &location.machine_id,
                &[tunnel, route, &visitor],
            );
            // The proof goes last, after the fields it covers.
            let (identity, proof) = signed.rsplit_once(' ').expect("signed fields");
            header.extend_from_slice(FORWARD_MAGIC);
            header.extend_from_slice(
                format!("{identity} {tunnel} {route} {visitor} {proof}\n").as_bytes(),
            );
        }
        header.extend_from_slice(&accepted.initial);
        tokio::time::timeout(ACK_TIMEOUT, stream.write_all(&header))
            .await
            .context("sending the header timed out")??;
        let mut answer = [0u8; 1];
        let read = tokio::time::timeout(ACK_TIMEOUT, stream.read(&mut answer))
            .await
            .context("no answer")??;
        Ok((read == 1 && answer[0] == FORWARD_ACCEPTED).then_some(stream))
    }

    // --- Control -----------------------------------------------------------------------------------------

    /// Whether another machine's live bridge holds any of `routes`. Only machines the mesh table says claim one
    /// are asked, and only their answer counts: a bridge there may have gone silent (it is retired when asked),
    /// or be closing. A machine that cannot be asked does not count.
    pub async fn held_elsewhere(&self, tunnel: &str, routes: &[String]) -> bool {
        for location in self.mesh.holders(tunnel, routes) {
            let path = format!("/internal/tunnel/{tunnel}/routes");
            let url = format!("http://{}{path}", location.address);
            let request = self.http.get(url);
            let request = if self.mesh.linked_v1(&location.machine_id) {
                // TEMPORARY: a machine of the previous version, which proved it holds the secret by sending it.
                request.bearer_auth(&self.token)
            } else {
                request.header(
                    CONTROL_AUTH,
                    self.sign(CONTROL_LABEL, &location.machine_id, &["GET", &path]),
                )
            };
            let held = request
                .send()
                .await
                .and_then(reqwest::Response::error_for_status);
            let held = match held {
                Ok(response) => response.json::<HeldRoutes>().await,
                Err(error) => Err(error),
            };
            match held {
                Ok(held) if held.routes.iter().any(|route| routes.contains(route)) => return true,
                Ok(_) => {}
                Err(error) => {
                    warn!(tunnel, machine = %location.machine_id, %error, "could not ask a machine about its routes");
                }
            }
        }
        false
    }

    /// The mesh's view of every machine, for `/api/admin/stats`.
    pub fn view(&self) -> serde_json::Value {
        self.mesh.view()
    }

    // --- Lifecycle ---------------------------------------------------------------------------------------

    /// Starts finding and linking peers, and handling what they announce.
    pub fn start(self: &Arc<Self>, service: &Service) -> Vec<tokio::task::JoinHandle<()>> {
        info!(machine = %self.machine_id, region = %self.region, address = %self.address(), epoch = self.mesh.epoch, "joining the mesh");
        let mut tasks = vec![tokio::spawn(self.mesh.clone().run())];
        if let Some(notices) = self.notices.lock().expect("notices lock").take() {
            tasks.push(tokio::spawn(run_notices(
                service.clone(),
                self.clone(),
                notices,
            )));
        }
        tasks
    }

    /// On shutdown: tells every peer, so they stop forwarding visitors here before the bridges move.
    pub async fn shutdown(&self) {
        self.mesh.leave();
    }
}

/// Acts on what other machines announce.
async fn run_notices(
    service: Service,
    cluster: Arc<Cluster>,
    mut notices: mpsc::UnboundedReceiver<Notice>,
) {
    while let Some(notice) = notices.recv().await {
        match notice {
            Notice::Event(
                Event::TunnelCreated { tunnel } | Event::CertificateChanged { tunnel },
            ) => {
                // The entry may be locked by a slow database read; nothing here waits for it.
                let service = service.clone();
                tokio::spawn(async move { service.expire(&tunnel).await });
            }
            Notice::Event(Event::TunnelDeleted { tunnel }) => {
                let service = service.clone();
                tokio::spawn(async move {
                    // Only what the database says: a peer's word alone closes no tenant's bridges.
                    match service
                        .store
                        .deleted_tunnels(std::slice::from_ref(&tunnel))
                        .await
                    {
                        Ok(deleted) if deleted.contains(&tunnel) => {}
                        Ok(_) => {
                            warn!(
                                tunnel,
                                "ignored a deletion another machine announced: the tunnel is not deleted"
                            );
                            return;
                        }
                        Err(error) => {
                            warn!(tunnel, error = %format!("{error:#}"), "could not check a deletion another machine announced");
                            return;
                        }
                    }
                    if service.close_deleted(&tunnel).await {
                        info!(
                            tunnel,
                            "closed the bridges of a tunnel deleted on another machine"
                        );
                    }
                });
            }
            Notice::Event(Event::JobEnqueued) => service.jobs.notify_one(),
            Notice::Event(Event::Leaving | Event::Unknown) => {}
            Notice::LinkUp => {
                // Events from that machine may have been missed while the link was down: cached answers are
                // read again before they are trusted, and tunnels with bridges here are checked for deletion.
                service.forget_cached_answers();
                if !cluster.reconcile_queued.swap(true, Ordering::SeqCst) {
                    let service = service.clone();
                    let cluster = cluster.clone();
                    tokio::spawn(async move {
                        // Links come up in bursts (startup, a healed partition): one check for all of them.
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        cluster.reconcile_queued.store(false, Ordering::SeqCst);
                        if let Err(error) = service.close_deleted_tunnels().await {
                            warn!(error = %format!("{error:#}"), "checking for deleted tunnels failed");
                        }
                    });
                }
            }
        }
    }
}

/// Copies both directions between a visitor and the machine it was forwarded to, until both end, either side
/// fails, or the connection stays quiet for too long.
async fn splice(accepted: Accepted, mut internal: TcpStream, timeouts: Timeouts) {
    let mut visitor = accepted.stream;
    let copied = net::splice(&mut visitor, &mut internal, timeouts).await;
    if let Err(error) = copied {
        debug!(%error, "forwarded connection ended");
        // The other machine reset the connection (the bridge reset it, or went away), the visitor did, or it
        // went quiet: reset both.
        let _ = visitor.set_zero_linger();
        let _ = internal.set_zero_linger();
    }
}

// --- The internal listener ---------------------------------------------------------------------------------

/// Accepts mesh links, forwarded visitors and control requests from other machines.
pub async fn serve_internal(listener: TcpListener, service: Service, cluster: Arc<Cluster>) {
    let mut errors = AcceptErrors::new("internal accept failed");
    let unauthenticated = Arc::new(tokio::sync::Semaphore::new(UNAUTHENTICATED));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                errors.failed(error).await;
                continue;
            }
        };
        net::tune(&stream);
        let Ok(permit) = unauthenticated.clone().try_acquire_owned() else {
            debug!(%peer, "internal connection refused: too many unauthenticated");
            continue;
        };
        let service = service.clone();
        let cluster = cluster.clone();
        tokio::spawn(async move {
            if let Err(error) = internal_connection(stream, peer, service, cluster, permit).await {
                debug!(%error, %peer, "internal connection ended");
            }
        });
    }
}

async fn internal_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    service: Service,
    cluster: Arc<Cluster>,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<()> {
    let mut buffer = Vec::with_capacity(1024);
    let line_end = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(end) = buffer.iter().position(|byte| *byte == b'\n') {
                return Ok(end);
            }
            if buffer.len() >= MAX_HEADER || stream.read_buf(&mut buffer).await? == 0 {
                bail!("no header");
            }
        }
    })
    .await
    .context("header timeout")??;
    if buffer.starts_with(MESH_MAGIC) || buffer.starts_with(MESH_MAGIC_V1) {
        let v1 = buffer.starts_with(MESH_MAGIC_V1);
        let greeting = std::str::from_utf8(&buffer[MESH_MAGIC.len()..line_end])?.to_owned();
        let rest = buffer.split_off(line_end + 1);
        let _ = stream.set_nodelay(true);
        let stream = crate::tls::Replay::new(rest, stream);
        return if v1 {
            cluster
                .mesh
                .accept_v1(stream, &greeting, peer, permit)
                .await
        } else {
            cluster.mesh.accept(stream, &greeting, peer, permit).await
        };
    }
    let v1 = buffer.starts_with(FORWARD_MAGIC_V1);
    if !v1 && !buffer.starts_with(FORWARD_MAGIC) {
        let io = crate::tls::Replay::new(buffer, stream);
        let handler = hyper::service::service_fn(move |request| {
            let service = service.clone();
            let cluster = cluster.clone();
            async move {
                Ok::<_, std::convert::Infallible>(control(request, peer, service, cluster).await)
            }
        });
        // Route checks are short; the connection keeps its slot while it lasts.
        let _ = tokio::time::timeout(
            Duration::from_secs(60),
            hyper::server::conn::http1::Builder::new()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(Duration::from_secs(10))
                .serve_connection(TokioIo::new(io), handler),
        )
        .await;
        drop(permit);
        return Ok(());
    }
    let line = std::str::from_utf8(&buffer[FORWARD_MAGIC.len()..line_end])?;
    let fields: Vec<&str> = line.split(' ').collect();
    let (tunnel, visitor) = match fields.as_slice() {
        [
            sender,
            receiver,
            timestamp,
            nonce,
            tunnel,
            route,
            visitor,
            proof,
        ] if !v1 => {
            cluster
                .verify(
                    FORWARD_LABEL,
                    (sender, receiver, timestamp, nonce, proof),
                    &[tunnel, route, visitor],
                )
                .with_context(|| format!("a forward from {peer}"))?;
            cluster.check_sender(sender, peer)?;
            (*tunnel, *visitor)
        }
        [token, tunnel, _route, visitor] if v1 => {
            if !cluster.authorized_v1(token) {
                bail!("forward with a bad token from {peer}");
            }
            (*tunnel, *visitor)
        }
        _ => bail!("malformed forward header"),
    };
    drop(permit);
    let tunnel = tunnel.to_owned();
    let visitor: SocketAddr = visitor.parse().context("forwarded visitor address")?;
    let rest = buffer.split_off(line_end + 1);
    let accepted = relay::accept_with(stream, visitor, false, rest).await?;
    if relay::tunnel_id(&accepted.sni, &service.domain).as_deref() != Some(tunnel.as_str()) {
        bail!("forwarded ClientHello is for another tunnel");
    }
    count(&cluster.stats.forwarded_in);
    let _open = crate::metrics::visitor_open();
    relay::route_tunnel(&service, accepted, Origin::Forwarded).await
}

async fn control(
    request: Request<Incoming>,
    peer: SocketAddr,
    service: Service,
    cluster: Arc<Cluster>,
) -> Response<Body> {
    let path = request.uri().path().to_owned();
    let headers = request.headers();
    let signed = headers
        .get(CONTROL_AUTH)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(' ').collect::<Vec<_>>());
    let authorized = match signed.as_deref() {
        Some([sender, receiver, timestamp, nonce, proof]) => {
            let method = request.method().as_str();
            match cluster
                .verify(
                    CONTROL_LABEL,
                    (sender, receiver, timestamp, nonce, proof),
                    &[method, &path],
                )
                .and_then(|()| cluster.check_sender(sender, peer))
            {
                Ok(()) => true,
                Err(error) => {
                    debug!(error = %format!("{error:#}"), "a control request failed authentication");
                    false
                }
            }
        }
        Some(_) => false,
        // TEMPORARY: the previous version's bearer secret.
        None => headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .is_some_and(|token| cluster.authorized_v1(token)),
    };
    if !authorized {
        return response(StatusCode::UNAUTHORIZED);
    }
    let Some(rest) = path.strip_prefix("/internal/tunnel/") else {
        return response(StatusCode::NOT_FOUND);
    };
    let Some((tunnel, action)) = rest.split_once('/') else {
        return response(StatusCode::NOT_FOUND);
    };
    match (request.method(), action) {
        (&Method::GET, "routes") => match service.held_routes(tunnel).await {
            Ok(routes) => json_response(StatusCode::OK, &HeldRoutes { routes }),
            Err(error) => json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({ "error": format!("{error:#}") }),
            ),
        },
        _ => response(StatusCode::NOT_FOUND),
    }
}
