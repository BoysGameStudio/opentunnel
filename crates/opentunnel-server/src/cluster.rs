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
//! The internal listener only binds the private network and every connection carries the shared secret.

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
use crate::crypto::{hash_token, token_matches};
use crate::http::{Body, Stats, count, json_response, response};
use crate::mesh::{Event, Location, MESH_MAGIC, Mesh, MeshConfig, Notice};
use crate::net::{self, AcceptErrors, Timeouts};
use crate::relay::{self, Accepted, Origin};
use crate::service::Service;
use crate::store::{BridgeLocation, Store};

/// The first line of a forwarded connection: `OPENTUNNEL-FORWARD/1 <token> <tunnel> <route> <visitor>\n`.
pub const FORWARD_MAGIC: &[u8] = b"OPENTUNNEL-FORWARD/1 ";
/// The receiving machine's answer, before any data: it has the bridge and the stream follows.
pub const FORWARD_ACCEPTED: u8 = b'1';
/// It has no bridge for the route (any more); the sender may look again.
pub const FORWARD_REFUSED: u8 = b'0';
const MAX_HEADER: usize = 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// The receiver may need to load the tunnel from the database before it answers.
const ACK_TIMEOUT: Duration = Duration::from_secs(10);
const CONTROL_TIMEOUT: Duration = Duration::from_secs(3);
/// TEMPORARY (deploys from the previous version): its registry rows refreshed this recently are live.
const LEGACY_LIVE_MS: u64 = 3 * 60_000;

impl From<&BridgeLocation> for Location {
    fn from(row: &BridgeLocation) -> Self {
        Self {
            machine_id: row.machine_id.clone(),
            region: row.region.clone(),
            address: row.address.clone(),
        }
    }
}

pub struct Cluster {
    pub machine_id: String,
    pub region: String,
    pub mesh: Arc<Mesh>,
    token: String,
    token_hash: String,
    store: Store,
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
        store: Store,
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
            .no_proxy()
            .build()?;
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
            token_hash: hash_token(&token),
            token,
            store,
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

    pub fn authorized(&self, token: &str) -> bool {
        !token.is_empty() && token_matches(token, &self.token_hash)
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
            let location = match self.mesh.locate(tunnel, route, tried.as_deref()) {
                Some(location) => location,
                None => match self.locate_legacy(tunnel, route, tried.as_deref()).await {
                    Some(location) => location,
                    None => {
                        if attempt == 0 {
                            crate::metrics::mesh_lookup("miss");
                        }
                        return Some(accepted);
                    }
                },
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

    /// TEMPORARY (deploys from the previous version, which keeps its bridges in the `bridges` table): while a
    /// machine of that version answers, a route the mesh does not know is looked up there too.
    async fn locate_legacy(
        &self,
        tunnel: &str,
        route: &str,
        except: Option<&str>,
    ) -> Option<Location> {
        if !self.mesh.legacy_present() {
            return None;
        }
        let since = self.clock.now_ms().saturating_sub(LEGACY_LIVE_MS);
        let rows = match self
            .store
            .bridge_locations(tunnel, Some(route), since)
            .await
        {
            Ok(rows) => rows,
            Err(error) => {
                debug!(tunnel, %error, "looking up the previous registry failed");
                return None;
            }
        };
        rows.iter()
            .find(|row| {
                row.machine_id != self.machine_id
                    && Some(row.machine_id.as_str()) != except
                    && !self.mesh.is_up(&row.machine_id)
            })
            .map(Location::from)
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
        let mut header = Vec::with_capacity(128 + accepted.initial.len());
        header.extend_from_slice(FORWARD_MAGIC);
        header.extend_from_slice(
            format!("{} {tunnel} {route} {}\n", self.token, accepted.peer).as_bytes(),
        );
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
            let url = format!(
                "http://{}/internal/tunnel/{tunnel}/routes",
                location.address
            );
            let held = self
                .http
                .get(url)
                .bearer_auth(&self.token)
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
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                errors.failed(error).await;
                continue;
            }
        };
        net::tune(&stream);
        let service = service.clone();
        let cluster = cluster.clone();
        tokio::spawn(async move {
            if let Err(error) = internal_connection(stream, peer, service, cluster).await {
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
) -> Result<()> {
    let mut buffer = Vec::with_capacity(4096);
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
    if buffer.starts_with(MESH_MAGIC) {
        let token = std::str::from_utf8(&buffer[MESH_MAGIC.len()..line_end])?.to_owned();
        let rest = buffer.split_off(line_end + 1);
        let _ = stream.set_nodelay(true);
        return cluster
            .mesh
            .accept(crate::tls::Replay::new(rest, stream), &token)
            .await;
    }
    if !buffer.starts_with(FORWARD_MAGIC) {
        let io = crate::tls::Replay::new(buffer, stream);
        let handler = hyper::service::service_fn(move |request| {
            let service = service.clone();
            let cluster = cluster.clone();
            async move { Ok::<_, std::convert::Infallible>(control(request, service, cluster).await) }
        });
        let _ = hyper::server::conn::http1::Builder::new()
            .timer(hyper_util::rt::TokioTimer::new())
            .header_read_timeout(Duration::from_secs(30))
            .serve_connection(TokioIo::new(io), handler)
            .await;
        return Ok(());
    }
    let line = std::str::from_utf8(&buffer[FORWARD_MAGIC.len()..line_end])?;
    let mut fields = line.split(' ');
    let (Some(token), Some(tunnel), Some(_route), Some(visitor)) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        bail!("malformed forward header");
    };
    if !cluster.authorized(token) {
        bail!("forward with a bad token from {peer}");
    }
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
    service: Service,
    cluster: Arc<Cluster>,
) -> Response<Body> {
    let token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or("");
    if !cluster.authorized(token) {
        return response(StatusCode::UNAUTHORIZED);
    }
    let path = request.uri().path().to_owned();
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
