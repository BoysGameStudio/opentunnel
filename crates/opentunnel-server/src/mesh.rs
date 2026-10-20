//! The cluster mesh: every machine keeps one TCP link to every other machine over the private network, and
//! through it a replicated table of which machine holds which bridge, plus events about tunnels.
//!
//! - **Membership.** Peers are the addresses of a DNS name (`<FLY_APP_NAME>.internal` on Fly, resolved again
//!   every few seconds) and any static addresses. Both sides of a pair dial (the higher address after a short
//!   delay); when two links to one machine come up, both sides keep the same one: the newer life of the machine
//!   (`started_at`, `epoch`), then the link dialed by the lower address.
//! - **Links.** On the internal listener, a challenge and response that never sends the shared secret: the dialer
//!   sends `OPENTUNNEL-MESH/2 <machine> <nonce>\n`, the acceptor answers `OPENTUNNEL-MESH/2 <machine> <nonce>
//!   <proof>\n` and the dialer `<proof>\n`, each proof an HMAC-SHA256 keyed with the secret over both nonces,
//!   both machine IDs and the role (`peer_auth.rs`, checked in constant time). Then frames: a big-endian `u32`
//!   length and a JSON [`Frame`]; a `hello` from another machine than the one that proved itself ends the link.
//!   Each side sends `hello`, then a
//!   `snapshot` of its own bridges, then `attached`/`detached` deltas numbered by a per-machine sequence, `event`s,
//!   and a `ping` every second when idle. A peer that sends nothing for `dead` (5 s) is down; a closed or failed
//!   link is down at once. Either way its bridges leave the table, and it is dialed again with backoff.
//! - **Table.** A machine is the only writer of its own entries, so the table needs no consensus: lookups are
//!   local reads of what peers announced. A restarted machine has a new epoch and its snapshot replaces whatever
//!   was known of its previous life.
//! - **Events.** Tunnel created, certificate changed, tunnel deleted (which closes its bridges), leaving (a
//!   draining machine: its bridges are dropped so visitors are no longer sent there) and job enqueued, handed to
//!   the service as [`Notice`]s. Events sent while a link is down are lost, so every link that comes up is a
//!   [`Notice::LinkUp`], on which the service treats its cached answers as stale and looks for deleted tunnels.
//!
//! A machine of a version before the mesh answers the mesh greeting with an HTTP error; it is counted as `legacy`.
//! TEMPORARY: a machine of the version before this handshake dials with `OPENTUNNEL-MESH/1 <secret>\n`; with
//! `MESH_ACCEPT_V1` that greeting is accepted when the secret is right, and answered with the same line it sent
//! (which tells it nothing it did not know). Such links are marked, so forwards and control requests to that
//! machine use the format it understands; nothing ever sends the secret to a machine that did not send it first.

use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use bytes::{BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter,
};
use tokio::net::TcpStream;
use tokio::sync::{Notify, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::clock::Clock;
use crate::peer_auth::{Secret, nonce};

/// The first line of a mesh link from the dialer, `OPENTUNNEL-MESH/2 <machine> <nonce>\n`, and the acceptor's
/// answer, `OPENTUNNEL-MESH/2 <machine> <nonce> <proof>\n`.
pub const MESH_MAGIC: &[u8] = b"OPENTUNNEL-MESH/2 ";
/// TEMPORARY: the previous version's greeting, `OPENTUNNEL-MESH/1 <secret>\n`, from both sides.
pub const MESH_MAGIC_V1: &[u8] = b"OPENTUNNEL-MESH/1 ";
const ACCEPT_LABEL: &str = "opentunnel mesh/2 accept";
const DIAL_LABEL: &str = "opentunnel mesh/2 dial";
/// The frame format's version, in `hello`. Unknown frame types and fields are ignored, so additions need no bump.
pub const VERSION: u32 = 1;
const MAX_FRAME: usize = 256 << 20;
/// Frames queued for a link; a peer that falls this far behind is disconnected and gets a fresh snapshot.
const LINK_QUEUE: usize = 200_000;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// Once a frame's length arrived, how long its body may take (a big snapshot over a slow path).
const FRAME_BODY_TIMEOUT: Duration = Duration::from_secs(60);
const FIRST_BACKOFF: Duration = Duration::from_millis(200);
const MAX_BACKOFF: Duration = Duration::from_secs(5);
/// How long the higher address of a pair waits before dialing too, so usually only one link is made.
const HIGHER_DIAL_DELAY: Duration = Duration::from_secs(2);
/// A machine of the previous version is greeted again this often, and counted as present this long after.
const LEGACY_RETRY: Duration = Duration::from_secs(15);
const LEGACY_TTL: Duration = Duration::from_secs(60);
/// An address that left the DNS answer is dialed for this long more.
const FORGET_AFTER: Duration = Duration::from_secs(30);
/// Writes are gathered up to this size before a flush.
const WRITE_BATCH: usize = 1 << 20;

#[derive(Debug, Clone)]
pub struct MeshConfig {
    /// A name whose addresses are the peers, at this machine's internal port.
    pub dns: Option<String>,
    /// Static peer addresses, `host:port`.
    pub peers: Vec<String>,
    pub discovery: Duration,
    pub ping: Duration,
    pub dead: Duration,
    /// TEMPORARY: accept links from machines that send the secret itself (`OPENTUNNEL-MESH/1`).
    pub accept_v1: bool,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            dns: None,
            peers: Vec::new(),
            discovery: Duration::from_secs(5),
            ping: Duration::from_secs(1),
            dead: Duration::from_secs(5),
            accept_v1: true,
        }
    }
}

/// One attached bridge and the routes it claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub tunnel: String,
    /// Unique per machine life.
    pub bridge: u64,
    pub routes: Vec<String>,
    /// The holder's clock, Unix ms: of two machines claiming a route, the newer attach wins.
    pub attached_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    TunnelCreated {
        tunnel: String,
    },
    /// Bound, ready, or renewed.
    CertificateChanged {
        tunnel: String,
    },
    /// Its bridges close everywhere.
    TunnelDeleted {
        tunnel: String,
    },
    /// The sender is shutting down: send it no more visitors.
    Leaving,
    JobEnqueued,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    pub version: u32,
    pub machine_id: String,
    pub region: String,
    /// The internal listener, where forwarded visitors go.
    pub address: String,
    /// Random per process life.
    pub epoch: u64,
    pub started_at: u64,
    pub draining: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Frame {
    Hello(Hello),
    Snapshot {
        epoch: u64,
        seq: u64,
        sent_at: u64,
        entries: Vec<Entry>,
    },
    Attached {
        seq: u64,
        sent_at: u64,
        entry: Entry,
    },
    Detached {
        seq: u64,
        sent_at: u64,
        tunnel: String,
        bridge: u64,
    },
    Event {
        sent_at: u64,
        event: Event,
    },
    Ping {
        sent_at: u64,
    },
    #[serde(other)]
    Unknown,
}

/// What the service hears from the mesh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notice {
    Event(Event),
    /// A link came up: events may have been missed while it was down.
    LinkUp,
}

/// A machine holding a route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    pub machine_id: String,
    pub region: String,
    pub address: String,
}

/// Why a dial ended without a link.
#[derive(Debug)]
enum DialError {
    /// The machine answered without speaking the mesh: the previous version.
    Legacy,
    Other(anyhow::Error),
}

impl From<anyhow::Error> for DialError {
    fn from(error: anyhow::Error) -> Self {
        Self::Other(error)
    }
}

impl From<std::io::Error> for DialError {
    fn from(error: std::io::Error) -> Self {
        Self::Other(error.into())
    }
}

struct Subscriber {
    tx: mpsc::Sender<Bytes>,
    cancel: CancellationToken,
}

/// This machine's own entries, and the links they are announced on.
#[derive(Default)]
struct Local {
    seq: u64,
    entries: HashMap<u64, Entry>,
    links: HashMap<u64, Subscriber>,
}

struct Peer {
    hello: Hello,
    link: u64,
    /// The address of the side that dialed this link.
    dialer: String,
    cancel: CancellationToken,
    connected_at: u64,
    seq: u64,
    entries: HashMap<u64, Entry>,
    /// TEMPORARY: linked with `OPENTUNNEL-MESH/1`, so it takes forwards and control requests in that format.
    v1: bool,
}

#[derive(Default)]
struct Remote {
    peers: HashMap<String, Peer>,
    /// Tunnel to `(machine, bridge)`.
    index: HashMap<String, HashSet<(String, u64)>>,
}

impl Remote {
    fn index_add(
        index: &mut HashMap<String, HashSet<(String, u64)>>,
        machine: &str,
        entry: &Entry,
    ) {
        index
            .entry(entry.tunnel.clone())
            .or_default()
            .insert((machine.to_owned(), entry.bridge));
    }

    fn index_remove(
        index: &mut HashMap<String, HashSet<(String, u64)>>,
        machine: &str,
        entry: &Entry,
    ) {
        if let Some(holders) = index.get_mut(&entry.tunnel) {
            holders.remove(&(machine.to_owned(), entry.bridge));
            if holders.is_empty() {
                index.remove(&entry.tunnel);
            }
        }
    }

    /// Empties a peer's entries.
    fn clear(&mut self, machine: &str) {
        let Remote { peers, index } = self;
        if let Some(peer) = peers.get_mut(machine) {
            for entry in peer.entries.values() {
                Self::index_remove(index, machine, entry);
            }
            peer.entries.clear();
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressState {
    Connecting,
    Up,
    Unreachable,
    Legacy,
}

impl AddressState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Connecting => "connecting",
            Self::Up => "up",
            Self::Unreachable => "unreachable",
            Self::Legacy => "legacy",
        }
    }
}

struct Address {
    state: AddressState,
    /// In the last DNS answer, or static.
    current: bool,
    is_static: bool,
    seen: Instant,
    legacy_at: Option<Instant>,
}

pub struct Mesh {
    pub machine_id: String,
    pub region: String,
    pub epoch: u64,
    pub started_at: u64,
    address: OnceLock<String>,
    secret: Secret,
    clock: Clock,
    config: MeshConfig,
    statics: Mutex<Vec<String>>,
    local: Mutex<Local>,
    remote: Mutex<Remote>,
    addresses: Mutex<HashMap<SocketAddr, Address>>,
    notices: mpsc::UnboundedSender<Notice>,
    next_link: AtomicU64,
    draining: AtomicBool,
    discover_now: Notify,
    /// Stops every link and dialer (shutdown, or a simulated crash in tests).
    halted: CancellationToken,
    /// With `halted`: keep the sockets open and silent instead of closing them, like a machine that froze.
    silent: AtomicBool,
    held: Mutex<Vec<Box<dyn Any + Send>>>,
    /// Test hook: machines this one refuses to link with.
    partitioned: Mutex<HashSet<String>>,
}

fn encode(frame: &Frame) -> Bytes {
    let json = serde_json::to_vec(frame).expect("frames serialize");
    let mut buffer = BytesMut::with_capacity(4 + json.len());
    buffer.put_u32(json.len() as u32);
    buffer.put_slice(&json);
    buffer.freeze()
}

async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    buffer: &mut Vec<u8>,
    wait: Duration,
) -> Result<Frame> {
    let length = tokio::time::timeout(wait, reader.read_u32())
        .await
        .map_err(|_| anyhow!("no frame for {wait:?}"))?
        .context("reading a frame")? as usize;
    if length > MAX_FRAME {
        bail!("a frame of {length} bytes");
    }
    buffer.resize(length, 0);
    tokio::time::timeout(FRAME_BODY_TIMEOUT, reader.read_exact(buffer))
        .await
        .map_err(|_| anyhow!("a frame body took over {FRAME_BODY_TIMEOUT:?}"))?
        .context("reading a frame")?;
    serde_json::from_slice(buffer).context("decoding a frame")
}

/// A machine ID as it may appear in a handshake line.
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 191
        && id
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b' ')
}

fn valid_nonce(nonce: &str) -> bool {
    (16..=128).contains(&nonce.len()) && nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// One handshake line without its newline, within the handshake timeout.
async fn read_line<R: AsyncRead + Unpin>(reader: &mut BufReader<R>) -> Result<String> {
    let mut line = Vec::new();
    tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        (&mut *reader).take(1024).read_until(b'\n', &mut line),
    )
    .await
    .map_err(|_| anyhow!("no greeting"))??;
    let line = line
        .strip_suffix(b"\n")
        .ok_or_else(|| anyhow!("no greeting"))?;
    Ok(std::str::from_utf8(line)
        .context("a greeting that is not text")?
        .to_owned())
}

fn random_u64() -> u64 {
    let mut bytes = [0u8; 8];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes)
        .expect("system randomness");
    u64::from_be_bytes(bytes)
}

impl Mesh {
    pub fn new(
        machine_id: String,
        region: String,
        token: String,
        clock: Clock,
        config: MeshConfig,
    ) -> (Arc<Self>, mpsc::UnboundedReceiver<Notice>) {
        let (notices, receiver) = mpsc::unbounded_channel();
        let statics = config.peers.clone();
        let mesh = Arc::new(Self {
            machine_id,
            region,
            epoch: random_u64(),
            started_at: clock.now_ms(),
            address: OnceLock::new(),
            secret: Secret::new(&token),
            clock,
            config,
            statics: Mutex::new(statics),
            local: Mutex::new(Local::default()),
            remote: Mutex::new(Remote::default()),
            addresses: Mutex::new(HashMap::new()),
            notices,
            next_link: AtomicU64::new(1),
            draining: AtomicBool::new(false),
            discover_now: Notify::new(),
            halted: CancellationToken::new(),
            silent: AtomicBool::new(false),
            held: Mutex::new(Vec::new()),
            partitioned: Mutex::new(HashSet::new()),
        });
        (mesh, receiver)
    }

    pub fn set_address(&self, address: String) {
        let _ = self.address.set(address);
    }

    pub fn address(&self) -> &str {
        self.address.get().map_or("", String::as_str)
    }

    fn own_address(&self) -> Option<SocketAddr> {
        self.address().parse().ok()
    }

    fn now(&self) -> u64 {
        self.clock.now_ms()
    }

    fn hello(&self) -> Hello {
        Hello {
            version: VERSION,
            machine_id: self.machine_id.clone(),
            region: self.region.clone(),
            address: self.address().to_owned(),
            epoch: self.epoch,
            started_at: self.started_at,
            draining: self.draining.load(Ordering::SeqCst),
        }
    }

    // --- This machine's entries ----------------------------------------------------------------------------

    /// Sends a frame to every link; a link whose queue is full is closed (it reconnects with a fresh snapshot).
    fn broadcast(local: &mut Local, frame: &Bytes) {
        local.links.retain(|_, subscriber| {
            if subscriber.tx.try_send(frame.clone()).is_ok() {
                return true;
            }
            subscriber.cancel.cancel();
            false
        });
    }

    /// Announces a bridge that attached here.
    pub fn attached(&self, tunnel: &str, bridge: u64, routes: &[String], attached_at: u64) {
        let entry = Entry {
            tunnel: tunnel.to_owned(),
            bridge,
            routes: routes.to_vec(),
            attached_at,
        };
        let mut local = self.local.lock().expect("mesh local lock");
        local.seq += 1;
        let frame = encode(&Frame::Attached {
            seq: local.seq,
            sent_at: self.now(),
            entry: entry.clone(),
        });
        local.entries.insert(bridge, entry);
        Self::broadcast(&mut local, &frame);
        let count = local.entries.len();
        drop(local);
        crate::metrics::set_mesh_table(&self.machine_id, Some(count));
    }

    /// Announces that a bridge that attached here is gone. Nothing happens for one never announced.
    pub fn detached(&self, tunnel: &str, bridge: u64) {
        let mut local = self.local.lock().expect("mesh local lock");
        if local.entries.remove(&bridge).is_none() {
            return;
        }
        local.seq += 1;
        let frame = encode(&Frame::Detached {
            seq: local.seq,
            sent_at: self.now(),
            tunnel: tunnel.to_owned(),
            bridge,
        });
        Self::broadcast(&mut local, &frame);
        let count = local.entries.len();
        drop(local);
        crate::metrics::set_mesh_table(&self.machine_id, Some(count));
    }

    /// Sends an event to every peer linked now.
    pub fn publish(&self, event: Event) {
        let frame = encode(&Frame::Event {
            sent_at: self.now(),
            event,
        });
        Self::broadcast(&mut self.local.lock().expect("mesh local lock"), &frame);
    }

    /// Tells every peer this machine is shutting down, so they stop sending it visitors.
    pub fn leave(&self) {
        self.draining.store(true, Ordering::SeqCst);
        self.publish(Event::Leaving);
    }

    /// A new link's queue, starting with a snapshot of this machine's entries. Everything announced afterwards
    /// follows it in order.
    fn subscribe(&self, cancel: CancellationToken) -> (u64, mpsc::Receiver<Bytes>) {
        let link = self.next_link.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(LINK_QUEUE);
        let mut local = self.local.lock().expect("mesh local lock");
        let snapshot = encode(&Frame::Snapshot {
            epoch: self.epoch,
            seq: local.seq,
            sent_at: self.now(),
            entries: local.entries.values().cloned().collect(),
        });
        let _ = tx.try_send(snapshot);
        local.links.insert(link, Subscriber { tx, cancel });
        (link, rx)
    }

    fn unsubscribe(&self, link: u64) {
        self.local
            .lock()
            .expect("mesh local lock")
            .links
            .remove(&link);
    }

    // --- Lookups -------------------------------------------------------------------------------------------

    /// The live machine holding a tunnel's route (the newest attach when several claim it), other than `except`.
    pub fn locate(&self, tunnel: &str, route: &str, except: Option<&str>) -> Option<Location> {
        let remote = self.remote.lock().expect("mesh remote lock");
        remote
            .index
            .get(tunnel)?
            .iter()
            .filter(|(machine, _)| Some(machine.as_str()) != except)
            .filter_map(|(machine, bridge)| {
                let peer = remote.peers.get(machine)?;
                let entry = peer.entries.get(bridge)?;
                (!peer.hello.draining && entry.routes.iter().any(|claimed| claimed == route))
                    .then_some((entry.attached_at, peer))
            })
            .max_by_key(|(attached_at, _)| *attached_at)
            .map(|(_, peer)| Location {
                machine_id: peer.hello.machine_id.clone(),
                region: peer.hello.region.clone(),
                address: peer.hello.address.clone(),
            })
    }

    /// The live machines holding any of a tunnel's `routes` (any route when empty).
    pub fn holders(&self, tunnel: &str, routes: &[String]) -> Vec<Location> {
        let remote = self.remote.lock().expect("mesh remote lock");
        let mut found: Vec<Location> = Vec::new();
        for (machine, bridge) in remote.index.get(tunnel).into_iter().flatten() {
            let Some(peer) = remote.peers.get(machine) else {
                continue;
            };
            let Some(entry) = peer.entries.get(bridge) else {
                continue;
            };
            let claims =
                routes.is_empty() || entry.routes.iter().any(|route| routes.contains(route));
            if peer.hello.draining
                || !claims
                || found.iter().any(|known| &known.machine_id == machine)
            {
                continue;
            }
            found.push(Location {
                machine_id: peer.hello.machine_id.clone(),
                region: peer.hello.region.clone(),
                address: peer.hello.address.clone(),
            });
        }
        found
    }

    /// TEMPORARY: whether the machine is linked with the previous version's handshake, so it proved it holds the
    /// secret by sending it, and takes forwards and control requests only in that version's format.
    pub fn linked_v1(&self, machine_id: &str) -> bool {
        self.remote
            .lock()
            .expect("mesh remote lock")
            .peers
            .get(machine_id)
            .is_some_and(|peer| peer.v1)
    }

    /// Whether a machine of this ID is linked now.
    pub fn is_up(&self, machine_id: &str) -> bool {
        self.remote
            .lock()
            .expect("mesh remote lock")
            .peers
            .contains_key(machine_id)
    }

    fn linked(&self, address: SocketAddr) -> bool {
        self.remote
            .lock()
            .expect("mesh remote lock")
            .peers
            .values()
            .any(|peer| peer.hello.address.parse::<SocketAddr>().ok() == Some(address))
    }

    /// Whether every machine known by address is linked. While not (a peer starting, unreachable, or of the
    /// previous version), events may be missed, so cached answers are trusted only briefly.
    pub fn complete(&self) -> bool {
        let current: Vec<SocketAddr> = self
            .addresses
            .lock()
            .expect("mesh addresses lock")
            .iter()
            .filter(|(_, address)| address.current)
            .map(|(address, _)| *address)
            .collect();
        current.into_iter().all(|address| self.linked(address))
    }

    /// Whether a machine of the previous version answered recently. TEMPORARY: for deploys from it.
    pub fn legacy_present(&self) -> bool {
        self.addresses
            .lock()
            .expect("mesh addresses lock")
            .values()
            .any(|address| {
                address.current
                    && address
                        .legacy_at
                        .is_some_and(|at| at.elapsed() < LEGACY_TTL)
            })
    }

    /// The machine IDs linked now.
    pub fn peers(&self) -> Vec<String> {
        self.remote
            .lock()
            .expect("mesh remote lock")
            .peers
            .keys()
            .cloned()
            .collect()
    }

    /// Bridges in the table per machine (this one first), for tests and stats.
    pub fn table_sizes(&self) -> Vec<(String, usize)> {
        let mut sizes = vec![(
            self.machine_id.clone(),
            self.local.lock().expect("mesh local lock").entries.len(),
        )];
        let remote = self.remote.lock().expect("mesh remote lock");
        sizes.extend(
            remote
                .peers
                .values()
                .map(|peer| (peer.hello.machine_id.clone(), peer.entries.len())),
        );
        sizes
    }

    /// Every machine and link, for `/api/admin/stats`.
    pub fn view(&self) -> serde_json::Value {
        fn summary(entries: &HashMap<u64, Entry>) -> (usize, usize, usize) {
            let tunnels: HashSet<&str> = entries
                .values()
                .map(|entry| entry.tunnel.as_str())
                .collect();
            let routes = entries.values().map(|entry| entry.routes.len()).sum();
            (entries.len(), tunnels.len(), routes)
        }
        let mut machines = Vec::new();
        {
            let local = self.local.lock().expect("mesh local lock");
            let (bridges, tunnels, routes) = summary(&local.entries);
            machines.push(serde_json::json!({
                "machine_id": self.machine_id,
                "region": self.region,
                "address": self.address(),
                "bridges": bridges,
                "tunnels": tunnels,
                "routes": routes,
                "link": "self",
                "draining": self.draining.load(Ordering::SeqCst),
                "epoch": self.epoch.to_string(),
                "started_at": self.started_at,
                "seq": local.seq,
            }));
        }
        {
            let remote = self.remote.lock().expect("mesh remote lock");
            for peer in remote.peers.values() {
                let (bridges, tunnels, routes) = summary(&peer.entries);
                machines.push(serde_json::json!({
                    "machine_id": peer.hello.machine_id,
                    "region": peer.hello.region,
                    "address": peer.hello.address,
                    "bridges": bridges,
                    "tunnels": tunnels,
                    "routes": routes,
                    "link": "up",
                    "draining": peer.hello.draining,
                    "epoch": peer.hello.epoch.to_string(),
                    "started_at": peer.hello.started_at,
                    "seq": peer.seq,
                    "connected_at": peer.connected_at,
                }));
            }
        }
        machines.sort_by(|a, b| {
            (a["region"].as_str(), a["machine_id"].as_str())
                .cmp(&(b["region"].as_str(), b["machine_id"].as_str()))
        });
        let mut regions = serde_json::Map::new();
        let mut total = 0;
        for machine in &machines {
            let bridges = machine["bridges"].as_u64().unwrap_or(0);
            total += bridges;
            let region = machine["region"].as_str().unwrap_or("").to_owned();
            let sum = regions
                .get(&region)
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            regions.insert(region, (sum + bridges).into());
        }
        let complete = self.complete();
        let mut states = serde_json::Map::new();
        let mut list: Vec<_> = self
            .address_states()
            .into_iter()
            .map(|(address, state)| {
                let name = state.as_str();
                let count = states
                    .get(name)
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);
                states.insert(name.to_owned(), (count + 1).into());
                serde_json::json!({ "address": address.to_string(), "state": name })
            })
            .collect();
        list.sort_by(|a, b| a["address"].as_str().cmp(&b["address"].as_str()));
        serde_json::json!({
            "bridges": total,
            "regions": regions,
            "machines": machines,
            "peers": states,
            "addresses": list,
            "complete": complete,
        })
    }

    // --- Links ---------------------------------------------------------------------------------------------

    /// Takes a link another machine dialed, after the start of its greeting line (`<machine> <nonce>`, after
    /// [`MESH_MAGIC`]). `stream` continues after that line.
    pub async fn accept<S>(self: &Arc<Self>, stream: S, greeting: &str) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let mut fields = greeting.split(' ');
        let (Some(dialer), Some(dial_nonce), None) = (fields.next(), fields.next(), fields.next())
        else {
            bail!("a malformed mesh greeting");
        };
        if !valid_id(dialer) || !valid_nonce(dial_nonce) {
            bail!("a malformed mesh greeting");
        }
        if dialer == self.machine_id {
            bail!("linked to itself");
        }
        let (read, mut write) = tokio::io::split(stream);
        let own_nonce = nonce();
        let proof = self.secret.sign(&[
            ACCEPT_LABEL,
            dialer,
            &self.machine_id,
            dial_nonce,
            &own_nonce,
        ]);
        let mut line = MESH_MAGIC.to_vec();
        line.extend_from_slice(format!("{} {own_nonce} {proof}\n", self.machine_id).as_bytes());
        tokio::time::timeout(HANDSHAKE_TIMEOUT, write.write_all(&line))
            .await
            .map_err(|_| anyhow!("the handshake timed out"))??;
        let mut reader = BufReader::new(read);
        let answer = read_line(&mut reader).await?;
        let expected = [DIAL_LABEL, dialer, &self.machine_id, dial_nonce, &own_nonce];
        if !self.secret.verify(&expected, &answer) {
            bail!("a mesh peer failed the challenge");
        }
        self.link(
            tokio::io::join(reader, write),
            false,
            Some(dialer.to_owned()),
            false,
        )
        .await
    }

    /// TEMPORARY: takes a link from a machine of the previous version, which greeted with the secret itself.
    /// It is answered with the line it sent, as that version expects, only when the secret is right.
    pub async fn accept_v1<S>(self: &Arc<Self>, stream: S, token: &str) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        if !self.config.accept_v1 {
            bail!("a mesh link of the previous version, which is no longer accepted");
        }
        if !self.secret.matches(token) {
            bail!("mesh link with a bad token");
        }
        let (read, mut write) = tokio::io::split(stream);
        let mut line = MESH_MAGIC_V1.to_vec();
        line.extend_from_slice(token.as_bytes());
        line.push(b'\n');
        tokio::time::timeout(HANDSHAKE_TIMEOUT, write.write_all(&line))
            .await
            .map_err(|_| anyhow!("the handshake timed out"))??;
        self.link(tokio::io::join(read, write), false, None, true)
            .await
    }

    async fn dial(self: &Arc<Self>, address: SocketAddr) -> Result<(), DialError> {
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(address))
            .await
            .map_err(|_| anyhow!("connecting timed out"))??;
        let _ = stream.set_nodelay(true);
        crate::net::keepalive(&stream);
        let (read, mut write) = stream.into_split();
        let own_nonce = nonce();
        let mut greeting = MESH_MAGIC.to_vec();
        greeting.extend_from_slice(format!("{} {own_nonce}\n", self.machine_id).as_bytes());
        write.write_all(&greeting).await?;
        // The other side answers with its challenge and proof, or (a version before the mesh, or before this
        // handshake) with HTTP.
        let mut reader = BufReader::new(read);
        let line = read_line(&mut reader).await?;
        if line.starts_with("HTTP/") {
            return Err(DialError::Legacy);
        }
        let mut fields = line
            .strip_prefix(std::str::from_utf8(MESH_MAGIC).expect("ASCII"))
            .ok_or_else(|| anyhow!("no greeting"))?
            .split(' ');
        let (Some(acceptor), Some(accept_nonce), Some(proof), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(anyhow!("a malformed greeting").into());
        };
        if !valid_id(acceptor) || !valid_nonce(accept_nonce) {
            return Err(anyhow!("a malformed greeting").into());
        }
        let parts = |label: &'static str| -> [&str; 5] {
            [
                label,
                self.machine_id.as_str(),
                acceptor,
                own_nonce.as_str(),
                accept_nonce,
            ]
        };
        if !self.secret.verify(&parts(ACCEPT_LABEL), proof) {
            return Err(anyhow!("the peer failed the challenge").into());
        }
        if acceptor == self.machine_id {
            return Err(anyhow!("linked to itself").into());
        }
        let answer = format!("{}\n", self.secret.sign(&parts(DIAL_LABEL)));
        write.write_all(answer.as_bytes()).await?;
        let acceptor = acceptor.to_owned();
        let stream = tokio::io::join(reader, write);
        Ok(self.link(stream, true, Some(acceptor), false).await?)
    }

    /// Runs a link after the handshake until it ends. `machine` is the machine that proved itself, if the
    /// handshake named one; `v1` a link of the previous version.
    async fn link<S>(
        self: &Arc<Self>,
        stream: S,
        dialed: bool,
        machine: Option<String>,
        v1: bool,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let cancel = self.halted.child_token();
        // Subscribed before `hello` goes out, so the peer misses nothing announced after it sees the link.
        let (link, queue) = self.subscribe(cancel.clone());
        let (read, write) = tokio::io::split(stream);
        let mut reader = BufReader::new(read);
        let mut writer = BufWriter::new(write);
        let result = self
            .run_link(
                &mut reader,
                &mut writer,
                (dialed, machine, v1),
                link,
                queue,
                &cancel,
            )
            .await;
        self.unsubscribe(link);
        cancel.cancel();
        if self.halted.is_cancelled() && self.silent.load(Ordering::SeqCst) {
            self.held
                .lock()
                .expect("held lock")
                .push(Box::new((reader, writer)));
        }
        result
    }

    async fn run_link<R, W>(
        self: &Arc<Self>,
        reader: &mut R,
        writer: &mut W,
        (dialed, machine, v1): (bool, Option<String>, bool),
        link: u64,
        mut queue: mpsc::Receiver<Bytes>,
        cancel: &CancellationToken,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut buffer = Vec::new();
        let peer = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
            writer
                .write_all(&encode(&Frame::Hello(self.hello())))
                .await?;
            writer.flush().await?;
            match read_frame(reader, &mut buffer, HANDSHAKE_TIMEOUT).await? {
                Frame::Hello(hello) => Ok(hello),
                _ => bail!("the peer did not say hello"),
            }
        })
        .await
        .map_err(|_| anyhow!("the handshake timed out"))??;
        if peer.machine_id == self.machine_id {
            bail!("linked to itself");
        }
        if machine.is_some_and(|machine| machine != peer.machine_id) {
            bail!("the peer said hello as another machine than it proved to be");
        }
        let dialer = if dialed {
            self.address().to_owned()
        } else {
            peer.address.clone()
        };
        let machine = peer.machine_id.clone();
        if !self.register(peer, link, dialer, cancel.clone(), v1) {
            debug!(peer = %machine, "a duplicate mesh link closed");
            return Ok(());
        }
        let _ = self.notices.send(Notice::LinkUp);
        let result = tokio::select! {
            result = self.read_loop(reader, &machine, link, &mut buffer) => result,
            result = self.write_loop(writer, &mut queue) => result,
            () = cancel.cancelled() => Ok(()),
        };
        self.link_down(&machine, link, result.as_ref().err());
        result
    }

    async fn read_loop<R: AsyncRead + Unpin>(
        &self,
        reader: &mut R,
        machine: &str,
        link: u64,
        buffer: &mut Vec<u8>,
    ) -> Result<()> {
        loop {
            let frame = read_frame(reader, buffer, self.config.dead).await?;
            self.apply(machine, link, frame)?;
        }
    }

    async fn write_loop<W: AsyncWrite + Unpin>(
        &self,
        writer: &mut W,
        queue: &mut mpsc::Receiver<Bytes>,
    ) -> Result<()> {
        let mut ping = tokio::time::interval(self.config.ping);
        ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                frame = queue.recv() => {
                    let Some(frame) = frame else {
                        bail!("the link's queue closed");
                    };
                    writer.write_all(&frame).await?;
                    let mut written = frame.len();
                    while written < WRITE_BATCH {
                        let Ok(frame) = queue.try_recv() else {
                            break;
                        };
                        writer.write_all(&frame).await?;
                        written += frame.len();
                    }
                    writer.flush().await?;
                    ping.reset();
                }
                _ = ping.tick() => {
                    writer.write_all(&encode(&Frame::Ping { sent_at: self.now() })).await?;
                    writer.flush().await?;
                }
            }
        }
    }

    /// Records a new link to a peer, unless a better one exists: the newer life of the machine wins, then the
    /// link dialed by the lower address, then the newer link. Both sides decide alike.
    fn register(
        &self,
        hello: Hello,
        link: u64,
        dialer: String,
        cancel: CancellationToken,
        v1: bool,
    ) -> bool {
        if self
            .partitioned
            .lock()
            .expect("partitioned lock")
            .contains(&hello.machine_id)
        {
            return false;
        }
        let machine = hello.machine_id.clone();
        let mut remote = self.remote.lock().expect("mesh remote lock");
        let mut entries = HashMap::new();
        if let Some(existing) = remote.peers.get(&machine) {
            let life = (hello.started_at, hello.epoch);
            let known = (existing.hello.started_at, existing.hello.epoch);
            let wins = if life != known {
                life > known
            } else if existing.dialer != dialer {
                dialer < existing.dialer
            } else {
                true
            };
            if !wins {
                return false;
            }
            existing.cancel.cancel();
            if life == known {
                // The snapshot that follows replaces them; until then they are still right.
                entries =
                    std::mem::take(&mut remote.peers.get_mut(&machine).expect("peer").entries);
            } else {
                remote.clear(&machine);
            }
        }
        info!(peer = %machine, region = %hello.region, address = %hello.address, epoch = hello.epoch, draining = hello.draining, "mesh peer up");
        remote.peers.insert(
            machine.clone(),
            Peer {
                hello,
                link,
                dialer,
                cancel,
                connected_at: self.now(),
                seq: 0,
                entries,
                v1,
            },
        );
        drop(remote);
        crate::metrics::mesh_link("up");
        self.update_gauges();
        true
    }

    fn link_down(&self, machine: &str, link: u64, error: Option<&anyhow::Error>) {
        let mut remote = self.remote.lock().expect("mesh remote lock");
        if remote
            .peers
            .get(machine)
            .is_none_or(|peer| peer.link != link)
        {
            return;
        }
        remote.clear(machine);
        remote.peers.remove(machine);
        drop(remote);
        if self.halted.is_cancelled() {
            return;
        }
        match error {
            Some(error) => warn!(peer = %machine, error = %format!("{error:#}"), "mesh peer down"),
            None => info!(peer = %machine, "mesh peer down"),
        }
        crate::metrics::mesh_link("down");
        crate::metrics::set_mesh_table(machine, None);
        self.update_gauges();
    }

    /// Applies a frame from a peer's current link.
    fn apply(&self, machine: &str, link: u64, frame: Frame) -> Result<()> {
        let now = self.now();
        let mut remote = self.remote.lock().expect("mesh remote lock");
        let Remote { peers, index } = &mut *remote;
        let Some(peer) = peers.get_mut(machine).filter(|peer| peer.link == link) else {
            bail!("the link was replaced");
        };
        match frame {
            Frame::Ping { .. } | Frame::Unknown => return Ok(()),
            Frame::Hello(_) => bail!("a second hello"),
            Frame::Snapshot {
                epoch,
                seq,
                sent_at,
                entries,
            } => {
                if epoch != peer.hello.epoch {
                    bail!("a snapshot of another epoch");
                }
                for entry in peer.entries.values() {
                    Remote::index_remove(index, machine, entry);
                }
                peer.entries.clear();
                peer.seq = seq;
                let count = entries.len();
                if !peer.hello.draining {
                    for entry in entries {
                        Remote::index_add(index, machine, &entry);
                        peer.entries.insert(entry.bridge, entry);
                    }
                }
                debug!(peer = %machine, bridges = count, "mesh snapshot applied");
                crate::metrics::mesh_snapshot(count, now.saturating_sub(sent_at));
            }
            Frame::Attached {
                seq,
                sent_at,
                entry,
            } => {
                if seq != peer.seq + 1 {
                    bail!("sequence {seq} after {}", peer.seq);
                }
                peer.seq = seq;
                if !peer.hello.draining {
                    if let Some(previous) = peer.entries.get(&entry.bridge) {
                        Remote::index_remove(index, machine, previous);
                    }
                    Remote::index_add(index, machine, &entry);
                    peer.entries.insert(entry.bridge, entry);
                }
                crate::metrics::mesh_propagation("attached", now.saturating_sub(sent_at));
            }
            Frame::Detached {
                seq,
                sent_at,
                bridge,
                ..
            } => {
                if seq != peer.seq + 1 {
                    bail!("sequence {seq} after {}", peer.seq);
                }
                peer.seq = seq;
                if let Some(entry) = peer.entries.remove(&bridge) {
                    Remote::index_remove(index, machine, &entry);
                }
                crate::metrics::mesh_propagation("detached", now.saturating_sub(sent_at));
            }
            Frame::Event { sent_at, event } => {
                crate::metrics::mesh_propagation("event", now.saturating_sub(sent_at));
                match event {
                    Event::Leaving => {
                        info!(peer = %machine, "mesh peer leaving");
                        peer.hello.draining = true;
                        for entry in peer.entries.values() {
                            Remote::index_remove(index, machine, entry);
                        }
                        peer.entries.clear();
                    }
                    Event::Unknown => {}
                    event => {
                        let _ = self.notices.send(Notice::Event(event));
                    }
                }
            }
        }
        let count = remote
            .peers
            .get(machine)
            .map_or(0, |peer| peer.entries.len());
        drop(remote);
        crate::metrics::set_mesh_table(machine, Some(count));
        Ok(())
    }

    // --- Membership ----------------------------------------------------------------------------------------

    /// Finds peers every `discovery` interval and keeps a dialer per address, until halted.
    pub async fn run(self: Arc<Self>) {
        loop {
            self.discover().await;
            tokio::select! {
                () = tokio::time::sleep(self.config.discovery) => {}
                () = self.discover_now.notified() => {}
                () = self.halted.cancelled() => return,
            }
        }
    }

    /// Adds a static peer address and dials it at once.
    pub fn add_peer(&self, address: &str) {
        self.statics
            .lock()
            .expect("statics lock")
            .push(address.to_owned());
        self.discover_now.notify_one();
    }

    async fn discover(self: &Arc<Self>) {
        let own = self.own_address();
        let statics = self.statics.lock().expect("statics lock").clone();
        let mut found: Vec<(SocketAddr, bool)> = Vec::new();
        for peer in &statics {
            match tokio::net::lookup_host(peer.as_str()).await {
                Ok(addresses) => found.extend(addresses.map(|address| (address, true))),
                Err(error) => debug!(peer, %error, "could not resolve a mesh peer"),
            }
        }
        let mut resolved = true;
        if let (Some(name), Some(own)) = (&self.config.dns, own) {
            match tokio::net::lookup_host((name.as_str(), own.port())).await {
                Ok(addresses) => found.extend(addresses.map(|address| (address, false))),
                Err(error) => {
                    resolved = false;
                    debug!(name, %error, "could not resolve the mesh peers");
                }
            }
        }
        let mut spawn = Vec::new();
        {
            let mut addresses = self.addresses.lock().expect("mesh addresses lock");
            // A failed lookup keeps what the last one found.
            if resolved {
                for address in addresses.values_mut() {
                    address.current = address.is_static;
                }
            }
            for (address, is_static) in found {
                if Some(address) == own {
                    continue;
                }
                let known = addresses.entry(address).or_insert_with(|| {
                    spawn.push(address);
                    Address {
                        state: AddressState::Connecting,
                        current: true,
                        is_static,
                        seen: Instant::now(),
                        legacy_at: None,
                    }
                });
                known.current = true;
                known.is_static |= is_static;
                known.seen = Instant::now();
            }
        }
        for address in spawn {
            tokio::spawn(self.clone().dial_loop(address));
        }
        self.update_gauges();
    }

    fn set_state(&self, address: SocketAddr, state: AddressState) {
        if let Some(known) = self
            .addresses
            .lock()
            .expect("mesh addresses lock")
            .get_mut(&address)
        {
            known.state = state;
            if state == AddressState::Legacy {
                known.legacy_at = Some(Instant::now());
            } else if state == AddressState::Up {
                known.legacy_at = None;
            }
        }
    }

    /// Keeps a link to `address` (dialing it whenever there is none) until it leaves DNS for good.
    async fn dial_loop(self: Arc<Self>, address: SocketAddr) {
        let higher = self.own_address().is_some_and(|own| own > address);
        if higher {
            tokio::select! {
                () = tokio::time::sleep(HIGHER_DIAL_DELAY) => {}
                () = self.halted.cancelled() => return,
            }
        }
        let mut backoff = FIRST_BACKOFF;
        loop {
            if self.halted.is_cancelled() {
                return;
            }
            {
                let mut addresses = self.addresses.lock().expect("mesh addresses lock");
                let wanted = addresses.get(&address).is_some_and(|known| {
                    known.is_static || known.current || known.seen.elapsed() < FORGET_AFTER
                });
                if !wanted {
                    addresses.remove(&address);
                    return;
                }
            }
            let wait = if self.linked(address) {
                self.set_state(address, AddressState::Up);
                backoff = FIRST_BACKOFF;
                Duration::from_millis(500)
            } else {
                match self.dial(address).await {
                    Ok(()) => {
                        backoff = FIRST_BACKOFF;
                        if self.linked(address) {
                            Duration::ZERO
                        } else {
                            self.set_state(address, AddressState::Connecting);
                            FIRST_BACKOFF
                        }
                    }
                    Err(DialError::Legacy) => {
                        self.set_state(address, AddressState::Legacy);
                        LEGACY_RETRY
                    }
                    Err(DialError::Other(error)) => {
                        if !self.linked(address) {
                            self.set_state(address, AddressState::Unreachable);
                        }
                        debug!(%address, error = %format!("{error:#}"), "mesh dial failed");
                        let wait = backoff;
                        backoff = (backoff * 2).min(MAX_BACKOFF);
                        wait
                    }
                }
            };
            self.update_gauges();
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                () = self.halted.cancelled() => return,
            }
        }
    }

    /// The state of every current peer address, as of now.
    fn address_states(&self) -> Vec<(SocketAddr, AddressState)> {
        let known: Vec<(SocketAddr, AddressState)> = self
            .addresses
            .lock()
            .expect("mesh addresses lock")
            .iter()
            .filter(|(_, address)| address.current)
            .map(|(address, known)| (*address, known.state))
            .collect();
        known
            .into_iter()
            .map(|(address, state)| {
                let state = match (self.linked(address), state) {
                    (true, _) => AddressState::Up,
                    (false, AddressState::Up) => AddressState::Connecting,
                    (false, state) => state,
                };
                (address, state)
            })
            .collect()
    }

    fn update_gauges(&self) {
        let mut counts = [
            ("up", 0),
            ("connecting", 0),
            ("unreachable", 0),
            ("legacy", 0),
        ];
        for (_, state) in self.address_states() {
            let index = match state {
                AddressState::Up => 0,
                AddressState::Connecting => 1,
                AddressState::Unreachable => 2,
                AddressState::Legacy => 3,
            };
            counts[index].1 += 1;
        }
        crate::metrics::set_mesh_peers(&counts);
    }

    // --- Shutdown and test hooks ---------------------------------------------------------------------------

    /// Ends every link and dialer. `silent` keeps the sockets open without sending anything, like a machine
    /// that froze, so peers notice only through the ping timeout (tests).
    pub fn halt(&self, silent: bool) {
        self.silent.store(silent, Ordering::SeqCst);
        self.halted.cancel();
    }

    /// Test hook: cuts (or heals) the link to a machine, and refuses to link with it while cut.
    #[doc(hidden)]
    pub fn partition(&self, machine_id: &str, cut: bool) {
        let mut partitioned = self.partitioned.lock().expect("partitioned lock");
        if !cut {
            partitioned.remove(machine_id);
            drop(partitioned);
            self.discover_now.notify_one();
            return;
        }
        partitioned.insert(machine_id.to_owned());
        drop(partitioned);
        if let Some(peer) = self
            .remote
            .lock()
            .expect("mesh remote lock")
            .peers
            .get(machine_id)
        {
            peer.cancel.cancel();
        }
    }
}
