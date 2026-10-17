//! Load test for the server (docs/server.md, "Capacity"): many bridges attached like real clients (TCP, TLS to
//! the API domain, the WebSocket upgrade, `attach`, pings every 15 s), visitors whose connections go through
//! them (the bridges echo every byte back), and a reconnect storm (every bridge dropped at once, reconnecting
//! with the clients' backoff).
//!
//! ```text
//! cargo run --release -p opentunnel-server --example loadtest -- seed --database-url $URL --count 20000
//! cargo run --release -p opentunnel-server --example loadtest -- run --server 127.0.0.1:8443 --count 20000 --pid $PID
//! ```

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use futures_util::{SinkExt, StreamExt};
use opentunnel_server::store::Store;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::watch;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Writes `count` tunnels with ready certificates into the database (IDs and tokens derive from the index).
    Seed {
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
        #[arg(long, default_value_t = 10_000)]
        count: usize,
        #[arg(long, default_value = "opentunnel.test")]
        domain: String,
    },
    /// Attaches the bridges, holds them, sends visitors through them, then drops them all at once.
    Run(Run),
    /// A TCP proxy adding `delay_ms` each way, to put the database as far away as from `nrt` or `syd`.
    Delay {
        #[arg(long, default_value = "127.0.0.1:13307")]
        listen: SocketAddr,
        #[arg(long, default_value = "127.0.0.1:3306")]
        target: SocketAddr,
        /// One way: a round trip takes twice this.
        #[arg(long, default_value_t = 75)]
        delay_ms: u64,
    },
}

#[derive(Parser, Clone)]
struct Run {
    /// The server's TLS listener.
    #[arg(long, default_value = "127.0.0.1:8443")]
    server: SocketAddr,
    #[arg(long, default_value = "opentunnel.test")]
    domain: String,
    /// Bridges (tunnels `0..count`, as seeded).
    #[arg(long, default_value_t = 10_000)]
    count: usize,
    /// New bridges started per second during the ramp.
    #[arg(long, default_value_t = 1_000)]
    rate: usize,
    /// Loopback source addresses (127.0.0.1, 127.0.0.2, ...): each gives one ephemeral port range.
    #[arg(long, default_value_t = 4)]
    sources: u8,
    /// Send a PROXY v2 header first (the server with `PROXY_PROTOCOL=true`, like Fly).
    #[arg(long)]
    proxy_protocol: bool,
    /// Disable TLS session resumption: every connection makes a full handshake.
    #[arg(long)]
    no_resume: bool,
    /// The server's process ID, to sample its CPU time and memory from /proc.
    #[arg(long)]
    pid: Option<u32>,
    /// Seconds to hold the bridges idle after the ramp (pings only), measuring steady-state CPU and memory.
    #[arg(long, default_value_t = 30)]
    hold: u64,
    /// Visitor loops running at once during the visitor phase (0 skips it).
    #[arg(long, default_value_t = 50)]
    visitors: usize,
    #[arg(long, default_value_t = 20)]
    visit_seconds: u64,
    /// Round trips of `echo_bytes` per visitor connection, after the ClientHello comes back.
    #[arg(long, default_value_t = 5)]
    round_trips: usize,
    #[arg(long, default_value_t = 4096)]
    echo_bytes: usize,
    /// Seconds to wait after the visitor phase before sampling memory again (freed memory returned or not).
    #[arg(long, default_value_t = 20)]
    rest: u64,
    /// Drop every bridge at once after the visitor phase and wait for all to attach again (`--storm 0` skips).
    #[arg(long, default_value_t = 1)]
    storms: usize,
    /// Give up waiting for the ramp or a storm to finish after this many seconds.
    #[arg(long, default_value_t = 600)]
    timeout: u64,
}

const HEARTBEAT: Duration = Duration::from_millis(15_000);
const CONNECT_TIMEOUT: Duration = Duration::from_millis(10_000);
const BACKOFF_MIN_MS: u64 = 250;
const BACKOFF_MAX_MS: u64 = 30_000;

fn tunnel_id(index: usize) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut id = String::from("lt");
    let mut rest = index as u64;
    for _ in 0..10 {
        id.push(ALPHABET[(rest & 31) as usize] as char);
        rest >>= 5;
    }
    id
}

fn tunnel_token(index: usize) -> String {
    format!("rly_loadtest_{index}")
}

/// splitmix64 over a shared counter: enough randomness for jitter and picking tunnels.
fn random() -> u64 {
    static STATE: AtomicU64 = AtomicU64::new(0x9e37_79b9_7f4a_7c15);
    let mut z = STATE
        .fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed)
        .wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// The clients' reconnect delay (`crates/opentunnel/src/tunnel.rs`).
fn backoff(attempt: u32) -> Duration {
    let base = BACKOFF_MIN_MS
        .saturating_mul(1 << attempt.min(16))
        .min(BACKOFF_MAX_MS);
    Duration::from_millis(base / 2 + random() % (base / 2 + 1))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn iso(ms: u64) -> String {
    let date = time::OffsetDateTime::from_unix_timestamp_nanos(ms as i128 * 1_000_000)
        .expect("valid time");
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        date.year(),
        date.month() as u8,
        date.day(),
        date.hour(),
        date.minute(),
        date.second(),
        date.millisecond()
    )
}

async fn seed(database_url: &str, count: usize, domain: &str) -> Result<()> {
    let store = Store::connect(database_url, 32)?;
    store.wait_ready(None).await?;
    let connected = iso(now_ms());
    // As large as real records: a certificate, its chain and the CSR in PEM are ~6 KB, cached per attached tunnel.
    let pem = |bytes: usize| {
        let body: String = (0..bytes)
            .map(|_| (b'A' + (random() % 26) as u8) as char)
            .collect();
        format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n")
    };
    let (certificate, chain, csr) = (pem(1_800), pem(3_600), pem(600));
    let started = Instant::now();
    let done = AtomicUsize::new(0);
    futures_util::stream::iter(0..count)
        .map(|index| {
            let store = &store;
            let connected = &connected;
            let done = &done;
            let (certificate, chain, csr) = (&certificate, &chain, &csr);
            async move {
                let id = tunnel_id(index);
                let record = serde_json::from_value(json!({
                    "version": 1,
                    "id": id,
                    "hostname": format!("{id}.{domain}"),
                    "state": "online",
                    "tokenHash": opentunnel_server::crypto::hash_token(&tunnel_token(index)),
                    "createdAt": "2026-10-01T00:00:00.000Z",
                    "certificateID": "cert_loadtest",
                    "certificate": {
                        "id": "cert_loadtest",
                        "state": { "type": "ready", "certificate": certificate, "chain": chain, "expiry": "2099-01-01T00:00:00.000Z" }
                    },
                    "certificateCsr": csr,
                    "certificateIdentifiers": [format!("{id}.{domain}"), format!("*.{id}.{domain}")],
                    "lastConnectedAt": connected,
                }))?;
                // A renewal alarm far ahead, so attaches schedule nothing.
                store
                    .import_tunnel(record, Some(4_000_000_000_000), true, now_ms())
                    .await?;
                let done = done.fetch_add(1, Ordering::Relaxed) + 1;
                if done.is_multiple_of(5_000) {
                    eprintln!("seeded {done}");
                }
                anyhow::Ok(())
            }
        })
        .buffer_unordered(32)
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<()>>()?;
    eprintln!("seeded {count} tunnels in {:.1?}", started.elapsed());
    Ok(())
}

#[derive(Debug)]
struct AcceptAny(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn client_config(resume: bool, alpn: &[&[u8]]) -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("ring supports the default versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny(provider)))
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    config.resumption = if resume {
        rustls::client::Resumption::in_memory_sessions(4096)
    } else {
        rustls::client::Resumption::disabled()
    };
    Arc::new(config)
}

#[derive(Default)]
struct Stats {
    attached: AtomicUsize,
    attaches: AtomicU64,
    attempts: AtomicU64,
    drops: AtomicU64,
    failures: Mutex<BTreeMap<String, u64>>,
    attach_ms: Mutex<Vec<u32>>,
    visits: AtomicU64,
    visit_failures: Mutex<BTreeMap<String, u64>>,
    /// Connect to the ClientHello echoed back, through the server and a bridge.
    first_byte_ms: Mutex<Vec<u32>>,
    round_trip_us: Mutex<Vec<u32>>,
}

impl Stats {
    fn fail(&self, reason: impl Into<String>) {
        *self
            .failures
            .lock()
            .unwrap()
            .entry(reason.into())
            .or_default() += 1;
    }

    fn visit_fail(&self, reason: impl Into<String>) {
        *self
            .visit_failures
            .lock()
            .unwrap()
            .entry(reason.into())
            .or_default() += 1;
    }
}

struct Harness {
    run: Run,
    tls: tokio_rustls::TlsConnector,
    stats: Stats,
    /// Bumped to drop every bridge at once.
    storm: watch::Sender<u64>,
    stop: AtomicBool,
    sockets: AtomicU64,
}

impl Harness {
    async fn connect(&self, destination: SocketAddr) -> std::io::Result<TcpStream> {
        let socket = TcpSocket::new_v4()?;
        let source = 1 + (self.sockets.fetch_add(1, Ordering::Relaxed) % self.run.sources as u64);
        socket.bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, source as u8)),
            0,
        ))?;
        let stream = socket.connect(destination).await?;
        stream.set_nodelay(true)?;
        Ok(stream)
    }
}

fn proxy_header(source: SocketAddr, destination: SocketAddr) -> Vec<u8> {
    let mut header = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
    header.extend_from_slice(&[0x21, 0x11, 0, 12]);
    let (IpAddr::V4(from), IpAddr::V4(to)) = (source.ip(), destination.ip()) else {
        return Vec::new();
    };
    header.extend_from_slice(&from.octets());
    header.extend_from_slice(&to.octets());
    header.extend_from_slice(&source.port().to_be_bytes());
    header.extend_from_slice(&destination.port().to_be_bytes());
    header
}

enum End {
    Dropped { attached: bool },
    Stopped,
}

async fn bridge(context: Arc<Harness>, index: usize) {
    let mut attempt = 0u32;
    let mut storm = context.storm.subscribe();
    storm.mark_unchanged();
    loop {
        match session(&context, index, &mut storm).await {
            End::Stopped => return,
            End::Dropped { attached } => {
                if attached {
                    attempt = 0;
                }
                let delay = backoff(attempt);
                attempt = attempt.saturating_add(1);
                tokio::time::sleep(delay).await;
                if context.stop.load(Ordering::Relaxed) {
                    return;
                }
            }
        }
    }
}

type Socket = tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>;

async fn open(context: &Harness, index: usize) -> Result<Socket, String> {
    let run = &context.run;
    let mut stream = context
        .connect(run.server)
        .await
        .map_err(|error| format!("connect: {}", error.kind()))?;
    if run.proxy_protocol {
        let local = stream.local_addr().map_err(|error| error.to_string())?;
        stream
            .write_all(&proxy_header(local, run.server))
            .await
            .map_err(|error| format!("connect: {}", error.kind()))?;
    }
    let name = ServerName::try_from(run.domain.clone()).map_err(|error| error.to_string())?;
    let tls = context
        .tls
        .connect(name, stream)
        .await
        .map_err(|error| format!("tls: {}", error.kind()))?;
    let mut request = format!(
        "wss://{}/api/tunnel/{}/connect",
        run.domain,
        tunnel_id(index)
    )
    .into_client_request()
    .map_err(|error| error.to_string())?;
    request.headers_mut().insert(
        "sec-websocket-protocol",
        "opentunnel".parse().expect("valid header"),
    );
    request.headers_mut().insert(
        "user-agent",
        "opentunnel-loadtest".parse().expect("valid header"),
    );
    let config = WebSocketConfig::default()
        .read_buffer_size(4096)
        .write_buffer_size(0);
    let (socket, _) = tokio_tungstenite::client_async_with_config(request, tls, Some(config))
        .await
        .map_err(|error| match error {
            tokio_tungstenite::tungstenite::Error::Http(response) => {
                format!("upgrade: {}", response.status().as_u16())
            }
            error => format!("upgrade: {error}"),
        })?;
    Ok(socket)
}

async fn session(context: &Harness, index: usize, storm: &mut watch::Receiver<u64>) -> End {
    let stats = &context.stats;
    stats.attempts.fetch_add(1, Ordering::Relaxed);
    let started = Instant::now();
    let attach = async {
        let mut socket = open(context, index).await?;
        let attach = json!({
            "type": "attach",
            "token": tunnel_token(index),
            "transport": "ws",
            "routes": ["@"],
            "client": { "version": "loadtest", "max_conns": 64 },
        });
        socket
            .send(Message::text(attach.to_string()))
            .await
            .map_err(|_| "attach: send".to_owned())?;
        loop {
            match socket.next().await {
                Some(Ok(Message::Text(text))) => {
                    let control: Value =
                        serde_json::from_str(text.as_str()).map_err(|error| error.to_string())?;
                    return match control["type"].as_str() {
                        Some("attached") => Ok(socket),
                        Some("attach_error") => Err(format!(
                            "attach_error: {}",
                            control["code"].as_str().unwrap_or("?")
                        )),
                        _ => continue,
                    };
                }
                Some(Ok(Message::Close(frame))) => {
                    return Err(format!(
                        "closed: {}",
                        frame.map_or(1005, |frame| u16::from(frame.code))
                    ));
                }
                Some(Ok(_)) => continue,
                Some(Err(_)) | None => return Err("closed before attached".to_owned()),
            }
        }
    };
    let socket = tokio::select! {
        result = tokio::time::timeout(CONNECT_TIMEOUT, attach) => match result {
            Ok(Ok(socket)) => socket,
            Ok(Err(reason)) => {
                stats.fail(reason);
                return End::Dropped { attached: false };
            }
            Err(_) => {
                stats.fail("timeout");
                return End::Dropped { attached: false };
            }
        },
        _ = storm.changed() => return End::Dropped { attached: true },
    };
    stats
        .attach_ms
        .lock()
        .unwrap()
        .push(started.elapsed().as_millis() as u32);
    stats.attaches.fetch_add(1, Ordering::Relaxed);
    stats.attached.fetch_add(1, Ordering::Relaxed);
    let end = attached(context, socket, storm).await;
    stats.attached.fetch_sub(1, Ordering::Relaxed);
    end
}

async fn attached(context: &Harness, socket: Socket, storm: &mut watch::Receiver<u64>) -> End {
    let (mut sink, mut stream) = socket.split();
    // Pings start at a random point in the first interval, as clients that attached at different times do.
    let first = tokio::time::Instant::now() + Duration::from_millis(random() % 15_000);
    let mut pings = tokio::time::interval_at(first, HEARTBEAT);
    loop {
        tokio::select! {
            _ = storm.changed() => {
                // Gone without a close, like a machine that died: the reconnect is what is measured.
                return End::Dropped { attached: true };
            }
            _ = pings.tick() => {
                if context.stop.load(Ordering::Relaxed) {
                    let _ = sink.close().await;
                    return End::Stopped;
                }
                let ping = json!({ "type": "ping", "time_sent": now_ms() }).to_string();
                if sink.send(Message::text(ping)).await.is_err() {
                    context.stats.drops.fetch_add(1, Ordering::Relaxed);
                    return End::Dropped { attached: true };
                }
            }
            message = stream.next() => {
                let reply = match message {
                    // The data comes back as it arrived, on the same connection.
                    Some(Ok(Message::Binary(frame))) => Some(Message::Binary(frame)),
                    Some(Ok(Message::Text(text))) => {
                        let control: Value = serde_json::from_str(text.as_str()).unwrap_or(Value::Null);
                        match control["type"].as_str() {
                            Some("end") => Some(Message::text(
                                json!({ "type": "end", "conn": control["conn"] }).to_string(),
                            )),
                            _ => None,
                        }
                    }
                    Some(Ok(_)) => None,
                    Some(Err(_)) | None => {
                        context.stats.drops.fetch_add(1, Ordering::Relaxed);
                        return End::Dropped { attached: true };
                    }
                };
                if let Some(reply) = reply
                    && sink.send(reply).await.is_err()
                {
                    context.stats.drops.fetch_add(1, Ordering::Relaxed);
                    return End::Dropped { attached: true };
                }
            }
        }
    }
}

/// One visitor connection: a real ClientHello for the tunnel's hostname, echoed back by its bridge, then
/// `round_trips` echoes of `echo_bytes`, then a half-close answered by the bridge's `end`.
async fn visit(context: &Harness, hello_config: &Arc<rustls::ClientConfig>) -> Result<()> {
    let run = &context.run;
    let index = (random() % run.count as u64) as usize;
    let host = format!("{}.{}", tunnel_id(index), run.domain);
    let mut connection = rustls::ClientConnection::new(
        hello_config.clone(),
        ServerName::try_from(host).context("server name")?,
    )?;
    let mut hello = Vec::new();
    while connection.wants_write() {
        connection.write_tls(&mut hello)?;
    }
    let started = Instant::now();
    let mut stream = context.connect(run.server).await.context("connect")?;
    if run.proxy_protocol {
        let local = stream.local_addr()?;
        stream.write_all(&proxy_header(local, run.server)).await?;
    }
    stream.write_all(&hello).await?;
    let mut echoed = vec![0u8; hello.len()];
    stream.read_exact(&mut echoed).await.context("hello echo")?;
    if echoed != hello {
        bail!("hello echo differs");
    }
    context
        .stats
        .first_byte_ms
        .lock()
        .unwrap()
        .push(started.elapsed().as_millis() as u32);
    let payload: Vec<u8> = (0..run.echo_bytes).map(|byte| byte as u8).collect();
    let mut back = vec![0u8; payload.len()];
    for _ in 0..run.round_trips {
        let sent = Instant::now();
        stream.write_all(&payload).await?;
        stream.read_exact(&mut back).await.context("echo")?;
        context
            .stats
            .round_trip_us
            .lock()
            .unwrap()
            .push(sent.elapsed().as_micros() as u32);
    }
    stream.shutdown().await?;
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).await.context("end")?;
    Ok(())
}

#[derive(Clone, Copy, Default)]
struct Sample {
    cpu_ticks: u64,
    rss: u64,
}

fn sample(pid: Option<u32>) -> Option<Sample> {
    let pid = pid?;
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Fields after the command name, which is in parentheses and may contain spaces.
    let fields: Vec<&str> = stat.rsplit_once(')')?.1.split_whitespace().collect();
    let cpu_ticks = fields.get(11)?.parse::<u64>().ok()? + fields.get(12)?.parse::<u64>().ok()?;
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let rss = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))?
        .trim()
        .trim_end_matches(" kB")
        .parse::<u64>()
        .ok()?
        * 1024;
    Some(Sample { cpu_ticks, rss })
}

/// Server CPU (in % of one core) and memory over a phase.
struct Meter {
    pid: Option<u32>,
    start: Instant,
    first: Option<Sample>,
    peak_cpu: Arc<Mutex<f64>>,
    peak_rss: Arc<AtomicU64>,
}

impl Meter {
    fn start(pid: Option<u32>) -> Self {
        let meter = Self {
            pid,
            start: Instant::now(),
            first: sample(pid),
            peak_cpu: Arc::default(),
            peak_rss: Arc::default(),
        };
        let (peak_cpu, peak_rss) = (meter.peak_cpu.clone(), meter.peak_rss.clone());
        tokio::spawn(async move {
            let mut last = (Instant::now(), sample(pid));
            loop {
                tokio::time::sleep(Duration::from_millis(500)).await;
                if Arc::strong_count(&peak_rss) == 1 {
                    return;
                }
                let now = (Instant::now(), sample(pid));
                if let (Some(before), Some(after)) = (last.1, now.1) {
                    let cpu = (after.cpu_ticks - before.cpu_ticks) as f64
                        / ticks_per_second()
                        / now.0.duration_since(last.0).as_secs_f64()
                        * 100.0;
                    let mut peak = peak_cpu.lock().unwrap();
                    *peak = peak.max(cpu);
                    peak_rss.fetch_max(after.rss, Ordering::Relaxed);
                }
                last = now;
            }
        });
        meter
    }

    /// Average CPU, peak CPU (over 0.5 s), current and peak RSS.
    fn finish(self) -> (f64, f64, u64, u64) {
        let end = sample(self.pid);
        let average = match (self.first, end) {
            (Some(first), Some(end)) => {
                (end.cpu_ticks - first.cpu_ticks) as f64
                    / ticks_per_second()
                    / self.start.elapsed().as_secs_f64()
                    * 100.0
            }
            _ => 0.0,
        };
        let rss = end.map_or(0, |end| end.rss);
        let peak_cpu = *self.peak_cpu.lock().unwrap();
        let peak_rss = self.peak_rss.load(Ordering::Relaxed).max(rss);
        (average, peak_cpu, rss, peak_rss)
    }
}

fn ticks_per_second() -> f64 {
    // SAFETY: sysconf has no preconditions.
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks > 0 { ticks as f64 } else { 100.0 }
}

fn percentiles(values: &mut [u32]) -> String {
    if values.is_empty() {
        return "-".into();
    }
    values.sort_unstable();
    let at = |q: f64| values[((values.len() - 1) as f64 * q) as usize];
    format!(
        "p50 {} p90 {} p99 {} max {}",
        at(0.5),
        at(0.9),
        at(0.99),
        values[values.len() - 1]
    )
}

fn mb(bytes: u64) -> f64 {
    bytes as f64 / 1_048_576.0
}

async fn wait_attached(context: &Harness, count: usize, timeout: Duration) -> Option<Duration> {
    let started = Instant::now();
    let mut last_report = Instant::now();
    while started.elapsed() < timeout {
        let attached = context.stats.attached.load(Ordering::Relaxed);
        if attached >= count {
            return Some(started.elapsed());
        }
        if last_report.elapsed() >= Duration::from_secs(5) {
            last_report = Instant::now();
            let failures: u64 = context.stats.failures.lock().unwrap().values().sum();
            eprintln!(
                "  {:>5.1}s attached {attached}/{count}, attempts {}, failures {failures}",
                started.elapsed().as_secs_f64(),
                context.stats.attempts.load(Ordering::Relaxed)
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    None
}

fn take_failures(context: &Harness) -> String {
    let failures = std::mem::take(&mut *context.stats.failures.lock().unwrap());
    if failures.is_empty() {
        return "none".into();
    }
    failures
        .iter()
        .map(|(reason, count)| format!("{reason} ×{count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

async fn run(run: Run) -> Result<()> {
    let count = run.count;
    let timeout = Duration::from_secs(run.timeout);
    let (storm, _) = watch::channel(0);
    let context = Arc::new(Harness {
        tls: tokio_rustls::TlsConnector::from(client_config(!run.no_resume, &[b"http/1.1"])),
        run: run.clone(),
        stats: Stats::default(),
        storm,
        stop: AtomicBool::new(false),
        sockets: AtomicU64::new(0),
    });
    let idle = sample(run.pid);
    if let Some(idle) = idle {
        println!("server before: rss {:.1} MB", mb(idle.rss));
    }

    // Ramp.
    println!("ramp: {count} bridges at {}/s", run.rate);
    let meter = Meter::start(run.pid);
    let spawner = {
        let context = context.clone();
        let rate = run.rate.max(1);
        tokio::spawn(async move {
            let started = Instant::now();
            for index in 0..count {
                let due = started + Duration::from_secs_f64(index as f64 / rate as f64);
                tokio::time::sleep_until(due.into()).await;
                tokio::spawn(bridge(context.clone(), index));
            }
        })
    };
    let ramp = wait_attached(&context, count, timeout).await;
    spawner.abort();
    let (cpu, peak_cpu, rss, peak_rss) = meter.finish();
    let attach_ms = percentiles(&mut std::mem::take(
        &mut *context.stats.attach_ms.lock().unwrap(),
    ));
    match ramp {
        Some(elapsed) => println!(
            "ramp: {count} attached in {:.1}s ({:.0}/s); attach ms {attach_ms}; server cpu avg {cpu:.0}% peak {peak_cpu:.0}%, rss {:.0} MB (peak {:.0}); failures: {}",
            elapsed.as_secs_f64(),
            count as f64 / elapsed.as_secs_f64(),
            mb(rss),
            mb(peak_rss),
            take_failures(&context)
        ),
        None => println!(
            "ramp: timed out with {} attached; failures: {}",
            context.stats.attached.load(Ordering::Relaxed),
            take_failures(&context)
        ),
    }

    // Steady state.
    println!("hold: {}s idle", run.hold);
    let meter = Meter::start(run.pid);
    tokio::time::sleep(Duration::from_secs(run.hold)).await;
    let (cpu, peak_cpu, rss, _) = meter.finish();
    let attached = context.stats.attached.load(Ordering::Relaxed);
    let per_bridge = idle.map_or(0.0, |idle| {
        (rss.saturating_sub(idle.rss)) as f64 / attached.max(1) as f64 / 1024.0
    });
    println!(
        "hold: {attached} attached; server cpu avg {cpu:.1}% peak {peak_cpu:.0}%, rss {:.0} MB, {per_bridge:.1} KB per bridge over the empty server; drops {}",
        mb(rss),
        context.stats.drops.load(Ordering::Relaxed)
    );

    // Visitors.
    if run.visitors > 0 {
        println!(
            "visitors: {} at once for {}s",
            run.visitors, run.visit_seconds
        );
        let meter = Meter::start(run.pid);
        let hello_config = client_config(false, &[b"h2", b"http/1.1"]);
        let deadline = Instant::now() + Duration::from_secs(run.visit_seconds);
        let loops: Vec<_> = (0..run.visitors)
            .map(|_| {
                let context = context.clone();
                let hello_config = hello_config.clone();
                tokio::spawn(async move {
                    while Instant::now() < deadline {
                        match tokio::time::timeout(
                            Duration::from_secs(10),
                            visit(&context, &hello_config),
                        )
                        .await
                        {
                            Ok(Ok(())) => {
                                context.stats.visits.fetch_add(1, Ordering::Relaxed);
                            }
                            Ok(Err(error)) => context.stats.visit_fail(format!("{error:#}")),
                            Err(_) => context.stats.visit_fail("timeout"),
                        }
                    }
                })
            })
            .collect();
        for task in loops {
            let _ = task.await;
        }
        let (cpu, peak_cpu, rss, _) = meter.finish();
        let visits = context.stats.visits.load(Ordering::Relaxed);
        let failures = std::mem::take(&mut *context.stats.visit_failures.lock().unwrap());
        println!(
            "visitors: {visits} connections ({:.0}/s), first byte ms {}, {}-byte round trip µs {}; server cpu avg {cpu:.0}% peak {peak_cpu:.0}%, rss {:.0} MB; failures: {failures:?}",
            visits as f64 / run.visit_seconds as f64,
            percentiles(&mut std::mem::take(
                &mut *context.stats.first_byte_ms.lock().unwrap()
            )),
            run.echo_bytes,
            percentiles(&mut std::mem::take(
                &mut *context.stats.round_trip_us.lock().unwrap()
            )),
            mb(rss),
        );
        if run.rest > 0 {
            tokio::time::sleep(Duration::from_secs(run.rest)).await;
            if let Some(rest) = sample(run.pid) {
                println!("visitors: {}s later, rss {:.0} MB", run.rest, mb(rest.rss));
            }
        }
    }

    // Storms.
    for round in 1..=run.storms {
        println!("storm {round}: dropping all {count} bridges");
        context.stats.attempts.store(0, Ordering::Relaxed);
        let meter = Meter::start(run.pid);
        context.storm.send_modify(|generation| *generation += 1);
        // Let every bridge notice before counting.
        while context.stats.attached.load(Ordering::Relaxed) > count / 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let drained = wait_attached(&context, count, timeout).await;
        let (cpu, peak_cpu, rss, peak_rss) = meter.finish();
        let attach_ms = percentiles(&mut std::mem::take(
            &mut *context.stats.attach_ms.lock().unwrap(),
        ));
        let attempts = context.stats.attempts.load(Ordering::Relaxed);
        match drained {
            Some(elapsed) => println!(
                "storm {round}: all attached again in {:.1}s, {attempts} attempts; attach ms {attach_ms}; server cpu avg {cpu:.0}% peak {peak_cpu:.0}%, rss {:.0} MB (peak {:.0}); failures: {}",
                elapsed.as_secs_f64(),
                mb(rss),
                mb(peak_rss),
                take_failures(&context)
            ),
            None => println!(
                "storm {round}: timed out with {} attached; failures: {}",
                context.stats.attached.load(Ordering::Relaxed),
                take_failures(&context)
            ),
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }

    context.stop.store(true, Ordering::Relaxed);
    Ok(())
}

async fn delay(listen: SocketAddr, target: SocketAddr, delay: Duration) -> Result<()> {
    async fn pipe(
        mut from: tokio::net::tcp::OwnedReadHalf,
        mut to: tokio::net::tcp::OwnedWriteHalf,
        delay: Duration,
    ) {
        let (tx, mut rx) =
            tokio::sync::mpsc::unbounded_channel::<(tokio::time::Instant, Vec<u8>)>();
        let writer = tokio::spawn(async move {
            while let Some((due, data)) = rx.recv().await {
                tokio::time::sleep_until(due).await;
                if to.write_all(&data).await.is_err() {
                    return;
                }
            }
            let _ = to.shutdown().await;
        });
        let mut buffer = vec![0u8; 64 * 1024];
        while let Ok(read) = from.read(&mut buffer).await {
            if read == 0 {
                break;
            }
            let due = tokio::time::Instant::now() + delay;
            if tx.send((due, buffer[..read].to_vec())).is_err() {
                break;
            }
        }
        drop(tx);
        let _ = writer.await;
    }
    let listener = tokio::net::TcpListener::bind(listen).await?;
    eprintln!("delaying {listen} -> {target} by {delay:?} each way");
    loop {
        let (client, _) = listener.accept().await?;
        tokio::spawn(async move {
            let Ok(server) = TcpStream::connect(target).await else {
                return;
            };
            let _ = (client.set_nodelay(true), server.set_nodelay(true));
            let (client_read, client_write) = client.into_split();
            let (server_read, server_write) = server.into_split();
            tokio::join!(
                pipe(client_read, server_write, delay),
                pipe(server_read, client_write, delay)
            );
        });
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    opentunnel_server::install_crypto_provider();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        match cli.command {
            Command::Seed {
                database_url,
                count,
                domain,
            } => seed(&database_url, count, &domain).await,
            Command::Run(options) => run(options).await,
            Command::Delay {
                listen,
                target,
                delay_ms,
            } => delay(listen, target, Duration::from_millis(delay_ms)).await,
        }
    })
}
