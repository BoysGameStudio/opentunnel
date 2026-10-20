//! Public TCP: reads the ClientHello, then either terminates TLS for the API domain or carries the raw stream
//! over the tunnel's bridge without decrypting it.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{ReadHalf, WriteHalf};
use tokio::sync::watch;
use tracing::debug;

use crate::bridge::{PROGRESS, ServerControl, data_frame, data_message, hold_outbound, ticks};
use crate::cluster::{Cluster, FORWARD_ACCEPTED, FORWARD_REFUSED};
use crate::net::Activity;
use crate::proxy_protocol;
use crate::service::{Inbound, Outcome, Route, Service};
use crate::sni::{CLIENT_HELLO_LIMIT, Hello, HelloParser};

const CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PAYLOAD: usize = opentunnel::protocol::bridge::MAX_PAYLOAD_SIZE;

/// The start of a public connection, read before deciding where it goes.
pub struct Accepted {
    pub stream: TcpStream,
    /// The visitor, from the PROXY header when one was required.
    pub peer: SocketAddr,
    /// Everything read after the PROXY header, starting with the ClientHello.
    pub initial: Vec<u8>,
    pub sni: String,
    pub alpn: String,
}

/// Reads the optional PROXY header and the ClientHello, within the ClientHello timeout.
pub async fn accept(stream: TcpStream, peer: SocketAddr, proxy_protocol: bool) -> Result<Accepted> {
    accept_with(stream, peer, proxy_protocol, Vec::with_capacity(4096)).await
}

/// [`accept`], after `buffer` was already read from the stream.
pub async fn accept_with(
    mut stream: TcpStream,
    peer: SocketAddr,
    proxy_protocol: bool,
    mut buffer: Vec<u8>,
) -> Result<Accepted> {
    tokio::time::timeout(CLIENT_HELLO_TIMEOUT, async move {
        let mut peer = peer;
        let mut start = 0;
        if proxy_protocol {
            loop {
                match proxy_protocol::parse(&buffer) {
                    proxy_protocol::Header::Complete { length, source } => {
                        if let Some(source) = source {
                            peer = source;
                        }
                        start = length;
                        break;
                    }
                    proxy_protocol::Header::Invalid => bail!("invalid PROXY protocol header"),
                    proxy_protocol::Header::Incomplete => {
                        if buffer.len() > 536 || stream.read_buf(&mut buffer).await? == 0 {
                            bail!("connection closed before the PROXY header");
                        }
                    }
                }
            }
        }
        let mut parser = HelloParser::default();
        loop {
            match parser.parse(&buffer[start..]) {
                Hello::Complete { server_name, alpn } => {
                    buffer.drain(..start);
                    return Ok(Accepted {
                        stream,
                        peer,
                        initial: buffer,
                        sni: server_name,
                        alpn,
                    });
                }
                Hello::Invalid(reason) => bail!("{reason}"),
                Hello::Incomplete => {
                    if buffer.len() - start >= CLIENT_HELLO_LIMIT {
                        bail!("ClientHello exceeded inspection limit");
                    }
                    if stream.read_buf(&mut buffer).await? == 0 {
                        bail!("Connection closed before ClientHello");
                    }
                }
            }
        }
    })
    .await
    .unwrap_or_else(|_| bail!("ClientHello timeout"))
}

/// The tunnel ID in `<id>.<domain>` or `<route>.<id>.<domain>`.
pub fn tunnel_id(hostname: &str, domain: &str) -> Option<String> {
    let labels = hostname.strip_suffix(domain)?.strip_suffix('.')?;
    let labels: Vec<&str> = labels.split('.').collect();
    if labels.is_empty() || labels.len() > 2 {
        return None;
    }
    let id = *labels.last()?;
    (!id.is_empty()).then(|| id.to_owned())
}

/// The route in `<id>.<domain>` (`@`) or `<route>.<id>.<domain>`.
pub fn route_name(hostname: &str, id: &str, domain: &str) -> Option<String> {
    let labels = hostname.strip_suffix(domain)?.strip_suffix('.')?;
    if labels == id {
        return Some("@".into());
    }
    let route = labels.strip_suffix(id)?.strip_suffix('.')?;
    (!route.is_empty() && !route.contains('.')).then(|| route.to_owned())
}

/// What to do with a tunnel connection nothing serves here.
pub trait Fallback: Send + Sync {
    /// Takes the connection, or gives it back.
    fn forward(&self, accepted: Accepted) -> Option<Accepted>;
}

/// Where a tunnel connection came from.
#[derive(Clone, Copy)]
pub enum Origin<'a> {
    /// A visitor on the public port. Without a bridge here it goes to the machine holding one, then to the
    /// legacy fallback.
    Public {
        cluster: Option<&'a Arc<Cluster>>,
        fallback: Option<&'a Arc<dyn Fallback>>,
    },
    /// Forwarded by another machine, which waits for one byte: [`FORWARD_ACCEPTED`] before the stream, or
    /// [`FORWARD_REFUSED`]. Never forwarded again.
    Forwarded,
}

/// Carries a public connection to a tunnel client over its bridge, until both directions end or one side
/// aborts.
pub async fn route_tunnel(service: &Service, accepted: Accepted, origin: Origin<'_>) -> Result<()> {
    let started = service.now();
    let Some(id) = tunnel_id(&accepted.sni, &service.domain) else {
        crate::metrics::visitor("rejected_unknown_tunnel");
        bail!("SNI is not an OpenTunnel hostname");
    };
    let route = match Box::pin(service.route(&id, &accepted.sni)).await {
        Ok(route) => route,
        Err(error) => {
            crate::metrics::visitor("error");
            return Err(error);
        }
    };
    let (bridge, conn, tunnel_id, finish, mut abort, inbound, bytes_out, _slot) = match route {
        Route::Bridge {
            bridge,
            conn,
            tunnel_id,
            finish,
            abort,
            inbound,
            bytes_out,
            slot,
        } => (
            bridge, conn, tunnel_id, finish, abort, inbound, bytes_out, slot,
        ),
        Route::Rejected {
            tunnel_exists,
            outcome,
        } => {
            let (cluster, fallback) = match origin {
                Origin::Public { cluster, fallback } => (cluster, fallback),
                Origin::Forwarded => {
                    // The forwarding machine retries elsewhere or rejects it, and reports it.
                    let mut stream = accepted.stream;
                    let _ = stream.write_all(&[FORWARD_REFUSED]).await;
                    debug!(tunnel = %id, outcome, "forwarded connection refused");
                    return Ok(());
                }
            };
            let mut accepted = accepted;
            if outcome == "no_bridge"
                && tunnel_exists
                && let Some(cluster) = cluster
                && let Some(route) = route_name(&accepted.sni, &id, &service.domain)
            {
                match Box::pin(cluster.forward(accepted, &id, &route, service.timeouts())).await {
                    None => {
                        crate::metrics::visitor("forwarded_out");
                        return Ok(());
                    }
                    Some(returned) => accepted = returned,
                }
            }
            if outcome == "no_bridge"
                && let Some(fallback) = fallback
            {
                match fallback.forward(accepted) {
                    None => {
                        crate::metrics::visitor("legacy_relay");
                        return Ok(());
                    }
                    Some(returned) => {
                        return reject(service, &id, tunnel_exists, outcome, started, returned)
                            .await;
                    }
                }
            }
            return reject(service, &id, tunnel_exists, outcome, started, accepted).await;
        }
    };

    let Accepted {
        stream,
        peer,
        initial,
        sni,
        alpn,
    } = accepted;
    let mut stream = stream;
    if matches!(origin, Origin::Forwarded) && stream.write_all(&[FORWARD_ACCEPTED]).await.is_err() {
        bridge.channels.lock().expect("channels lock").remove(&conn);
        return Ok(());
    }
    crate::metrics::visitor(match origin {
        Origin::Public { .. } => "served_local",
        Origin::Forwarded => "forwarded_in",
    });
    let carried = std::time::Instant::now();
    let peer = peer.to_string();
    let _ = bridge
        .tx
        .send(
            ServerControl::Open {
                conn,
                peer: &peer,
                sni: &sni,
                alpn: &alpn,
            }
            .message(),
        )
        .await;
    for chunk in initial.chunks(MAX_PAYLOAD) {
        let _ = bridge.tx.send(data_frame(conn, chunk)).await;
    }
    let bytes_in = initial.len() as u64;

    let _ = stream.set_nodelay(true);
    crate::net::limit_unsent(&stream, UNSENT_LIMIT);
    let activity = Activity::default();
    let uploaded = AtomicU64::new(0);
    let (read, write) = stream.split();
    let upload = upload(
        read,
        &bridge,
        conn,
        &finish,
        abort.clone(),
        &activity,
        &uploaded,
    );
    let download = download(
        write,
        inbound,
        &bridge,
        conn,
        &finish,
        abort.clone(),
        &activity,
    );
    let idle = tokio::select! {
        _ = async { tokio::join!(upload, download) } => false,
        () = activity.expired(service.timeouts()) => true,
    };
    if idle {
        // Quiet for too long, or half-closed and the other side never ended: the visitor or the target is gone
        // without saying so.
        bridge.channels.lock().expect("channels lock").remove(&conn);
        let _ = bridge.tx.try_send(
            ServerControl::Reset {
                conn,
                code: "client_io_error",
            }
            .message(),
        );
        finish.finish(Outcome::ClientError, true);
        debug!(tunnel = %tunnel_id, conn, "idle tunnel connection closed");
    }
    if idle || *abort.borrow_and_update() {
        // Aborted: drop the socket with a reset rather than a clean close.
        let _ = stream.set_zero_linger();
    }
    bridge.channels.lock().expect("channels lock").remove(&conn);
    finish.finish(Outcome::Closed, false);
    crate::metrics::visitor_finished(
        carried.elapsed(),
        bytes_in + uploaded.load(Ordering::Relaxed),
        bytes_out.load(Ordering::Relaxed),
    );
    service.analytics.publish(
        "connection.closed",
        serde_json::json!({
            "tunnel_id": tunnel_id,
            "outcome": finish.outcome().unwrap_or(Outcome::Closed).as_str(),
            "duration_ms": service.now().saturating_sub(started),
            "bytes_in": bytes_in + uploaded.load(Ordering::Relaxed),
            "bytes_out": bytes_out.load(Ordering::Relaxed),
        }),
    );
    Ok(())
}

async fn reject(
    service: &Service,
    id: &str,
    tunnel_exists: bool,
    outcome: &str,
    started: u64,
    accepted: Accepted,
) -> Result<()> {
    crate::metrics::visitor(crate::metrics::rejected_outcome(tunnel_exists, outcome));
    if tunnel_exists {
        service.analytics.publish(
            "connection.closed",
            serde_json::json!({
                "tunnel_id": id,
                "outcome": outcome,
                "duration_ms": service.now().saturating_sub(started),
                "bytes_in": accepted.initial.len(),
                "bytes_out": 0,
            }),
        );
    }
    debug!(tunnel = %id, outcome, "public connection rejected");
    Ok(())
}

/// Visitor to tunnel client, counting the bytes read after the ClientHello in `total`.
async fn upload(
    mut read: ReadHalf<'_>,
    bridge: &crate::service::Bridge,
    conn: u32,
    finish: &crate::service::Finish,
    mut abort: watch::Receiver<bool>,
    activity: &Activity,
    total: &AtomicU64,
) {
    let mut buffer = vec![0u8; MAX_PAYLOAD];
    loop {
        let read = tokio::select! {
            read = read.read(&mut buffer) => read,
            _ = abort.wait_for(|aborted| *aborted) => return,
        };
        match read {
            Ok(0) => {
                activity.half_close();
                let _ = bridge.tx.send(ServerControl::End { conn }.message()).await;
                return;
            }
            Ok(read) => {
                total.fetch_add(read as u64, Ordering::Relaxed);
                activity.touch();
                // Waits while the bridge's or the machine's budget is spent: the backpressure on visitors.
                let sent = tokio::select! {
                    sent = async {
                        let held = hold_outbound(bridge, read).await?;
                        bridge.tx.send(data_message(conn, &buffer[..read], held)).await.ok()
                    } => sent.is_some(),
                    _ = abort.wait_for(|aborted| *aborted) => return,
                };
                if !sent {
                    finish.finish(Outcome::BridgeDisconnected, true);
                    return;
                }
            }
            Err(_) => {
                let _ = bridge.tx.try_send(
                    ServerControl::Reset {
                        conn,
                        code: "client_io_error",
                    }
                    .message(),
                );
                bridge.channels.lock().expect("channels lock").remove(&conn);
                finish.finish(Outcome::ClientError, true);
                return;
            }
        }
    }
}

/// Tunnel client to visitor, until the client ends its side.
async fn download(
    mut write: WriteHalf<'_>,
    mut inbound: tokio::sync::mpsc::UnboundedReceiver<Inbound>,
    bridge: &crate::service::Bridge,
    conn: u32,
    finish: &crate::service::Finish,
    mut abort: watch::Receiver<bool>,
    activity: &Activity,
) {
    loop {
        let item = tokio::select! {
            item = inbound.recv() => item,
            _ = abort.wait_for(|aborted| *aborted) => return,
        };
        match item {
            Some(Inbound::Data(data, held)) => {
                let written = tokio::select! {
                    written = write_watched(&mut write, &data, held.drained_at()) => written,
                    _ = abort.wait_for(|aborted| *aborted) => return,
                };
                // Its budget is given back once the visitor's socket took it.
                drop(held);
                if written.is_err() {
                    bridge.channels.lock().expect("channels lock").remove(&conn);
                    let _ = bridge.tx.try_send(
                        ServerControl::Reset {
                            conn,
                            code: "client_io_error",
                        }
                        .message(),
                    );
                    finish.finish(Outcome::ClientError, true);
                    return;
                }
                activity.touch();
            }
            Some(Inbound::End) | None => {
                activity.half_close();
                let _ = write.shutdown().await;
                return;
            }
        }
    }
}

/// Bytes a visitor's socket keeps unsent in the kernel ([`crate::net::limit_unsent`]).
const UNSENT_LIMIT: u32 = 128 * 1024;

/// How often a write that waits checks whether the visitor is reading.
const PROGRESS_CHECK: Duration = Duration::from_secs(1);

/// Writes `data` to the visitor. While the write waits, notes in `drained_at` each time the visitor acknowledged
/// another `PROGRESS` bytes: it is reading, only slower than the bridge, and must not be taken for stalled.
async fn write_watched(
    write: &mut WriteHalf<'_>,
    data: &[u8],
    drained_at: Option<&AtomicU64>,
) -> std::io::Result<()> {
    let Some(drained_at) = drained_at else {
        return write.write_all(data).await;
    };
    let socket = std::os::fd::AsRawFd::as_raw_fd(AsRef::<TcpStream>::as_ref(write));
    let writing = write.write_all(data);
    tokio::pin!(writing);
    let start = tokio::time::Instant::now() + PROGRESS_CHECK;
    let mut check = tokio::time::interval_at(start, PROGRESS_CHECK);
    check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut previous = None;
    let mut acked = 0;
    loop {
        tokio::select! {
            written = &mut writing => return written,
            _ = check.tick() => {
                let Some(queued) = crate::net::unacked(socket) else { continue };
                if let Some(previous) = previous
                    && queued < previous
                {
                    acked += previous - queued;
                }
                previous = Some(queued);
                if acked >= PROGRESS {
                    drained_at.store(ticks(), Ordering::Relaxed);
                    acked = 0;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_routes() {
        let domain = "opentunnel.xyz";
        assert_eq!(
            tunnel_id("api.abcdefghijkl.opentunnel.xyz", domain).as_deref(),
            Some("abcdefghijkl")
        );
        assert_eq!(
            route_name("abcdefghijkl.opentunnel.xyz", "abcdefghijkl", domain).as_deref(),
            Some("@")
        );
        assert_eq!(
            route_name("api.abcdefghijkl.opentunnel.xyz", "abcdefghijkl", domain).as_deref(),
            Some("api")
        );
        assert_eq!(
            route_name("a.b.abcdefghijkl.opentunnel.xyz", "abcdefghijkl", domain),
            None
        );
        assert_eq!(
            route_name("xabcdefghijkl.opentunnel.xyz", "abcdefghijkl", domain),
            None
        );
    }
}
