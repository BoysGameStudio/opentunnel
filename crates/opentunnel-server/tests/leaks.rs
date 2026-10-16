//! Public connections that never end on their own: every one must release its task and sockets.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::TestServer;
use futures_util::{SinkExt, StreamExt};
use opentunnel::protocol::bridge::{
    ClientInfo, ClientMessage, ServerMessage, Transport, WEBSOCKET_SUBPROTOCOL,
};
use opentunnel::{Client, ClientOptions, Storage};
use rustls_pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

const IDLE_MS: u64 = 2_000;
const HALF_CLOSE_MS: u64 = 600;
/// Visitors per scenario.
const VISITORS: usize = 40;

async fn machine(dir: &std::path::Path, name: &str, extra: &[&str]) -> Option<TestServer> {
    let mut args = vec![
        "--internal-listen=127.0.0.1:0".to_owned(),
        "--internal-token=cluster-secret".to_owned(),
        format!("--machine-id={name}"),
        "--mesh-dns=off".to_owned(),
        format!("--connection-idle-timeout-ms={IDLE_MS}"),
        format!("--half-close-timeout-ms={HALF_CLOSE_MS}"),
    ];
    args.extend(extra.iter().map(|arg| (*arg).to_owned()));
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    TestServer::start(dir, &args).await
}

/// What the harness bridge does with each public connection.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Behaviour {
    /// Never answers and never ends: a target that ignores the visitor's half-close.
    Hold,
    /// Ends its side at once and then ignores the connection: a target that closed while the visitor stays.
    End,
}

/// A bridge speaking the protocol directly, so the server's tasks and sockets can be counted alone.
struct Bridge {
    task: tokio::task::JoinHandle<()>,
    conns: Arc<Mutex<Vec<u32>>>,
}

impl Bridge {
    async fn attach(server: &TestServer, id: &str, token: &str, behaviour: Behaviour) -> Self {
        let url = format!(
            "{}/api/tunnel/{id}/connect",
            server.api.replace("http://", "ws://")
        );
        let mut request = url.into_client_request().unwrap();
        request.headers_mut().insert(
            "sec-websocket-protocol",
            WEBSOCKET_SUBPROTOCOL.parse().unwrap(),
        );
        let (mut socket, _) = tokio_tungstenite::connect_async(request).await.unwrap();
        let attach = ClientMessage::Attach {
            token: token.to_owned(),
            transport: Transport::Ws,
            routes: vec!["@".into()],
            client: ClientInfo {
                version: "test".into(),
                max_conns: 100_000,
            },
        };
        socket
            .send(Message::text(serde_json::to_string(&attach).unwrap()))
            .await
            .unwrap();
        loop {
            let Some(Ok(Message::Text(text))) = socket.next().await else {
                panic!("bridge closed before attach");
            };
            match ServerMessage::decode(&text).unwrap() {
                Some(ServerMessage::Attached { .. }) => break,
                Some(ServerMessage::AttachError { code }) => panic!("attach failed: {code}"),
                _ => {}
            }
        }
        let conns = Arc::new(Mutex::new(Vec::new()));
        let seen = conns.clone();
        let task = tokio::spawn(async move {
            let mut ping = tokio::time::interval(Duration::from_secs(5));
            loop {
                tokio::select! {
                    message = socket.next() => {
                        let Some(Ok(message)) = message else { return };
                        let Message::Text(text) = message else { continue };
                        match ServerMessage::decode(&text) {
                            Ok(Some(ServerMessage::Open { conn, .. })) => {
                                seen.lock().await.push(conn);
                                if behaviour == Behaviour::End {
                                    let end = ClientMessage::End { conn };
                                    let _ = socket.send(Message::text(serde_json::to_string(&end).unwrap())).await;
                                }
                            }
                            Ok(Some(ServerMessage::Ping { time_sent })) => {
                                let pong = ClientMessage::Pong { time_sent };
                                let _ = socket.send(Message::text(serde_json::to_string(&pong).unwrap())).await;
                            }
                            _ => {}
                        }
                    }
                    _ = ping.tick() => {
                        let message = ClientMessage::Ping { time_sent: 1 };
                        let _ = socket.send(Message::text(serde_json::to_string(&message).unwrap())).await;
                    }
                }
            }
        });
        Self { task, conns }
    }

    async fn opened(&self) -> usize {
        self.conns.lock().await.len()
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The first flight of a TLS connection to `sni`.
fn client_hello(sni: &str) -> Vec<u8> {
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
    let name = ServerName::try_from(sni.to_owned()).unwrap();
    let mut connection = rustls::ClientConnection::new(Arc::new(config), name).unwrap();
    let mut hello = Vec::new();
    while connection.wants_write() {
        connection.write_tls(&mut hello).unwrap();
    }
    hello
}

fn tasks() -> usize {
    tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks()
}

fn fds() -> usize {
    std::fs::read_dir("/proc/self/fd").map_or(0, Iterator::count)
}

async fn provision(server: &TestServer, dir: &std::path::Path) -> (String, String, String) {
    let client = Client::new(ClientOptions {
        api: Some(server.api.parse().unwrap()),
        storage: Some(Storage::at(dir.join("client"))),
        ..Default::default()
    });
    let identity = client.create("default", |_| {}).await.unwrap();
    (identity.id, identity.token, identity.hostname)
}

/// Waits until the process is back to `baseline` tasks and descriptors (plus `held` sockets the test keeps).
async fn settles(what: &str, baseline: (usize, usize), held: usize, within: Duration) {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let (now_tasks, now_fds) = (tasks(), fds());
        // Slack for background work (bridge close timers, database and HTTP pools growing), far below one
        // descriptor per visitor.
        if now_tasks <= baseline.0 + 3 && now_fds <= baseline.1 + held + 10 {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "{what}: {now_tasks} tasks and {now_fds} descriptors, baseline {} and {} (+{held} held)",
                baseline.0, baseline.1
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Connects `VISITORS` visitors to `server` and sends each the ClientHello.
async fn visitors(at: std::net::SocketAddr, hello: &[u8]) -> Vec<TcpStream> {
    let mut visitors = Vec::new();
    for _ in 0..VISITORS {
        let mut visitor = TcpStream::connect(at).await.unwrap();
        visitor.write_all(hello).await.unwrap();
        visitors.push(visitor);
    }
    visitors
}

/// Whether the server closed or reset the visitor's connection.
async fn closed(visitor: &mut TcpStream, within: Duration) -> bool {
    let mut buffer = [0u8; 64];
    loop {
        match tokio::time::timeout(within, visitor.read(&mut buffer)).await {
            Err(_) => return false,
            Ok(Ok(0) | Err(_)) => return true,
            Ok(Ok(_)) => {}
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn connections_whose_peers_vanish_are_released() {
    let dir = tempfile::tempdir().unwrap();
    let Some(a) = machine(dir.path(), "machine-a", &[]).await else {
        return;
    };
    let b = machine(dir.path(), "machine-b", &[]).await.unwrap();
    common::link(&[&a, &b]).await;
    let (id, token, host) = provision(&a, dir.path()).await;
    let hello = client_hello(&host);
    let quickly = Duration::from_millis(IDLE_MS * 3);

    // The target never ends its side. Visitors close after the ClientHello, locally and through B: once
    // half-closed, the connection must not wait for the target forever.
    let bridge = Bridge::attach(&a, &id, &token, Behaviour::Hold).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let baseline = (tasks(), fds());
    drop(visitors(a.tls, &hello).await);
    drop(visitors(b.tls, &hello).await);
    common::eventually("the bridge to see every visitor", || async {
        bridge.opened().await == 2 * VISITORS
    })
    .await;
    settles("visitors that closed", baseline, 0, quickly).await;

    // Visitors that stay connected but say nothing, with a target that says nothing: the idle timeout.
    let mut held = visitors(a.tls, &hello).await;
    held.extend(visitors(b.tls, &hello).await);
    tokio::time::sleep(Duration::from_millis(IDLE_MS / 2)).await;
    for visitor in &mut held {
        assert!(!closed(visitor, Duration::from_millis(10)).await);
    }
    for visitor in &mut held {
        assert!(
            closed(visitor, quickly).await,
            "an idle connection stayed open"
        );
    }
    settles("idle visitors", baseline, held.len(), quickly).await;
    drop(held);

    // A visitor that keeps sending is never idle.
    let mut busy = TcpStream::connect(b.tls).await.unwrap();
    busy.write_all(&hello).await.unwrap();
    for _ in 0..(3 * IDLE_MS / 250) {
        tokio::time::sleep(Duration::from_millis(250)).await;
        busy.write_all(b"x").await.unwrap();
    }
    assert!(!closed(&mut busy, Duration::from_millis(100)).await);
    drop(busy);
    settles("a busy visitor that closed", baseline, 0, quickly).await;

    // The bridge goes away while connections are open: they end with it.
    let held = visitors(a.tls, &hello).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    drop(bridge);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let baseline = (tasks(), fds());
    drop(held);
    settles("visitors of a bridge that went away", baseline, 0, quickly).await;

    // The target ends at once; visitors read the half-close but never close: the half-close timeout.
    let bridge = Bridge::attach(&a, &id, &token, Behaviour::End).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let baseline = (tasks(), fds());
    let mut held = visitors(a.tls, &hello).await;
    held.extend(visitors(b.tls, &hello).await);
    for visitor in &mut held {
        assert!(
            closed(visitor, quickly).await,
            "the target's end did not arrive"
        );
    }
    settles("visitors that never close", baseline, held.len(), quickly).await;
    drop(held);
    // The channels the target ended are gone too, so its bridge closing later finds nothing.
    drop(bridge);

    // A ClientHello that never completes, and visitors for an unknown tunnel.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let baseline = (tasks(), fds());
    let partial = visitors(a.tls, &hello[..20]).await;
    let unknown = visitors(b.tls, &client_hello("nosuchtunnel.opentunnel.test")).await;
    settles(
        "partial ClientHellos",
        baseline,
        partial.len() + unknown.len(),
        Duration::from_secs(15),
    )
    .await;
}
