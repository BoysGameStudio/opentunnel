//! Limits on what one bridge or visitor may cost: frame and message sizes, buffered bytes, stalled visitors,
//! connections per bridge, and route lists.

mod common;

use std::time::{Duration, Instant};

use common::TestServer;
use futures_util::{SinkExt, StreamExt};
use opentunnel::protocol::bridge::{
    ClientInfo, ClientMessage, MAX_PAYLOAD_SIZE, ServerMessage, Transport, WEBSOCKET_SUBPROTOCOL,
};
use opentunnel::{Client, ClientOptions, Identity, Storage};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn open(server: &TestServer, id: &str) -> Socket {
    let url = format!(
        "{}/api/tunnel/{id}/connect",
        server.api.replace("http://", "ws://")
    );
    let mut request = url.into_client_request().unwrap();
    request.headers_mut().insert(
        "sec-websocket-protocol",
        WEBSOCKET_SUBPROTOCOL.parse().unwrap(),
    );
    let config = WebSocketConfig::default()
        .max_frame_size(Some(64 << 20))
        .max_message_size(Some(64 << 20));
    tokio_tungstenite::connect_async_with_config(request, Some(config), false)
        .await
        .unwrap()
        .0
}

fn attach_message(token: &str, routes: Vec<String>, max_conns: u32) -> Message {
    Message::text(
        serde_json::to_string(&ClientMessage::Attach {
            token: token.to_owned(),
            transport: Transport::Ws,
            routes,
            client: ClientInfo {
                version: "test".into(),
                max_conns,
            },
        })
        .unwrap(),
    )
}

/// What the server answered before closing: a close frame's code, or an attach error code.
async fn outcome(socket: &mut Socket) -> String {
    let read = async {
        while let Some(message) = socket.next().await {
            match message {
                Ok(Message::Close(Some(frame))) => return format!("{}", u16::from(frame.code)),
                Ok(Message::Close(None)) | Err(_) => return "closed".into(),
                Ok(Message::Text(text)) => match ServerMessage::decode(&text) {
                    Ok(Some(ServerMessage::AttachError { code })) => {
                        return format!("attach_error {code}");
                    }
                    Ok(Some(ServerMessage::Attached { .. })) => return "attached".into(),
                    _ => {}
                },
                Ok(_) => {}
            }
        }
        "closed".into()
    };
    tokio::time::timeout(Duration::from_secs(10), read)
        .await
        .unwrap_or_else(|_| "no answer within 10 s".into())
}

/// A bridge speaking the protocol directly, with its reads and writes in their own tasks so a server that
/// stops reading cannot stall the test.
struct Bridge {
    out: mpsc::Sender<Message>,
    events: mpsc::UnboundedReceiver<Message>,
    /// Every control message read so far.
    seen: Vec<ServerMessage>,
}

impl Bridge {
    async fn attach(server: &TestServer, identity: &Identity, max_conns: u32) -> Self {
        let mut socket = open(server, &identity.id).await;
        socket
            .send(attach_message(&identity.token, vec!["@".into()], max_conns))
            .await
            .unwrap();
        assert_eq!(outcome(&mut socket).await, "attached");
        let (mut sink, mut stream) = socket.split();
        let (out, mut outgoing) = mpsc::channel::<Message>(16);
        let (incoming, events) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(message) = outgoing.recv().await {
                if sink.send(message).await.is_err() {
                    return;
                }
            }
        });
        tokio::spawn(async move {
            while let Some(Ok(message)) = stream.next().await {
                if incoming.send(message).is_err() {
                    return;
                }
            }
        });
        Self {
            out,
            events,
            seen: Vec::new(),
        }
    }

    async fn control(&self, message: &ClientMessage) {
        let _ = self
            .out
            .send(Message::text(serde_json::to_string(message).unwrap()))
            .await;
    }

    async fn data(&self, conn: u32, payload: &[u8]) {
        let _ = self.out.send(frame(conn, payload)).await;
    }

    /// The next control message matching `want`, skipping everything else; `None` once the bridge closed or
    /// nothing matched within `timeout`.
    async fn wait<T>(
        &mut self,
        timeout: Duration,
        mut want: impl FnMut(&ServerMessage) -> Option<T>,
    ) -> Option<T> {
        tokio::time::timeout(timeout, async {
            while let Some(message) = self.events.recv().await {
                match message {
                    Message::Text(text) => {
                        if let Ok(Some(message)) = ServerMessage::decode(&text) {
                            let found = want(&message);
                            self.seen.push(message);
                            if found.is_some() {
                                return found;
                            }
                        }
                    }
                    Message::Close(_) => return None,
                    _ => {}
                }
            }
            None
        })
        .await
        .ok()
        .flatten()
    }

    async fn next_open(&mut self) -> Option<u32> {
        self.wait(Duration::from_secs(10), |message| match message {
            ServerMessage::Open { conn, .. } => Some(*conn),
            _ => None,
        })
        .await
    }

    /// Sends a ping and waits for its pong.
    async fn ping(&mut self, timeout: Duration) -> bool {
        let time_sent = 4242;
        self.control(&ClientMessage::Ping { time_sent }).await;
        self.wait(timeout, |message| {
            matches!(message, ServerMessage::Pong { time_sent: sent } if *sent == time_sent)
                .then_some(())
        })
        .await
        .is_some()
    }
}

fn frame(conn: u32, payload: &[u8]) -> Message {
    let mut frame = conn.to_be_bytes().to_vec();
    frame.extend_from_slice(payload);
    Message::binary(frame)
}

fn u16be(n: usize) -> [u8; 2] {
    [(n >> 8) as u8, n as u8]
}

/// A minimal ClientHello naming `sni`, in one TLS record.
fn client_hello(sni: &str) -> Vec<u8> {
    let name = sni.as_bytes();
    let mut names = vec![0u8];
    names.extend(u16be(name.len()));
    names.extend(name);
    let mut list = u16be(names.len()).to_vec();
    list.extend(names);
    let mut extensions = vec![0, 0];
    extensions.extend(u16be(list.len()));
    extensions.extend(list);
    let mut hello = vec![3, 3];
    hello.extend([0u8; 32]);
    hello.extend([0, 0, 2, 0x13, 1, 1, 0]);
    hello.extend(u16be(extensions.len()));
    hello.extend(extensions);
    let mut handshake = vec![1, 0];
    handshake.extend(u16be(hello.len()));
    handshake.extend(hello);
    let mut record = vec![0x16, 3, 1];
    record.extend(u16be(handshake.len()));
    record.extend(handshake);
    record
}

/// A visitor that sent its ClientHello. With `stalled`, its receive buffer is tiny and it never reads.
async fn visitor(server: &TestServer, identity: &Identity, stalled: bool) -> TcpStream {
    let socket = TcpSocket::new_v4().unwrap();
    if stalled {
        socket.set_recv_buffer_size(4096).unwrap();
    }
    let mut stream = socket.connect(server.tls).await.unwrap();
    stream
        .write_all(&client_hello(&identity.hostname))
        .await
        .unwrap();
    stream
}

async fn setup(dir: &std::path::Path) -> Option<(TestServer, Identity)> {
    let server = TestServer::start(dir, &[]).await?;
    let client = Client::new(ClientOptions {
        api: Some(server.api.parse().unwrap()),
        owner_token: Some(common::OWNER_TOKEN.into()),
        storage: Some(Storage::at(dir.join("client"))),
        ..Default::default()
    });
    let identity = client.create("default", |_| {}).await.unwrap();
    Some((server, identity))
}

#[tokio::test(flavor = "multi_thread")]
async fn frames_and_messages_are_limited() {
    let dir = tempfile::tempdir().unwrap();
    let Some((server, identity)) = setup(dir.path()).await else {
        return;
    };

    // Before attach, a message far larger than any attach is refused at once.
    let mut socket = open(&server, &identity.id).await;
    socket
        .send(Message::text(format!(
            r#"{{"type":"attach","token":"{}","pad":"{}"}}"#,
            identity.token,
            "x".repeat(100 * 1024)
        )))
        .await
        .unwrap();
    assert_eq!(outcome(&mut socket).await, "1009");

    // A data frame of the protocol's largest payload is carried; one byte more closes the bridge.
    let mut bridge = Bridge::attach(&server, &identity, 256).await;
    let mut visitor = visitor(&server, &identity, false).await;
    let conn = bridge.next_open().await.unwrap();
    bridge.data(conn, &vec![7u8; MAX_PAYLOAD_SIZE]).await;
    let mut received = vec![0u8; MAX_PAYLOAD_SIZE];
    tokio::time::timeout(Duration::from_secs(10), visitor.read_exact(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert!(bridge.ping(Duration::from_secs(5)).await);
    bridge.data(conn, &vec![7u8; MAX_PAYLOAD_SIZE + 1]).await;
    let closed = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(message) = bridge.events.recv().await {
            if let Message::Close(frame) = message {
                return frame.map(|frame| u16::from(frame.code));
            }
        }
        None
    })
    .await
    .unwrap();
    assert_eq!(closed, Some(1009));
}

#[tokio::test(flavor = "multi_thread")]
async fn route_lists_are_limited() {
    let dir = tempfile::tempdir().unwrap();
    let Some((server, identity)) = setup(dir.path()).await else {
        return;
    };
    let routes = |count: usize| -> Vec<String> { (0..count).map(|n| format!("r{n}")).collect() };

    // Far too many routes for any client: refused before any work on them, valid token or not.
    for token in [identity.token.as_str(), "bad"] {
        let mut socket = open(&server, &identity.id).await;
        let started = Instant::now();
        socket
            .send(attach_message(token, routes(5_000), 256))
            .await
            .unwrap();
        assert_eq!(outcome(&mut socket).await, "attach_error too_many_routes");
        assert!(started.elapsed() < Duration::from_secs(2));
    }
    // Larger than an attach can be: closed by the message limit.
    let mut socket = open(&server, &identity.id).await;
    socket
        .send(attach_message(&identity.token, routes(120_000), 256))
        .await
        .unwrap();
    assert_eq!(outcome(&mut socket).await, "1009");
    // A bad token is reported before the routes are looked at.
    let mut socket = open(&server, &identity.id).await;
    socket
        .send(attach_message("bad", routes(64), 256))
        .await
        .unwrap();
    assert_eq!(outcome(&mut socket).await, "attach_error bad_token");

    // At the limit, duplicates are folded and the attach succeeds.
    let mut many = routes(100);
    many.extend(routes(28));
    let mut socket = open(&server, &identity.id).await;
    socket
        .send(attach_message(&identity.token, many, 256))
        .await
        .unwrap();
    assert_eq!(outcome(&mut socket).await, "attached");

    // A tunnel's bridges share a limit too.
    let named = |prefix: &str, count: usize| -> Vec<String> {
        (0..count).map(|n| format!("{prefix}{n}")).collect()
    };
    let mut second = open(&server, &identity.id).await;
    second
        .send(attach_message(&identity.token, named("s", 128), 256))
        .await
        .unwrap();
    assert_eq!(outcome(&mut second).await, "attached");
    let mut third = open(&server, &identity.id).await;
    third
        .send(attach_message(&identity.token, named("t", 29), 256))
        .await
        .unwrap();
    assert_eq!(outcome(&mut third).await, "attach_error too_many_routes");
    drop((socket, second));
}

#[tokio::test(flavor = "multi_thread")]
async fn connections_per_bridge_are_limited() {
    let dir = tempfile::tempdir().unwrap();
    let Some((server, identity)) = setup(dir.path()).await else {
        return;
    };
    let mut bridge = Bridge::attach(&server, &identity, 3).await;
    let mut visitors = Vec::new();
    let mut opened = Vec::new();
    for _ in 0..3 {
        visitors.push(visitor(&server, &identity, false).await);
        opened.push(bridge.next_open().await.unwrap());
    }
    // Beyond the advertised `max_conns`, the visitor is closed and the client never hears of it.
    let mut extra = visitor(&server, &identity, false).await;
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(10), extra.read(&mut byte))
        .await
        .unwrap();
    assert!(matches!(read, Ok(0) | Err(_)));
    assert!(
        bridge
            .wait(Duration::from_millis(500), |message| matches!(
                message,
                ServerMessage::Open { .. }
            )
            .then_some(()))
            .await
            .is_none()
    );
    // Once one ends, there is room again.
    bridge
        .control(&ClientMessage::Reset {
            conn: opened[0],
            code: "upstream_io_error".into(),
        })
        .await;
    let mut freed = false;
    for _ in 0..50 {
        let _visitor = visitor(&server, &identity, false).await;
        if bridge
            .wait(Duration::from_millis(200), |message| {
                matches!(message, ServerMessage::Open { .. }).then_some(())
            })
            .await
            .is_some()
        {
            freed = true;
            break;
        }
    }
    assert!(freed, "a slot freed up");
}

/// The bytes this process holds in memory, from `/proc` (0 elsewhere).
fn resident() -> u64 {
    std::fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|statm| statm.split_whitespace().nth(1)?.parse::<u64>().ok())
        .map_or(0, |pages| pages * 4096)
}

/// Sends `bytes` to each of `conns` from a task, round robin, as the server may stop reading for a while.
fn flood(bridge: &Bridge, conns: &[u32], bytes: usize) {
    let out = bridge.out.clone();
    let conns = conns.to_vec();
    tokio::spawn(async move {
        let chunk = vec![1u8; MAX_PAYLOAD_SIZE];
        for _ in 0..bytes / MAX_PAYLOAD_SIZE {
            for conn in &conns {
                if out.send(frame(*conn, &chunk)).await.is_err() {
                    return;
                }
            }
        }
    });
}

/// Many visitors that stop reading hold a bounded number of bytes in the server (H1: before, 64 frames of up
/// to 1 MiB each per connection).
#[tokio::test(flavor = "multi_thread")]
async fn stalled_visitors_hold_bounded_memory() {
    let dir = tempfile::tempdir().unwrap();
    let Some((server, identity)) = setup(dir.path()).await else {
        return;
    };
    let mut bridge = Bridge::attach(&server, &identity, 256).await;
    let before = resident();
    let mut stalled = Vec::new();
    let mut conns = Vec::new();
    for _ in 0..32 {
        stalled.push(visitor(&server, &identity, true).await);
        conns.push(bridge.next_open().await.unwrap());
    }
    flood(&bridge, &conns, 8 << 20);
    let started = Instant::now();
    let mut peak_buffered = 0;
    let mut peak_resident = 0;
    while started.elapsed() < Duration::from_secs(4) {
        peak_buffered = peak_buffered.max(server.service().buffered_bytes());
        peak_resident = peak_resident.max(resident().saturating_sub(before));
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    eprintln!("peak buffered {peak_buffered} B, peak resident growth {peak_resident} B");
    // One bridge's budget (4 MiB), whatever the visitors do.
    assert!(peak_buffered <= 4 << 20, "buffered {peak_buffered}");
    assert!(bridge.ping(Duration::from_secs(30)).await, "ping answered");
    drop(stalled);
    common::eventually("buffers released", || async {
        server.service().buffered_bytes() == 0
    })
    .await;
}

/// Visitors that stop reading never keep the bridge from its pings or its other connections, and are reset on
/// their own (H2: before, each blocked the bridge reader for 30 s, and three took the tunnel offline).
#[tokio::test(flavor = "multi_thread")]
async fn stalled_visitors_cannot_take_the_bridge_down() {
    let dir = tempfile::tempdir().unwrap();
    let Some((server, identity)) = setup(dir.path()).await else {
        return;
    };
    let mut bridge = Bridge::attach(&server, &identity, 256).await;
    let mut stalled = Vec::new();
    let mut conns = Vec::new();
    for _ in 0..3 {
        stalled.push(visitor(&server, &identity, true).await);
        conns.push(bridge.next_open().await.unwrap());
    }
    // Far more than the kernel's buffers for each (4 MiB on Linux by default).
    flood(&bridge, &conns, 24 << 20);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let started = Instant::now();
    // A healthy visitor on the same bridge still gets its data, and pings are answered meanwhile.
    let mut healthy = visitor(&server, &identity, false).await;
    let conn = bridge.next_open().await.unwrap();
    bridge.data(conn, b"hello").await;
    assert!(bridge.ping(Duration::from_secs(15)).await, "ping answered");
    let mut hello = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(15), healthy.read_exact(&mut hello))
        .await
        .expect("healthy visitor served")
        .unwrap();
    assert_eq!(&hello, b"hello");
    // At most one wait for the stalled visitors (5 s) before they are reset together: well inside the client's
    // idle timeout (45 s). Before, 90 s.
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(15),
        "served after {elapsed:?}"
    );
    // The stalled ones were reset, without the bridge going away.
    let resets = |seen: &[ServerMessage]| -> Vec<u32> {
        seen.iter()
            .filter_map(|message| match message {
                ServerMessage::Reset { conn, .. } => Some(*conn),
                _ => None,
            })
            .collect()
    };
    while resets(&bridge.seen).len() < conns.len() {
        bridge
            .wait(Duration::from_secs(15), |message| {
                matches!(message, ServerMessage::Reset { .. }).then_some(())
            })
            .await
            .expect("stalled visitors reset");
    }
    let mut reset = resets(&bridge.seen);
    reset.sort_unstable();
    assert_eq!(reset, conns);
    assert!(bridge.ping(Duration::from_secs(5)).await);
    assert!(server.service().buffered_bytes() <= 4 << 20);
}

/// A visitor slower than the client but reading gets the whole download: the bridge waits for it instead of
/// resetting it.
#[tokio::test(flavor = "multi_thread")]
async fn slow_visitors_get_everything() {
    let dir = tempfile::tempdir().unwrap();
    let Some((server, identity)) = setup(dir.path()).await else {
        return;
    };
    let mut bridge = Bridge::attach(&server, &identity, 256).await;
    let mut slow = visitor(&server, &identity, true).await;
    let conn = bridge.next_open().await.unwrap();
    // More than the connection's budget and the kernel's send buffer (4 MiB), which the kernel only takes more
    // from once half of it is free: at this pace, after longer than the bridge waits for a stalled visitor.
    let total = 6 << 20;
    flood(&bridge, &[conn], total);
    // About 300 KB/s (8 KB reads), far slower than the bridge.
    let mut received = 0;
    let mut buffer = vec![0u8; 64 * 1024];
    while received < total {
        let read = tokio::time::timeout(Duration::from_secs(10), slow.read(&mut buffer))
            .await
            .expect("data keeps coming")
            .unwrap();
        assert!(read > 0, "closed after {received} bytes");
        received += read;
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(bridge.ping(Duration::from_secs(5)).await);
    assert!(
        !bridge
            .seen
            .iter()
            .any(|message| matches!(message, ServerMessage::Reset { .. }))
    );
}

/// An app that sends back everything it reads.
async fn echo_app() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut read, mut write) = socket.into_split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    address
}

/// The real Rust client keeps its bridge while a visitor uploads to an echo app and never reads the answers
/// (H2 as reproduced: the server's reader waited 30 s on the visitor, the client's send queue filled with the
/// echoes, its read loop then waited to queue a ping and stopped reading, and the server's write timeout closed
/// the bridge, every connection with it, within about 45 s, again and again).
#[tokio::test(flavor = "multi_thread")]
async fn real_client_survives_a_stalled_uploading_visitor() {
    let dir = tempfile::tempdir().unwrap();
    let Some((server, identity)) = setup(dir.path()).await else {
        return;
    };
    let client = Client::new(ClientOptions {
        api: Some(server.api.parse().unwrap()),
        owner_token: Some(common::OWNER_TOKEN.into()),
        storage: Some(Storage::at(dir.path().join("client"))),
        ..Default::default()
    });
    let echo = echo_app().await;
    let tunnel = client
        .connect(
            "default",
            [("@".to_owned(), echo.as_str().into())]
                .into_iter()
                .collect(),
        )
        .unwrap();
    common::eventually("the tunnel to connect", || async {
        tunnel.status().state == opentunnel::State::Connected
    })
    .await;
    let session = tunnel.status().session.clone();
    assert!(session.is_some());

    let socket = TcpSocket::new_v4().unwrap();
    socket.set_recv_buffer_size(4096).unwrap();
    let stream = socket.connect(server.tls).await.unwrap();
    let name = rustls_pki_types::ServerName::try_from(identity.hostname.clone()).unwrap();
    let tls = common::connector(&server.ca)
        .connect(name, stream)
        .await
        .unwrap();
    let (_read, mut write) = tokio::io::split(tls);
    let uploading = tokio::spawn(async move {
        let chunk = vec![5u8; 64 * 1024];
        let mut sent = 0usize;
        while sent < 256 << 20 {
            if write.write_all(&chunk).await.is_err() {
                return sent;
            }
            sent += chunk.len();
        }
        sent
    });

    // Past the server's write timeout (30 s) and the 45 s it took before.
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(60) {
        let status = tunnel.status();
        assert_eq!(
            status.state,
            opentunnel::State::Connected,
            "after {:?}",
            started.elapsed()
        );
        assert_eq!(
            status.session,
            session,
            "reconnected after {:?}",
            started.elapsed()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    // The stalled visitor was reset, not the tunnel.
    let sent = tokio::time::timeout(Duration::from_secs(5), uploading)
        .await
        .expect("the stalled visitor was reset")
        .unwrap();
    assert!(sent < 256 << 20);
    // Other visitors are served all along.
    let stream = TcpStream::connect(server.tls).await.unwrap();
    let name = rustls_pki_types::ServerName::try_from(identity.hostname.clone()).unwrap();
    let mut tls = common::connector(&server.ca)
        .connect(name, stream)
        .await
        .unwrap();
    tls.write_all(b"ping").await.unwrap();
    let mut answer = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(10), tls.read_exact(&mut answer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&answer, b"ping");
    assert_eq!(tunnel.status().session, session);
}
