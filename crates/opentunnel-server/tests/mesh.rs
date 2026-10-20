//! The mesh on its own, without servers or a database: links between several machines, duplicate links, the
//! previous versions, bad secrets, the challenge never revealing the secret, and a table of 20,000 bridges under
//! churn.

use std::sync::Arc;
use std::time::{Duration, Instant};

use opentunnel_server::clock::Clock;
use opentunnel_server::mesh::{Event, MESH_MAGIC, MESH_MAGIC_V1, Mesh, MeshConfig, Notice};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

struct Node {
    mesh: Arc<Mesh>,
    address: String,
    notices: mpsc::UnboundedReceiver<Notice>,
}

fn config() -> MeshConfig {
    MeshConfig {
        ping: Duration::from_millis(200),
        dead: Duration::from_millis(1000),
        ..MeshConfig::default()
    }
}

/// A machine: a mesh behind its own internal listener, which only takes mesh links.
async fn node(name: &str, token: &str) -> Node {
    node_with(name, token, config()).await
}

async fn node_with(name: &str, token: &str, config: MeshConfig) -> Node {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let (mesh, notices) = Mesh::new(
        name.into(),
        "local".into(),
        token.into(),
        Clock::system(),
        config,
    );
    mesh.set_address(address.clone());
    let accepting = mesh.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, peer)) = listener.accept().await {
            let mesh = accepting.clone();
            tokio::spawn(async move {
                let mut line = Vec::new();
                let mut byte = [0u8; 1];
                while stream.read_exact(&mut byte).await.is_ok() && byte[0] != b'\n' {
                    line.push(byte[0]);
                }
                let stream = opentunnel_server::tls::Replay::new(Vec::new(), stream);
                if let Some(greeting) = line.strip_prefix(MESH_MAGIC) {
                    let greeting = String::from_utf8_lossy(greeting).into_owned();
                    let _ = mesh.accept(stream, &greeting, peer, ()).await;
                } else if let Some(token) = line.strip_prefix(MESH_MAGIC_V1) {
                    let token = String::from_utf8_lossy(token).into_owned();
                    let _ = mesh.accept_v1(stream, &token, peer, ()).await;
                }
            });
        }
    });
    tokio::spawn(mesh.clone().run());
    Node {
        mesh,
        address,
        notices,
    }
}

async fn wait(what: &str, limit: Duration, mut check: impl FnMut() -> bool) -> Duration {
    let started = Instant::now();
    while !check() {
        assert!(started.elapsed() < limit, "{what} took over {limit:?}");
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    started.elapsed()
}

fn size(node: &Node, machine: &str) -> Option<usize> {
    node.mesh
        .table_sizes()
        .into_iter()
        .find(|(id, _)| id == machine)
        .map(|(_, size)| size)
}

#[tokio::test(flavor = "multi_thread")]
async fn links_every_pair_once_and_replicates_the_table() {
    let nodes = [
        node("m1", "secret").await,
        node("m2", "secret").await,
        node("m3", "secret").await,
    ];
    // Everyone knows everyone, so both sides of each pair dial; one link per pair stays.
    for node in &nodes {
        for other in &nodes {
            if other.address != node.address {
                node.mesh.add_peer(&other.address);
            }
        }
    }
    wait("every link", Duration::from_secs(5), || {
        nodes.iter().all(|node| node.mesh.peers().len() == 2)
    })
    .await;
    // Through the duplicate-link delay: still exactly one link per pair, and stable.
    tokio::time::sleep(Duration::from_secs(3)).await;
    for node in &nodes {
        assert_eq!(node.mesh.peers().len(), 2);
        assert_eq!(node.mesh.view()["complete"], true);
    }
    assert!(!nodes[0].mesh.linked_v1("m2"));

    nodes[0]
        .mesh
        .attached("abcdefghijkl", 1, &["api".into(), "@".into()], 10);
    nodes[1]
        .mesh
        .attached("abcdefghijkl", 1, &["web".into()], 20);
    wait("the table to replicate", Duration::from_secs(1), || {
        nodes[2].mesh.locate("abcdefghijkl", "api", None).is_some()
            && nodes[2].mesh.locate("abcdefghijkl", "web", None).is_some()
    })
    .await;
    let located = nodes[2].mesh.locate("abcdefghijkl", "api", None).unwrap();
    assert_eq!(located.machine_id, "m1");
    assert_eq!(located.address, nodes[0].address);
    assert_eq!(
        nodes[2]
            .mesh
            .locate("abcdefghijkl", "web", None)
            .unwrap()
            .machine_id,
        "m2"
    );
    assert!(nodes[0].mesh.locate("abcdefghijkl", "api", None).is_none());
    // Two machines claiming one route: the newer attach wins, and the other is found when it is excluded.
    nodes[1]
        .mesh
        .attached("abcdefghijkl", 2, &["api".into()], 30);
    wait("the newer claim", Duration::from_secs(1), || {
        nodes[2]
            .mesh
            .locate("abcdefghijkl", "api", None)
            .is_some_and(|location| location.machine_id == "m2")
    })
    .await;
    assert_eq!(
        nodes[2]
            .mesh
            .locate("abcdefghijkl", "api", Some("m2"))
            .unwrap()
            .machine_id,
        "m1"
    );
    assert_eq!(nodes[2].mesh.holders("abcdefghijkl", &[]).len(), 2);
    nodes[1].mesh.detached("abcdefghijkl", 2);
    nodes[1].mesh.detached("abcdefghijkl", 1);
    wait("the detaches", Duration::from_secs(1), || {
        size(&nodes[2], "m2") == Some(0)
    })
    .await;

    // A leaving machine's bridges are dropped at once, and its later claims ignored.
    nodes[0].mesh.leave();
    wait(
        "the leaving machine to be dropped",
        Duration::from_secs(1),
        || nodes[2].mesh.locate("abcdefghijkl", "api", None).is_none(),
    )
    .await;
    nodes[0]
        .mesh
        .attached("abcdefghijkl", 3, &["late".into()], 40);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(nodes[2].mesh.locate("abcdefghijkl", "late", None).is_none());
    assert!(nodes[2].mesh.is_up("m1"));
    for node in &nodes {
        node.mesh.halt(false);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn events_reach_every_peer_and_a_new_link_is_announced() {
    let mut a = node("a", "secret").await;
    let mut b = node("b", "secret").await;
    a.mesh.add_peer(&b.address);
    wait("the link", Duration::from_secs(3), || b.mesh.is_up("a")).await;
    assert_eq!(a.notices.recv().await, Some(Notice::LinkUp));
    assert_eq!(b.notices.recv().await, Some(Notice::LinkUp));
    a.mesh.publish(Event::TunnelDeleted {
        tunnel: "gonetunnel00".into(),
    });
    a.mesh.publish(Event::JobEnqueued);
    let received = tokio::time::timeout(Duration::from_secs(1), b.notices.recv())
        .await
        .unwrap();
    assert_eq!(
        received,
        Some(Notice::Event(Event::TunnelDeleted {
            tunnel: "gonetunnel00".into()
        }))
    );
    assert_eq!(
        b.notices.recv().await,
        Some(Notice::Event(Event::JobEnqueued))
    );
    a.mesh.halt(false);
    b.mesh.halt(false);
}

#[tokio::test(flavor = "multi_thread")]
async fn refuses_a_peer_with_another_token_and_recognises_the_previous_version() {
    let a = node("a", "secret").await;
    let stranger = node("stranger", "other").await;
    a.mesh.add_peer(&stranger.address);
    stranger.mesh.add_peer(&a.address);
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(a.mesh.peers().is_empty());
    assert!(stranger.mesh.peers().is_empty());
    assert_eq!(a.mesh.view()["complete"], false);

    // The previous version's internal listener answers anything but a forward with HTTP.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let old = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let _ = stream
                .write_all(b"HTTP/1.1 400 Bad Request\r\nconnection: close\r\n\r\n")
                .await;
        }
    });
    a.mesh.add_peer(&old);
    wait(
        "the previous version to be recognised",
        Duration::from_secs(3),
        || a.mesh.view()["peers"]["legacy"] == 1,
    )
    .await;
    assert_eq!(a.mesh.view()["peers"]["legacy"], 1);
    a.mesh.halt(false);
    stranger.mesh.halt(false);
}

/// What a machine sends to whatever answers at a peer address never contains the secret, and an impostor that
/// does not hold it cannot complete the handshake either way.
#[tokio::test(flavor = "multi_thread")]
async fn the_challenge_never_reveals_the_secret() {
    const SECRET: &str = "the-shared-secret";
    let a = node("a", SECRET).await;
    // An impostor listening at a peer address: it records what it is sent and answers like a machine of this
    // version that does not know the secret.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let impostor = listener.local_addr().unwrap().to_string();
    let (seen_tx, mut seen) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let seen_tx = seen_tx.clone();
            tokio::spawn(async move {
                let mut received = vec![0u8; 512];
                let read = stream.read(&mut received).await.unwrap_or(0);
                received.truncate(read);
                let _ = stream
                    .write_all(
                        format!(
                            "OPENTUNNEL-MESH/2 impostor {} {}\n",
                            "ab".repeat(16),
                            "00".repeat(32)
                        )
                        .as_bytes(),
                    )
                    .await;
                let mut rest = Vec::new();
                let _ = tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut rest))
                    .await;
                received.extend_from_slice(&rest);
                let _ = seen_tx.send(received);
            });
        }
    });
    a.mesh.add_peer(&impostor);
    let received = tokio::time::timeout(Duration::from_secs(5), seen.recv())
        .await
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(&received);
    assert!(text.starts_with("OPENTUNNEL-MESH/2 a "), "{text}");
    assert!(!text.contains(SECRET), "{text}");
    // The impostor's proof was wrong: a sent nothing after its greeting, and has no peer.
    assert_eq!(text.lines().count(), 1, "{text}");
    assert!(a.mesh.peers().is_empty());

    // Dialing a: the answer proves nothing to an impostor and contains no secret; a wrong proof ends the link.
    let mut stream = tokio::net::TcpStream::connect(&a.address).await.unwrap();
    stream
        .write_all(format!("OPENTUNNEL-MESH/2 impostor {}\n", "cd".repeat(16)).as_bytes())
        .await
        .unwrap();
    let mut answer = vec![0u8; 512];
    let read = stream.read(&mut answer).await.unwrap();
    let answer = String::from_utf8_lossy(&answer[..read]).into_owned();
    assert!(answer.starts_with("OPENTUNNEL-MESH/2 a "), "{answer}");
    assert!(!answer.contains(SECRET));
    stream
        .write_all(format!("{}\n", "00".repeat(32)).as_bytes())
        .await
        .unwrap();
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut rest)).await;
    assert!(
        rest.is_empty(),
        "sent {:?} after a wrong proof",
        String::from_utf8_lossy(&rest)
    );
    assert!(a.mesh.peers().is_empty());
    a.mesh.halt(false);
}

/// TEMPORARY: a machine of the previous version greets with the secret itself. It is linked when the secret is
/// right (and answered with its own line), marked so forwards to it use its format, and refused otherwise or once
/// `accept_v1` is off.
#[tokio::test(flavor = "multi_thread")]
async fn accepts_the_previous_handshake_only_with_the_right_secret() {
    let a = node("a", "secret").await;
    for (token, accepted) in [("wrong", false), ("secret", true)] {
        let mut stream = tokio::net::TcpStream::connect(&a.address).await.unwrap();
        stream
            .write_all(format!("OPENTUNNEL-MESH/1 {token}\n").as_bytes())
            .await
            .unwrap();
        let mut answer = vec![0u8; 4096];
        let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut answer))
            .await
            .map_or(0, |read| read.unwrap_or(0));
        let answer = String::from_utf8_lossy(&answer[..read]).into_owned();
        if !accepted {
            assert!(answer.is_empty(), "{answer}");
            continue;
        }
        assert!(answer.starts_with("OPENTUNNEL-MESH/1 secret\n"), "{answer}");
        // Its hello, as the previous version sends it.
        let hello = serde_json::json!({
            "type": "hello", "version": 1, "machine_id": "old", "region": "local", "address": "127.0.0.1:1",
            "epoch": 1, "started_at": 1, "draining": false,
        });
        let body = serde_json::to_vec(&hello).unwrap();
        stream.write_u32(body.len() as u32).await.unwrap();
        stream.write_all(&body).await.unwrap();
        wait("the old machine to link", Duration::from_secs(2), || {
            a.mesh.is_up("old")
        })
        .await;
        assert!(a.mesh.linked_v1("old"));
        drop(stream);
    }
    a.mesh.halt(false);

    let strict = node_with(
        "strict",
        "secret",
        MeshConfig {
            accept_v1: false,
            ..config()
        },
    )
    .await;
    let mut stream = tokio::net::TcpStream::connect(&strict.address)
        .await
        .unwrap();
    stream
        .write_all(b"OPENTUNNEL-MESH/1 secret\n")
        .await
        .unwrap();
    let mut answer = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut answer)).await;
    assert!(answer.is_empty(), "{}", String::from_utf8_lossy(&answer));
    strict.mesh.halt(false);
}

/// A linked peer is held to what it proved: the address it connects from, its machine ID while another link
/// has it, and a sane clock.
#[tokio::test(flavor = "multi_thread")]
async fn peers_cannot_claim_other_addresses_ids_or_times() {
    let a = node("a", "secret").await;
    let b = node("b", "secret").await;
    // An authenticated machine that says it is somewhere else (forwards would go there).
    let liar = node("liar", "secret").await;
    liar.mesh.set_address_for_tests("127.0.0.9:9");
    liar.mesh.add_peer(&a.address);
    b.mesh.add_peer(&a.address);
    wait("b to link", Duration::from_secs(3), || a.mesh.is_up("b")).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!a.mesh.is_up("liar"));
    // A second machine calling itself b, at another address, does not take b's place.
    let impostor = node("b", "secret").await;
    impostor.mesh.add_peer(&a.address);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        a.mesh.peer_address("b").as_deref(),
        Some(b.address.as_str())
    );
    // An attach dated far in the future counts as now, so a later real attach still wins the route.
    b.mesh
        .attached("abcdefghijkl", 1, &["api".into()], u64::MAX);
    wait("the attach", Duration::from_secs(1), || {
        a.mesh.locate("abcdefghijkl", "api", None).is_some()
    })
    .await;
    let c = node("c", "secret").await;
    c.mesh.add_peer(&a.address);
    wait("c to link", Duration::from_secs(3), || a.mesh.is_up("c")).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    c.mesh.attached(
        "abcdefghijkl",
        1,
        &["api".into()],
        Clock::system().now_ms() + 1_000,
    );
    wait("the newer attach to win", Duration::from_secs(1), || {
        a.mesh
            .locate("abcdefghijkl", "api", None)
            .is_some_and(|location| location.machine_id == "c")
    })
    .await;
    for node in [&a, &b, &liar, &impostor, &c] {
        node.mesh.halt(false);
    }
}

/// 20,000 bridges, then 100 attaches and detaches per second for 10 seconds on one machine while another
/// follows: every change arrives, quickly, and memory stays modest. A third machine joining late gets the
/// whole table in one snapshot.
#[tokio::test(flavor = "multi_thread")]
async fn a_large_table_under_churn() {
    const BRIDGES: u64 = 20_000;
    // Snapshots of more than 64 KiB go out in several frames.
    let a = node_with(
        "a",
        "secret",
        MeshConfig {
            snapshot_chunk: 64 << 10,
            ..config()
        },
    )
    .await;
    let b = node("b", "secret").await;
    a.mesh.add_peer(&b.address);
    wait("the link", Duration::from_secs(3), || b.mesh.is_up("a")).await;
    let resident = || opentunnel_server::metrics::resident_memory().unwrap_or(0);
    let before = resident();

    let started = Instant::now();
    for bridge in 0..BRIDGES {
        let tunnel = format!("tunnel{bridge:06}");
        a.mesh
            .attached(&tunnel, bridge, &["@".into(), "api".into()], bridge);
    }
    let announced = started.elapsed();
    let took = wait("20,000 attaches to arrive", Duration::from_secs(10), || {
        size(&b, "a") == Some(BRIDGES as usize)
    })
    .await;
    eprintln!("20,000 attaches announced in {announced:?}, all applied after {took:?} more");

    // Churn: each tick detaches one bridge and attaches a new one, and measures how long until the peer
    // sees the new one.
    let mut latencies = Vec::new();
    let churn_started = Instant::now();
    let mut ticker = tokio::time::interval(Duration::from_millis(10));
    for round in 0..1000u64 {
        let next = BRIDGES + round;
        ticker.tick().await;
        let old = round * 7 % BRIDGES;
        a.mesh.detached(&format!("tunnel{old:06}"), old);
        let tunnel = format!("tunnel{next:06}");
        a.mesh.attached(&tunnel, next, &["@".into()], next);
        if round % 10 == 0 {
            let sent = Instant::now();
            while b.mesh.locate(&tunnel, "@", None).is_none() {
                assert!(
                    sent.elapsed() < Duration::from_secs(2),
                    "a change took over 2 s"
                );
                tokio::task::yield_now().await;
            }
            latencies.push(sent.elapsed());
        }
    }
    let churn = churn_started.elapsed();
    let last = format!("tunnel{:06}", BRIDGES + 999);
    wait("the churn to settle", Duration::from_secs(5), || {
        b.mesh.locate(&last, "@", None).is_some() && size(&b, "a") == size(&a, "a")
    })
    .await;
    latencies.sort();
    let p50 = latencies[latencies.len() / 2];
    let p99 = latencies[latencies.len() * 99 / 100];
    let max = *latencies.last().unwrap();
    eprintln!(
        "2,000 changes over {churn:?}: propagation p50 {p50:?}, p99 {p99:?}, max {max:?}; table {:?} here, {:?} there",
        size(&a, "a"),
        size(&b, "a")
    );
    assert_eq!(size(&b, "a"), Some(BRIDGES as usize));
    assert!(p99 < Duration::from_millis(100), "p99 {p99:?}");

    // A late joiner gets everything in one snapshot, in many frames.
    let c = node("c", "secret").await;
    let joined = Instant::now();
    c.mesh.add_peer(&a.address);
    a.mesh.add_peer(&c.address);
    let took = wait("the snapshot", Duration::from_secs(10), || {
        size(&c, "a") == size(&a, "a")
    })
    .await;
    eprintln!(
        "a snapshot of {:?} bridges applied {took:?} after the join was requested ({:?} total)",
        size(&c, "a"),
        joined.elapsed()
    );
    let grown = resident().saturating_sub(before);
    eprintln!(
        "resident memory grew by {} MiB for three copies of the table",
        grown >> 20
    );
    assert!(grown < 512 << 20, "memory grew by {grown} bytes");
    for node in [&a, &b, &c] {
        node.mesh.halt(false);
    }
}
