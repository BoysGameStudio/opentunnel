//! Several servers on one database, as machines in several regions, linked by the mesh: visitors reach a bridge
//! attached to another machine as soon as it attached, detaches, deletes and route conflicts cross machines, a
//! machine that crashes, freezes, restarts or is cut off is handled, changes reach other machines' caches at
//! once, a deploy from the previous version keeps forwarding, and background jobs run once.

mod common;

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use common::{TestServer, app, eventually, link};
use opentunnel::protocol::api::{CertificateInfo, CertificateState};
use opentunnel::{Client, ClientOptions, Routes, State, Storage};
use opentunnel_server::clock::iso;
use opentunnel_server::crypto::hash_token;
use opentunnel_server::issuer::Issuer;
use opentunnel_server::service::Route;
use opentunnel_server::store::{BridgeLocation, Job, JobKind};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Fast pings, so a silent peer is down after a second.
const FAST: &[&str] = &["--mesh-ping-ms=200", "--mesh-dead-ms=1000"];

async fn machine_with(
    dir: &std::path::Path,
    name: &str,
    region: &str,
    extra: &[&str],
) -> Option<TestServer> {
    let mut args = vec![
        "--internal-listen=127.0.0.1:0".to_owned(),
        "--internal-token=cluster-secret".to_owned(),
        format!("--machine-id={name}"),
        format!("--region={region}"),
        "--mesh-dns=off".to_owned(),
    ];
    args.extend(extra.iter().map(|arg| (*arg).to_owned()));
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    TestServer::start(dir, &args).await
}

async fn machine(dir: &std::path::Path, name: &str, region: &str) -> Option<TestServer> {
    machine_with(dir, name, region, FAST).await
}

fn client(server: &TestServer, storage: &std::path::Path) -> Client {
    Client::new(ClientOptions {
        api: Some(server.api.parse().unwrap()),
        storage: Some(Storage::at(storage)),
        ..Default::default()
    })
}

fn routes(pairs: &[(&str, &str)]) -> Routes {
    pairs
        .iter()
        .map(|(name, target)| ((*name).to_owned(), (*target).into()))
        .collect()
}

async fn connected(tunnel: &opentunnel::Tunnel) {
    eventually("the tunnel to connect", || async {
        tunnel.status().state == State::Connected
    })
    .await;
}

async fn stats(server: &TestServer) -> serde_json::Value {
    reqwest::Client::new()
        .post(format!("{}/api/admin/stats", server.api))
        .bearer_auth("admin-secret")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// Bridges `machine` holds in `server`'s mesh table, if it knows the machine.
fn table(server: &TestServer, machine: &str) -> Option<usize> {
    server
        .mesh()
        .table_sizes()
        .into_iter()
        .find(|(id, _)| id == machine)
        .map(|(_, size)| size)
}

/// Waits until `check` holds, failing after `within`, and returns how long it took.
async fn within<F, Fut>(what: &str, within: Duration, mut check: F) -> Duration
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let started = Instant::now();
    while !check().await {
        assert!(started.elapsed() < within, "{what} took over {within:?}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let took = started.elapsed();
    eprintln!("{what}: {took:?}");
    took
}

#[tokio::test(flavor = "multi_thread")]
async fn forwards_visitors_and_control_between_machines() {
    let dir = tempfile::tempdir().unwrap();
    let Some(a) = machine(dir.path(), "machine-a", "iad").await else {
        return;
    };
    let b = machine(dir.path(), "machine-b", "syd").await.unwrap();
    link(&[&a, &b]).await;

    // The client attaches to A; a visitor arrives at B right after, without waiting for anything.
    let storage = dir.path().join("client");
    let on_a = client(&a, &storage);
    let identity = on_a.create("default", |_| {}).await.unwrap();
    let host = identity.hostname.clone();
    let api = app("from the client on a").await;
    let tunnel = on_a.connect("default", routes(&[("api", &api)])).unwrap();
    connected(&tunnel).await;
    let response = b.visit(&format!("api.{host}"), "/").await.unwrap();
    assert!(response.ends_with("from the client on a"), "{response}");
    for _ in 0..2 {
        let response = b.visit(&format!("api.{host}"), "/").await.unwrap();
        assert!(response.ends_with("from the client on a"), "{response}");
    }
    assert_eq!(b.server.app.stats.forwarded_out.load(Ordering::Relaxed), 3);
    assert_eq!(a.server.app.stats.forwarded_in.load(Ordering::Relaxed), 3);
    // A route nobody serves is refused on both, and never loops.
    assert!(b.visit(&host, "/").await.is_err());

    // B reports the tunnel online and both machines in its stats.
    let on_b = client(&b, &storage);
    let info = on_b.api().get(&identity.token, &identity.id).await.unwrap();
    assert_eq!(info.state, opentunnel::protocol::api::TunnelState::Online);
    let report = stats(&b).await;
    assert_eq!(report["machine"]["id"], "machine-b");
    assert_eq!(report["machine"]["forwarded_out"], 3);
    assert_eq!(report["cluster"]["bridges"], 1);
    assert_eq!(report["cluster"]["regions"]["iad"], 1);
    assert_eq!(report["cluster"]["regions"]["syd"], 0);
    assert_eq!(report["cluster"]["machines"][0]["machine_id"], "machine-a");
    assert_eq!(report["cluster"]["machines"][0]["link"], "up");
    assert_eq!(report["cluster"]["machines"][1]["link"], "self");
    assert_eq!(report["cluster"]["peers"]["up"], 1);
    assert_eq!(report["cluster"]["complete"], true);

    // Routes are exclusive across machines: a second client on B cannot take `api`, but can serve `web`,
    // which visitors arriving at A then reach.
    let web = app("from the client on b").await;
    let conflicting = on_b.connect("default", routes(&[("api", &web)])).unwrap();
    eventually("route_conflict", || async {
        conflicting
            .status()
            .last_error
            .is_some_and(|error| error.contains("route_conflict"))
    })
    .await;
    conflicting.close().await.unwrap();
    let second = on_b
        .connect("default", routes(&[("web", &web), ("@", &web)]))
        .unwrap();
    connected(&second).await;
    let response = a.visit(&format!("web.{host}"), "/").await.unwrap();
    assert!(response.ends_with("from the client on b"), "{response}");
    let response = a.visit(&host, "/").await.unwrap();
    assert!(response.ends_with("from the client on b"), "{response}");
    let response = b.visit(&format!("api.{host}"), "/").await.unwrap();
    assert!(response.ends_with("from the client on a"), "{response}");

    // Once A's client goes, B knows at once and refuses `api`.
    tunnel.close().await.unwrap();
    let took = within("B to drop A's route", Duration::from_secs(2), || async {
        b.mesh().locate(&identity.id, "api", None).is_none()
    })
    .await;
    assert!(took < Duration::from_secs(1));
    assert!(b.visit(&format!("api.{host}"), "/").await.is_err());
    let tunnel = on_a.connect("default", routes(&[("api", &api)])).unwrap();
    connected(&tunnel).await;

    // Deleting through B closes the bridges on A too.
    on_b.remove("default").await.unwrap();
    within("A's bridge to close", Duration::from_secs(5), || async {
        tunnel.status().state != State::Connected
    })
    .await;
    eventually("B's bridge to close", || async {
        second.status().state != State::Connected
    })
    .await;
    assert!(b.visit(&format!("api.{host}"), "/").await.is_err());
    assert!(a.visit(&format!("api.{host}"), "/").await.is_err());
    eventually("the tables to empty", || async {
        stats(&b).await["cluster"]["bridges"] == 0
    })
    .await;
    a.stop().await;
    b.stop().await;
}

/// A machine that freezes (its links stay open but carry nothing) is dropped once its pings stop, after the
/// default five seconds; its clients then attach elsewhere.
#[tokio::test(flavor = "multi_thread")]
async fn drops_a_machine_that_goes_silent() {
    let dir = tempfile::tempdir().unwrap();
    let Some(a) = machine_with(dir.path(), "machine-a", "iad", &[]).await else {
        return;
    };
    let b = machine_with(dir.path(), "machine-b", "fra", &[])
        .await
        .unwrap();
    link(&[&a, &b]).await;
    let on_a = client(&a, &dir.path().join("client"));
    let identity = on_a.create("default", |_| {}).await.unwrap();
    let api = app("before the freeze").await;
    let tunnel = on_a.connect("default", routes(&[("api", &api)])).unwrap();
    connected(&tunnel).await;
    let sni = format!("api.{}", identity.hostname);
    assert!(
        b.visit(&sni, "/")
            .await
            .unwrap()
            .ends_with("before the freeze")
    );

    a.freeze();
    let took = within(
        "B to drop the frozen machine",
        Duration::from_secs(8),
        || async { !b.mesh().is_up("machine-a") },
    )
    .await;
    assert!(took > Duration::from_secs(3), "dropped after {took:?}");
    assert!(b.mesh().locate(&identity.id, "api", None).is_none());
    // No forward is even tried: the visitor is closed at once.
    let failures = b.server.app.stats.forward_failures.load(Ordering::Relaxed);
    let started = Instant::now();
    assert!(b.visit(&sni, "/").await.is_err());
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(
        b.server.app.stats.forward_failures.load(Ordering::Relaxed),
        failures
    );

    // The client moves to B, which accepts its routes (the frozen machine does not count) and serves them.
    let on_b = client(&b, &dir.path().join("client"));
    let moved = on_b.connect("default", routes(&[("api", &api)])).unwrap();
    connected(&moved).await;
    assert!(
        b.visit(&sni, "/")
            .await
            .unwrap()
            .ends_with("before the freeze")
    );
    drop(tunnel);
    b.stop().await;
}

/// A machine that crashes closes its links, so peers drop it at once and stop forwarding there.
#[tokio::test(flavor = "multi_thread")]
async fn drops_a_machine_that_crashed_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let Some(a) = machine(dir.path(), "machine-a", "iad").await else {
        return;
    };
    let b = machine(dir.path(), "machine-b", "fra").await.unwrap();
    link(&[&a, &b]).await;
    let on_a = client(&a, &dir.path().join("client"));
    let identity = on_a.create("default", |_| {}).await.unwrap();
    let api = app("x").await;
    let tunnel = on_a.connect("default", routes(&[("api", &api)])).unwrap();
    connected(&tunnel).await;
    let sni = format!("api.{}", identity.hostname);
    within("B to know the bridge", Duration::from_secs(1), || async {
        b.mesh().locate(&identity.id, "api", None).is_some()
    })
    .await;
    a.crash();
    let took = within(
        "B to drop the crashed machine",
        Duration::from_secs(2),
        || async { !b.mesh().is_up("machine-a") },
    )
    .await;
    assert!(took < Duration::from_millis(500));
    assert!(b.visit(&sni, "/").await.is_err());
    drop(tunnel);
    b.stop().await;
}

/// A machine that restarts while its old process is still linked (frozen) replaces its old life's entries at
/// once: the new epoch wins without waiting for the old link to time out.
#[tokio::test(flavor = "multi_thread")]
async fn a_restarted_machine_replaces_its_old_entries() {
    let dir = tempfile::tempdir().unwrap();
    let Some(a) = machine_with(dir.path(), "machine-a", "iad", &[]).await else {
        return;
    };
    let b = machine_with(dir.path(), "machine-b", "fra", &[])
        .await
        .unwrap();
    link(&[&a, &b]).await;
    let on_a = client(&a, &dir.path().join("client"));
    let identity = on_a.create("default", |_| {}).await.unwrap();
    let api = app("x").await;
    let tunnel = on_a.connect("default", routes(&[("api", &api)])).unwrap();
    connected(&tunnel).await;
    within("B to know the bridge", Duration::from_secs(1), || async {
        table(&b, "machine-a") == Some(1)
    })
    .await;
    let old_epoch = a.mesh().epoch;
    a.freeze();
    drop(tunnel);

    let restarted = machine_with(dir.path(), "machine-a", "iad", &[])
        .await
        .unwrap();
    assert_ne!(restarted.mesh().epoch, old_epoch);
    restarted.mesh().add_peer(&b.internal());
    let took = within(
        "B to replace the old life's entries",
        Duration::from_secs(3),
        || async { table(&b, "machine-a") == Some(0) },
    )
    .await;
    assert!(took < Duration::from_secs(3));
    assert!(b.mesh().locate(&identity.id, "api", None).is_none());
    let view = b.mesh().view();
    let machine = view["machines"]
        .as_array()
        .unwrap()
        .iter()
        .find(|machine| machine["machine_id"] == "machine-a")
        .unwrap()
        .clone();
    assert_eq!(machine["epoch"], restarted.mesh().epoch.to_string());
    assert_eq!(stats(&restarted).await["cluster"]["bridges"], 0);
    restarted.stop().await;
    b.stop().await;
}

/// Cut a link: each side keeps serving its own bridges and refuses visitors for the other's at once. What
/// happened meanwhile (a bridge attached, a tunnel deleted) is caught up when the link heals: the table from
/// the snapshot, the deletion from the check every new link triggers.
#[tokio::test(flavor = "multi_thread")]
async fn tables_reconverge_after_a_partition() {
    let dir = tempfile::tempdir().unwrap();
    let Some(a) = machine(dir.path(), "machine-a", "iad").await else {
        return;
    };
    let b = machine(dir.path(), "machine-b", "syd").await.unwrap();
    link(&[&a, &b]).await;
    let first_client = client(&a, &dir.path().join("first"));
    let first = first_client.create("default", |_| {}).await.unwrap();
    let api = app("first").await;
    let first_tunnel = first_client
        .connect("default", routes(&[("api", &api)]))
        .unwrap();
    connected(&first_tunnel).await;
    let first_sni = format!("api.{}", first.hostname);
    assert!(b.visit(&first_sni, "/").await.unwrap().ends_with("first"));

    a.mesh().partition("machine-b", true);
    within(
        "both sides to drop the link",
        Duration::from_secs(2),
        || async { !a.mesh().is_up("machine-b") && !b.mesh().is_up("machine-a") },
    )
    .await;
    let started = Instant::now();
    assert!(b.visit(&first_sni, "/").await.is_err());
    assert!(started.elapsed() < Duration::from_secs(1));
    // A still serves its own bridge.
    assert!(a.visit(&first_sni, "/").await.unwrap().ends_with("first"));

    // Meanwhile: a second tunnel attaches to A, and the first is deleted through B.
    let second_client = client(&a, &dir.path().join("second"));
    let second = second_client.create("default", |_| {}).await.unwrap();
    let web = app("second").await;
    let second_tunnel = second_client
        .connect("default", routes(&[("web", &web)]))
        .unwrap();
    connected(&second_tunnel).await;
    client(&b, &dir.path().join("first"))
        .remove("default")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(first_tunnel.status().state, State::Connected);
    assert!(b.mesh().locate(&second.id, "web", None).is_none());

    a.mesh().partition("machine-b", false);
    let took = within(
        "the tables to reconverge",
        Duration::from_secs(10),
        || async {
            b.mesh().locate(&second.id, "web", None).is_some()
                && a.mesh().is_up("machine-b")
                && table(&b, "machine-a") == table(&a, "machine-a")
        },
    )
    .await;
    eprintln!("healed after {took:?}");
    within(
        "the deleted tunnel's bridge to close",
        Duration::from_secs(5),
        || async { first_tunnel.status().state != State::Connected },
    )
    .await;
    let second_sni = format!("web.{}", second.hostname);
    assert!(b.visit(&second_sni, "/").await.unwrap().ends_with("second"));
    a.stop().await;
    b.stop().await;
}

/// Two machines in one region hold different routes of one tunnel; a third machine sends each visitor to the
/// right one, and each sends the other's visitors across.
#[tokio::test(flavor = "multi_thread")]
async fn machines_in_one_region_hold_different_routes() {
    let dir = tempfile::tempdir().unwrap();
    let Some(a) = machine(dir.path(), "machine-a", "iad").await else {
        return;
    };
    let b = machine(dir.path(), "machine-b", "iad").await.unwrap();
    let c = machine(dir.path(), "machine-c", "fra").await.unwrap();
    link(&[&a, &b, &c]).await;
    let storage = dir.path().join("client");
    let on_a = client(&a, &storage);
    let identity = on_a.create("default", |_| {}).await.unwrap();
    let api = app("api on a").await;
    let web = app("web on b").await;
    let on_api = on_a.connect("default", routes(&[("api", &api)])).unwrap();
    let on_web = client(&b, &storage)
        .connect("default", routes(&[("web", &web)]))
        .unwrap();
    connected(&on_api).await;
    connected(&on_web).await;
    let host = &identity.hostname;
    for (server, route, body) in [
        (&c, "api", "api on a"),
        (&c, "web", "web on b"),
        (&a, "web", "web on b"),
        (&b, "api", "api on a"),
        (&a, "api", "api on a"),
        (&b, "web", "web on b"),
    ] {
        let response = server.visit(&format!("{route}.{host}"), "/").await.unwrap();
        assert!(response.ends_with(body), "{route} at {response}");
    }
    let report = stats(&c).await;
    assert_eq!(report["cluster"]["regions"]["iad"], 2);
    assert_eq!(report["cluster"]["bridges"], 2);
    assert_eq!(report["cluster"]["peers"]["up"], 2);
    a.stop().await;
    b.stop().await;
    c.stop().await;
}

fn csr(hostname: &str) -> String {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec![hostname.to_owned()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, hostname);
    params.serialize_request(&key).unwrap().pem().unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn runs_each_job_once_across_machines() {
    let dir = tempfile::tempdir().unwrap();
    let Some(a) = machine(dir.path(), "machine-a", "iad").await else {
        return;
    };
    let b = machine(dir.path(), "machine-b", "nrt").await.unwrap();
    let store = &a.service().store;
    let names: Vec<String> = (0..30)
        .map(|index| format!("job{index:02}.opentunnel.test"))
        .collect();
    let now = a.service().now();
    for name in &names {
        store
            .add_job(
                Job {
                    certificate_id: format!("cert_{name}"),
                    tunnel_id: None,
                    kind: JobKind::Issue,
                    identifiers: vec![name.clone()],
                    csr: csr(name),
                    attempts: 0,
                    created_at: now,
                },
                now,
            )
            .await
            .unwrap();
    }
    a.service().jobs.notify_one();
    b.service().jobs.notify_one();
    eventually("every job to finish", || async {
        store.counts().await.unwrap()["jobs_pending"] == 0
    })
    .await;
    let signed = |server: &TestServer| match server.server.jobs.issuer.as_ref() {
        Issuer::Local(ca) => ca.signed.lock().unwrap().clone(),
        Issuer::Acme(_) => unreachable!(),
    };
    let (on_a, on_b) = (signed(&a), signed(&b));
    for name in &names {
        let runs = on_a.get(name).copied().unwrap_or(0) + on_b.get(name).copied().unwrap_or(0);
        assert_eq!(runs, 1, "{name} ran {runs} times");
    }
    a.stop().await;
    b.stop().await;
}

/// How a machine's routing sees a tunnel right now: absent, its certificate not ready, or routable.
async fn routing(server: &TestServer, id: &str) -> &'static str {
    let service = server.service();
    match service
        .route(id, &format!("{id}.{}", service.domain))
        .await
        .unwrap()
    {
        Route::Rejected {
            tunnel_exists: false,
            ..
        } => "missing",
        Route::Rejected { outcome, .. } => outcome,
        Route::Bridge { .. } => "bridge",
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn changes_reach_other_machines_caches_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let Some(a) = machine(dir.path(), "machine-a", "iad").await else {
        return;
    };
    let b = machine(dir.path(), "machine-b", "syd").await.unwrap();
    link(&[&a, &b]).await;
    let store = &a.service().store;

    // B looks the ID up before it exists and caches "missing", which it would trust for minutes; the upgrade
    // path agrees.
    let id = "createdlater";
    assert_eq!(routing(&b, id).await, "missing");
    assert!(!b.service().exists(id).await.unwrap());

    // A creates it, and B accepts it at once.
    let started = Instant::now();
    a.service()
        .create(id, hash_token("token"))
        .await
        .unwrap()
        .unwrap();
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "create took {:?}",
        started.elapsed()
    );
    let took = within(
        "B to see the new tunnel",
        Duration::from_secs(2),
        || async { b.service().exists(id).await.unwrap() },
    )
    .await;
    assert!(took < Duration::from_millis(500), "took {took:?}");
    assert_eq!(routing(&b, id).await, "certificate_not_ready");

    // B now caches "certificate not ready"; the certificate becomes ready on A.
    let mut issuing = store.tunnel(id).await.unwrap().unwrap().record;
    issuing.certificate_id = Some("cert_later".into());
    issuing.certificate = Some(CertificateInfo {
        id: "cert_later".into(),
        state: CertificateState::Issuing,
    });
    store.put_tunnel(&issuing, a.service().now()).await.unwrap();
    // Written behind A's back, so B is told by hand here.
    b.service().expire(id).await;
    assert_eq!(routing(&b, id).await, "certificate_not_ready");
    let ready = CertificateState::Ready {
        certificate: "C".into(),
        chain: "CH".into(),
        expiry: iso(a.service().now() + 90 * 24 * 3600 * 1000),
    };
    assert!(
        a.service()
            .update_certificate(id, "cert_later", ready)
            .await
            .unwrap()
    );
    let took = within("B to route the tunnel", Duration::from_secs(2), || async {
        routing(&b, id).await == "no_bridge"
    })
    .await;
    assert!(took < Duration::from_millis(500), "took {took:?}");

    // A deletion reaches B's cached ready record too (B never re-reads a ready record by itself).
    a.service().remove(id, "token").await.unwrap();
    within("B to forget the tunnel", Duration::from_secs(2), || async {
        !b.service().exists(id).await.unwrap()
    })
    .await;

    a.stop().await;
    b.stop().await;
}

/// A machine of the previous version, as far as a new one can tell: it answers the mesh greeting with an HTTP
/// error (its internal listener hands anything but a forward to its HTTP control API) and passes forwarded
/// visitors on to `target`, a server that holds the bridge outside the mesh.
async fn previous_version(target: String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let target = target.clone();
            tokio::spawn(async move {
                let mut first = [0u8; 18];
                if stream.read_exact(&mut first).await.is_err() {
                    return;
                }
                if first.starts_with(b"OPENTUNNEL-FORWARD") {
                    let Ok(mut upstream) = TcpStream::connect(&target).await else {
                        return;
                    };
                    let _ = upstream.write_all(&first).await;
                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
                } else {
                    let _ = stream
                        .write_all(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                        .await;
                }
            });
        }
    });
    address
}

/// During a deploy from the previous version, which keeps its bridges in the `bridges` table and not in the
/// mesh, a new machine still forwards visitors to the old machines' bridges.
#[tokio::test(flavor = "multi_thread")]
async fn forwards_to_machines_of_the_previous_version() {
    let dir = tempfile::tempdir().unwrap();
    let Some(old) = machine(dir.path(), "machine-old", "iad").await else {
        return;
    };
    // The old machine is outside the mesh: it never links.
    old.mesh().halt(false);
    let on_old = client(&old, &dir.path().join("client"));
    let identity = on_old.create("default", |_| {}).await.unwrap();
    let api = app("on the old machine").await;
    let tunnel = on_old.connect("default", routes(&[("api", &api)])).unwrap();
    connected(&tunnel).await;
    let front = previous_version(old.internal()).await;
    // Its registry row, as the previous version writes it.
    old.service()
        .store
        .put_bridge(
            &BridgeLocation {
                tunnel_id: identity.id.clone(),
                route: String::new(),
                machine_id: "machine-old".into(),
                bridge_id: 1,
                region: "iad".into(),
                address: front.clone(),
                updated_at: old.service().now(),
            },
            &["api".into()],
        )
        .await
        .unwrap();

    let new = machine(dir.path(), "machine-new", "syd").await.unwrap();
    let sni = format!("api.{}", identity.hostname);
    // Until the new machine has met the old one, it does not look there.
    assert!(new.visit(&sni, "/").await.is_err());
    new.mesh().add_peer(&front);
    within(
        "the old machine to be recognised",
        Duration::from_secs(3),
        || async { new.mesh().legacy_present() },
    )
    .await;
    assert_eq!(stats(&new).await["cluster"]["peers"]["legacy"], 1);
    assert_eq!(stats(&new).await["cluster"]["complete"], false);
    let response = new.visit(&sni, "/").await.unwrap();
    assert!(response.ends_with("on the old machine"), "{response}");
    drop(tunnel);
    new.stop().await;
}

/// Requests between machines prove the shared secret without carrying it: a signed control request is answered
/// once, and not when replayed, stale, for another machine or signed with another secret. TEMPORARY: the previous
/// version's bearer secret and forward header are accepted only while `MESH_ACCEPT_V1` is on.
#[tokio::test(flavor = "multi_thread")]
async fn internal_requests_prove_the_secret_without_sending_it() {
    use opentunnel_server::peer_auth::{Secret, nonce};
    let dir = tempfile::tempdir().unwrap();
    let Some(a) = machine(dir.path(), "machine-a", "iad").await else {
        return;
    };
    let path = "/internal/tunnel/abcdefghijkl/routes";
    let url = format!("http://{}{path}", a.internal());
    let signed = |secret: &str, receiver: &str, timestamp: u64, nonce: &str| {
        let timestamp = timestamp.to_string();
        let proof = Secret::new(secret).sign(&[
            "opentunnel control/2",
            "machine-x",
            receiver,
            &timestamp,
            nonce,
            "GET",
            path,
        ]);
        format!("machine-x {receiver} {timestamp} {nonce} {proof}")
    };
    let get = |auth: Option<(&'static str, String)>| {
        let url = url.clone();
        async move {
            let mut request = reqwest::Client::new().get(url);
            if let Some((name, value)) = auth {
                request = request.header(name, value);
            }
            request.send().await.unwrap().status().as_u16()
        }
    };
    let now = a.service().now();
    let once = nonce();
    let good = signed("cluster-secret", "machine-a", now, &once);
    assert_eq!(get(Some(("x-opentunnel-auth", good.clone()))).await, 200);
    assert_eq!(
        get(Some(("x-opentunnel-auth", good))).await,
        401,
        "replayed"
    );
    for (auth, why) in [
        (
            signed("cluster-secret", "machine-b", now, &nonce()),
            "another machine",
        ),
        (
            signed("cluster-secret", "machine-a", now - 60_000, &nonce()),
            "stale",
        ),
        (
            signed("cluster-secret", "machine-a", now + 60_000, &nonce()),
            "future",
        ),
        (
            signed("other-secret", "machine-a", now, &nonce()),
            "another secret",
        ),
        ("machine-x machine-a".to_owned(), "malformed"),
    ] {
        assert_eq!(get(Some(("x-opentunnel-auth", auth))).await, 401, "{why}");
    }
    assert_eq!(get(None).await, 401);
    assert_eq!(
        get(Some(("authorization", "Bearer wrong".into()))).await,
        401
    );
    // TEMPORARY: the previous version's bearer secret.
    assert_eq!(
        get(Some(("authorization", "Bearer cluster-secret".into()))).await,
        200
    );
    // A forward with a bad proof is closed without an answer.
    let mut stream = TcpStream::connect(a.internal()).await.unwrap();
    let timestamp = now.to_string();
    stream
        .write_all(
            format!(
                "OPENTUNNEL-FORWARD/2 machine-x machine-a {timestamp} {} abcdefghijkl @ 127.0.0.1:1 {}\n",
                nonce(),
                "00".repeat(32)
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut answer = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut answer)).await;
    assert!(answer.is_empty());
    a.stop().await;

    let strict = machine_with(
        dir.path(),
        "machine-strict",
        "iad",
        &["--mesh-accept-v1=false"],
    )
    .await
    .unwrap();
    let url = format!("http://{}{path}", strict.internal());
    let status = reqwest::Client::new()
        .get(url)
        .bearer_auth("cluster-secret")
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status, 401);
    strict.stop().await;
}
