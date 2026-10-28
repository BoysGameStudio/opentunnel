//! Several servers on one database, as machines in several regions, linked by the mesh: visitors reach a bridge
//! attached to another machine as soon as it attached, detaches, deletes and route conflicts cross machines, a
//! machine that crashes, freezes, restarts or is cut off is handled, changes reach other machines' caches at
//! once, requests between machines prove the secret, and background jobs run once.

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
use opentunnel_server::store::{Job, JobKind};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

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
        owner_token: Some(common::OWNER_TOKEN.into()),
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
    let address = a.internal();
    a.freeze();
    drop(tunnel);

    // A restarted machine keeps its address (on Fly, its 6PN address): a link from another address claiming
    // its ID would be refused while the old link lasts.
    let listen = format!("--internal-listen={address}");
    let restarted = machine_with(dir.path(), "machine-a", "iad", &[&listen])
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
    // Tunnels waiting for these certificates (the runner orders only a tunnel's own names, and only while it
    // still wants them).
    let records: Vec<serde_json::Value> = names
        .iter()
        .map(|name| {
            let id = name.split('.').next().unwrap();
            serde_json::json!({ "record": {
                "version": 1, "id": id, "hostname": name, "tokenHash": hash_token("token"),
                "state": "offline", "createdAt": "2026-10-09T00:00:00.000Z",
                "certificateID": format!("cert_{name}"),
                "certificate": { "id": format!("cert_{name}"), "state": { "type": "issuing" } },
                "certificateIdentifiers": [name],
                "certificateCsr": csr(name),
            }})
        })
        .collect();
    let imported: serde_json::Value = reqwest::Client::new()
        .post(format!("{}/api/admin/import", a.api))
        .bearer_auth("admin-secret")
        .json(&serde_json::json!({ "version": 1, "records": records }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(imported["inserted"], 30, "{imported}");
    for name in &names {
        let csr = store
            .tunnel(name.split('.').next().unwrap())
            .await
            .unwrap()
            .unwrap()
            .record
            .certificate_csr
            .unwrap();
        store
            .add_job(
                Job {
                    certificate_id: format!("cert_{name}"),
                    tunnel_id: Some(name.split('.').next().unwrap().to_owned()),
                    kind: JobKind::Issue,
                    identifiers: vec![name.clone()],
                    csr,
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

/// Requests between machines prove the shared secret without carrying it: a signed control request is answered
/// once, and not when replayed, stale, for another machine or signed with another secret. The bearer secret and
/// the forward header carrying it (before October 2026) are refused.
#[tokio::test(flavor = "multi_thread")]
async fn internal_requests_prove_the_secret_without_sending_it() {
    use opentunnel_server::peer_auth::{Secret, nonce};
    let dir = tempfile::tempdir().unwrap();
    let Some(a) = machine(dir.path(), "machine-a", "iad").await else {
        return;
    };
    // Signed requests count only from a linked machine, at its address (here loopback, like the test client).
    let b = machine(dir.path(), "machine-b", "syd").await.unwrap();
    link(&[&a, &b]).await;
    let path = "/internal/tunnel/abcdefghijkl/routes";
    let url = format!("http://{}{path}", a.internal());
    let signed_by = |sender: &str, secret: &str, receiver: &str, timestamp: u64, nonce: &str| {
        let timestamp = timestamp.to_string();
        let proof = Secret::new(secret).sign(&[
            "opentunnel control/2",
            sender,
            receiver,
            &timestamp,
            nonce,
            "GET",
            path,
        ]);
        format!("{sender} {receiver} {timestamp} {nonce} {proof}")
    };
    let signed = |secret: &str, receiver: &str, timestamp: u64, nonce: &str| {
        signed_by("machine-b", secret, receiver, timestamp, nonce)
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
    // The bearer secret itself, as machines before October 2026 sent it.
    assert_eq!(
        get(Some(("authorization", "Bearer cluster-secret".into()))).await,
        401
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
    // One carrying the secret itself is not a forward at all (the listener takes it for bad HTTP).
    let mut stream = TcpStream::connect(a.internal()).await.unwrap();
    stream
        .write_all(b"OPENTUNNEL-FORWARD/1 cluster-secret abcdefghijkl @ 127.0.0.1:1\n")
        .await
        .unwrap();
    let mut answer = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut answer)).await;
    assert!(
        answer.is_empty() || answer.starts_with(b"HTTP/1.1 4"),
        "{}",
        String::from_utf8_lossy(&answer)
    );
    a.stop().await;
    b.stop().await;
}

/// A deletion another machine announces closes bridges only when the database says the tunnel is deleted.
#[tokio::test(flavor = "multi_thread")]
async fn ignores_deletions_the_database_does_not_confirm() {
    let dir = tempfile::tempdir().unwrap();
    let Some(a) = machine(dir.path(), "machine-a", "iad").await else {
        return;
    };
    let b = machine(dir.path(), "machine-b", "syd").await.unwrap();
    link(&[&a, &b]).await;
    let on_b = client(&b, &dir.path().join("client"));
    let identity = on_b.create("default", |_| {}).await.unwrap();
    let api = app("still here").await;
    let tunnel = on_b.connect("default", routes(&[("api", &api)])).unwrap();
    connected(&tunnel).await;
    a.mesh()
        .publish(opentunnel_server::mesh::Event::TunnelDeleted {
            tunnel: identity.id.clone(),
        });
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(tunnel.status().state, State::Connected);
    let response = a
        .visit(&format!("api.{}", identity.hostname), "/")
        .await
        .unwrap();
    assert!(response.ends_with("still here"), "{response}");
    drop(tunnel);
    a.stop().await;
    b.stop().await;
}
