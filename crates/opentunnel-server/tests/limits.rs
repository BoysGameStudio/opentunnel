//! Limits on creating tunnels and issuing certificates, through the HTTP API: per client address (with
//! `CF-Connecting-IP` believed only from trusted proxies), per tunnel, and the cluster-wide job backlog.

mod common;

use std::time::Duration;

use common::TestServer;
use opentunnel_server::store::{Job, JobKind};
use serde_json::Value;

fn csr(hostname: &str) -> String {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params =
        rcgen::CertificateParams::new(vec![hostname.to_owned(), format!("*.{hostname}")]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, hostname);
    params.serialize_request(&key).unwrap().pem().unwrap()
}

struct Answer {
    status: u16,
    retry_after: Option<u64>,
    body: Value,
}

async fn create(server: &TestServer, client_ip: Option<&str>) -> Answer {
    let mut request = reqwest::Client::new()
        .post(format!("{}/api/tunnel", server.api))
        .json(&serde_json::json!({}));
    if let Some(ip) = client_ip {
        request = request.header("CF-Connecting-IP", ip);
    }
    answer(request.send().await.unwrap()).await
}

async fn bind(server: &TestServer, id: &str, token: &str, csr: &str) -> Answer {
    let request = reqwest::Client::new()
        .post(format!("{}/api/tunnel/{id}/certificate", server.api))
        .bearer_auth(token)
        .json(&serde_json::json!({ "csr": csr }));
    answer(request.send().await.unwrap()).await
}

async fn answer(response: reqwest::Response) -> Answer {
    let status = response.status().as_u16();
    let retry_after = response
        .headers()
        .get("retry-after")
        .map(|value| value.to_str().unwrap().parse().unwrap());
    let body = response.json().await.unwrap_or(Value::Null);
    Answer {
        status,
        retry_after,
        body,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn limits_tunnels_per_client_address() {
    let dir = tempfile::tempdir().unwrap();
    let Some(server) = TestServer::start(
        dir.path(),
        &["--create-rate-per-hour=2", "--create-rate-burst=2"],
    )
    .await
    else {
        return;
    };
    assert_eq!(create(&server, None).await.status, 201);
    assert_eq!(create(&server, None).await.status, 201);
    let limited = create(&server, None).await;
    assert_eq!(limited.status, 429);
    // One every 30 minutes after the burst.
    let retry = limited.retry_after.unwrap();
    assert!((1_790..=1_800).contains(&retry), "{retry}");
    assert_eq!(limited.body["_tag"], "RateLimitedError");
    assert_eq!(
        limited.body["message"],
        "Too many tunnels created from this address; try again in 30 minutes"
    );
    // The connection is not from a trusted proxy: a spoofed CF-Connecting-IP is ignored and the request still
    // counts against its real address.
    for spoofed in ["203.0.113.1", "203.0.113.2", "2001:db8::1"] {
        assert_eq!(create(&server, Some(spoofed)).await.status, 429);
    }
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn believes_the_client_header_from_trusted_proxies() {
    let dir = tempfile::tempdir().unwrap();
    let Some(server) = TestServer::start(
        dir.path(),
        &[
            "--create-rate-per-hour=1",
            "--create-rate-burst=1",
            // Requests come from loopback, here standing in for Cloudflare.
            "--trusted-proxy-ranges=127.0.0.0/8",
        ],
    )
    .await
    else {
        return;
    };
    assert_eq!(create(&server, Some("203.0.113.1")).await.status, 201);
    assert_eq!(create(&server, Some("203.0.113.1")).await.status, 429);
    assert_eq!(create(&server, Some("203.0.113.2")).await.status, 201);
    // IPv6 clients count by /64.
    assert_eq!(create(&server, Some("2001:db8:0:1::1")).await.status, 201);
    assert_eq!(
        create(&server, Some("2001:db8:0:1::ffff")).await.status,
        429
    );
    assert_eq!(create(&server, Some("2001:db8:0:2::1")).await.status, 201);
    // Without the header, the proxy's own address.
    assert_eq!(create(&server, None).await.status, 201);
    assert_eq!(create(&server, None).await.status, 429);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn limits_new_certificates_per_tunnel() {
    let dir = tempfile::tempdir().unwrap();
    let Some(server) = TestServer::start(
        dir.path(),
        &["--issuance-rate-per-day=1", "--issuance-rate-burst=2"],
    )
    .await
    else {
        return;
    };
    let created = create(&server, None).await;
    assert_eq!(created.status, 201);
    let id = created.body["tunnel"]["id"].as_str().unwrap().to_owned();
    let hostname = created.body["tunnel"]["hostname"]
        .as_str()
        .unwrap()
        .to_owned();
    let token = created.body["token"].as_str().unwrap().to_owned();
    let ready = || async {
        for _ in 0..200 {
            let certificate = server.service().certificate(&id, &token).await.unwrap();
            if let opentunnel_server::service::CertificateLookup::Ok(info) = certificate
                && matches!(
                    info.state,
                    opentunnel::protocol::api::CertificateState::Ready { .. }
                )
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("the certificate was not issued");
    };
    let first = csr(&hostname);
    assert_eq!(bind(&server, &id, &token, &first).await.status, 202);
    ready().await;
    // Binding the CSR the tunnel has does not count.
    for _ in 0..3 {
        assert_eq!(bind(&server, &id, &token, &first).await.status, 202);
    }
    assert_eq!(
        bind(&server, &id, &token, &csr(&hostname)).await.status,
        202
    );
    ready().await;
    let limited = bind(&server, &id, &token, &csr(&hostname)).await;
    assert_eq!(limited.status, 429);
    assert_eq!(limited.body["_tag"], "RateLimitedError");
    let retry = limited.retry_after.unwrap();
    assert!((86_390..=86_400).contains(&retry), "{retry}");
    // Another tunnel has its own budget.
    let other = create(&server, None).await;
    let other_id = other.body["tunnel"]["id"].as_str().unwrap();
    let other_token = other.body["token"].as_str().unwrap();
    let other_csr = csr(other.body["tunnel"]["hostname"].as_str().unwrap());
    assert_eq!(
        bind(&server, other_id, other_token, &other_csr)
            .await
            .status,
        202
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn refuses_new_issuance_while_the_backlog_is_full() {
    let dir = tempfile::tempdir().unwrap();
    let Some(server) = TestServer::start(dir.path(), &["--issuance-backlog-limit=2"]).await else {
        return;
    };
    let created = create(&server, None).await;
    assert_eq!(created.status, 201);
    let id = created.body["tunnel"]["id"].as_str().unwrap().to_owned();
    let hostname = created.body["tunnel"]["hostname"]
        .as_str()
        .unwrap()
        .to_owned();
    let token = created.body["token"].as_str().unwrap().to_owned();
    // Three jobs queued far in the future: over the limit.
    let store = &server.service().store;
    let far = server.service().now() + 86_400_000;
    for index in 0..3 {
        store
            .add_job(
                Job {
                    certificate_id: format!("cert_backlog_{index}"),
                    tunnel_id: None,
                    kind: JobKind::Renew,
                    identifiers: vec!["x.opentunnel.test".into()],
                    csr: "csr".into(),
                    attempts: 0,
                    created_at: far,
                },
                far,
            )
            .await
            .unwrap();
    }
    // The count is cached for a few seconds.
    tokio::time::sleep(Duration::from_millis(5_100)).await;
    let refused = create(&server, None).await;
    assert_eq!(refused.status, 503);
    assert_eq!(refused.retry_after, Some(30));
    assert_eq!(
        refused.body,
        serde_json::json!({
            "_tag": "ServiceUnavailableError",
            "message": "certificate issuance is busy; try again later",
        })
    );
    let refused = bind(&server, &id, &token, &csr(&hostname)).await;
    assert_eq!(refused.status, 503);
    assert_eq!(refused.retry_after, Some(30));
    // Reads are not affected.
    let info = reqwest::Client::new()
        .get(format!("{}/api/tunnel/{id}", server.api))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(info.status(), 200);
    server.stop().await;
}

/// While the CA cools down (shared in the database by whichever machine saw it fail), first issuance waits.
#[tokio::test(flavor = "multi_thread")]
async fn pauses_first_issuance_while_the_ca_cools_down() {
    let dir = tempfile::tempdir().unwrap();
    let Some(url) = common::database_url(dir.path()).await else {
        return;
    };
    let store = opentunnel_server::store::Store::open(&url).await.unwrap();
    let until = opentunnel_server::clock::Clock::system().now_ms() + 3_600_000;
    store
        .set_meta("ca_cooldown", &format!("{until} 60000"))
        .await
        .unwrap();
    // A configured API certificate, so no job for it runs first (a success would end the cool-down).
    let key = rcgen::KeyPair::generate().unwrap();
    let certificate = rcgen::CertificateParams::new(vec![common::DOMAIN.to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let (cert_file, key_file) = (dir.path().join("cert.pem"), dir.path().join("key.pem"));
    std::fs::write(&cert_file, certificate.pem()).unwrap();
    std::fs::write(&key_file, key.serialize_pem()).unwrap();
    let cert_arg = format!("--tls-cert-file={}", cert_file.display());
    let key_arg = format!("--tls-key-file={}", key_file.display());
    let server = TestServer::start(dir.path(), &[&cert_arg, &key_arg])
        .await
        .unwrap();
    let created = create(&server, None).await;
    let id = created.body["tunnel"]["id"].as_str().unwrap().to_owned();
    let hostname = created.body["tunnel"]["hostname"]
        .as_str()
        .unwrap()
        .to_owned();
    let token = created.body["token"].as_str().unwrap().to_owned();
    assert_eq!(
        bind(&server, &id, &token, &csr(&hostname)).await.status,
        202
    );
    tokio::time::sleep(Duration::from_secs(2)).await;
    // The local CA would have signed it at once.
    let counts = server.service().store.counts().await.unwrap();
    assert_eq!(counts["jobs_pending"], 1, "{counts}");
    server.stop().await;
}
