//! Imports (`POST /api/admin/import`, a restore) take only records the server could have written itself, and
//! the job runner orders certificates only for a tunnel's own names, whatever queued the job: a record or job
//! naming the domain, its wildcard or another tunnel never reaches the CA.

mod common;

use std::time::Duration;

use common::TestServer;
use opentunnel_server::crypto::hash_token;
use opentunnel_server::store::{Job, JobKind};
use serde_json::{Value, json};

fn csr(names: &[&str]) -> String {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(
        names
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>(),
    )
    .unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, names[0]);
    params.serialize_request(&key).unwrap().pem().unwrap()
}

fn record(id: &str, extra: Value) -> Value {
    let mut record = json!({
        "version": 1,
        "id": id,
        "hostname": format!("{id}.opentunnel.test"),
        "tokenHash": hash_token("token"),
        "state": "offline",
        "createdAt": "2026-10-09T00:00:00.000Z",
    });
    for (key, value) in extra.as_object().unwrap() {
        record[key] = value.clone();
    }
    json!({ "record": record })
}

async fn import(server: &TestServer, records: Vec<Value>) -> Value {
    reqwest::Client::new()
        .post(format!("{}/api/admin/import", server.api))
        .bearer_auth("admin-secret")
        .json(&json!({ "version": 1, "records": records }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn imports_only_records_for_a_tunnels_own_names() {
    let dir = tempfile::tempdir().unwrap();
    let Some(server) = TestServer::start(dir.path(), &[]).await else {
        return;
    };
    let apex = ["opentunnel.test", "*.opentunnel.test"];
    let issuing = |names: &[&str], csr: String| {
        json!({
            "certificateID": "cert_imported",
            "certificate": { "id": "cert_imported", "state": { "type": "issuing" } },
            "certificateCsr": csr,
            "certificateIdentifiers": names,
        })
    };
    let summary = import(
        &server,
        vec![
            record("goodtunnel01", json!({})),
            record(
                "goodtunnel02",
                issuing(
                    &[
                        "goodtunnel02.opentunnel.test",
                        "*.goodtunnel02.opentunnel.test",
                    ],
                    csr(&[
                        "goodtunnel02.opentunnel.test",
                        "*.goodtunnel02.opentunnel.test",
                    ]),
                ),
            ),
            // The whole domain, with the attacker's CSR.
            record("evil00000001", issuing(&apex, csr(&apex))),
            // The tunnel's names, but a CSR for the domain.
            record(
                "evil00000002",
                issuing(&["evil00000002.opentunnel.test"], csr(&apex)),
            ),
            // Another tunnel's names.
            record(
                "evil00000003",
                issuing(
                    &["goodtunnel01.opentunnel.test"],
                    csr(&["goodtunnel01.opentunnel.test"]),
                ),
            ),
            record("evil00000004", json!({ "hostname": "opentunnel.test" })),
            record("Evil.Tunnel", json!({})),
            record("evil00000005", json!({ "tokenHash": "" })),
        ],
    )
    .await;
    assert_eq!(summary["inserted"], 2, "{summary}");
    let rejected = summary["rejected"].as_array().unwrap();
    assert_eq!(rejected.len(), 6, "{summary}");
    for id in [
        "evil00000001",
        "evil00000002",
        "evil00000003",
        "evil00000004",
    ] {
        assert!(server.service().store.tunnel(id).await.unwrap().is_none());
    }
    assert!(
        server
            .service()
            .store
            .tunnel("goodtunnel02")
            .await
            .unwrap()
            .is_some()
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_job_runner_refuses_names_that_are_not_the_tunnels() {
    let dir = tempfile::tempdir().unwrap();
    let Some(server) = TestServer::start(dir.path(), &[]).await else {
        return;
    };
    assert_eq!(
        import(&server, vec![record("victim000001", json!({}))]).await["inserted"],
        1
    );
    let store = &server.service().store;
    let now = server.service().now();
    let apex = ["opentunnel.test", "*.opentunnel.test"];
    // Jobs as a tampered record or a bug could queue them.
    for (id, names, request) in [
        ("cert_apex", apex.to_vec(), csr(&apex)),
        (
            "cert_mismatch",
            vec!["victim000001.opentunnel.test"],
            csr(&apex),
        ),
    ] {
        store
            .add_job(
                Job {
                    certificate_id: id.into(),
                    tunnel_id: Some("victim000001".into()),
                    kind: JobKind::Issue,
                    identifiers: names.iter().map(|name| (*name).to_owned()).collect(),
                    csr: request,
                    attempts: 0,
                    created_at: now,
                },
                now,
            )
            .await
            .unwrap();
    }
    server.service().jobs.notify_one();
    for _ in 0..200 {
        let counts = store.counts().await.unwrap();
        if counts["jobs_failed"] == 2 && counts["jobs_pending"] == 0 {
            server.stop().await;
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("{}", store.counts().await.unwrap());
}
