//! Issuance through a fake ACME CA and a fake Cloudflare DNS API that fail the ways ZeroSSL and Cloudflare did
//! in production: HTML instead of a directory, no nonce, rejected nonces, 502s from the CA's proxy, a challenge
//! token shared by a hostname and its wildcard, a challenge record left behind by an earlier attempt, and
//! authorizations handed to every new order while their validation never finishes.

mod common;

use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use common::{DOMAIN, TestServer};
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Response, StatusCode};
use opentunnel::protocol::api::{CertificateInfo, CertificateState, TunnelState};
use opentunnel_server::acme::{Acme, AcmeConfig};
use opentunnel_server::crypto::{base64url, decode_base64url, hash_token};
use opentunnel_server::dns::DnsProvider;
use opentunnel_server::record::StoredTunnel;
use opentunnel_server::service::CertificateLookup;
use opentunnel_server::store::{Job, JobKind, Store};
use serde_json::{Value, json};
use tokio::sync::Notify;

#[derive(Default)]
struct Faults {
    /// Directory requests answered with an HTML page and status 200.
    garbage_directory: u32,
    /// Nonce requests answered with 503 and no nonce.
    no_nonce: u32,
    /// Signed requests rejected with badNonce.
    bad_nonce: u32,
    /// Authorization reads answered with nginx's 502 page and no nonce.
    authz_502: u32,
    /// Every new order's challenge record already exists, as left by an interrupted attempt.
    leftover_record: bool,
    /// The next answered challenges start validation that never finishes, as ZeroSSL's sometimes do.
    stuck_challenges: u32,
    /// The next answered challenges fail validation.
    invalid_challenges: u32,
    /// Validation of an answered challenge finishes after this many reads of its authorization.
    slow_validation: u32,
    /// The next new order hands out the newest failed authorization for its identifier again.
    reuse_failed_once: bool,
}

/// An authorization, which the CA hands to every new order for its identifier while it is pending or valid.
struct Authz {
    identifier: String,
    token: String,
    /// pending, valid, invalid or deactivated.
    status: &'static str,
    /// The dns-01 challenge: pending, processing, valid or invalid.
    challenge: &'static str,
    error: Option<Value>,
    /// Reads of the authorization left until validation finishes; `None` never finishes.
    reads_left: Option<u32>,
}

struct Order {
    identifiers: Vec<String>,
    authzs: Vec<usize>,
    certificate: Option<String>,
}

#[derive(Default)]
struct State {
    faults: Faults,
    nonces: HashSet<String>,
    counter: u64,
    thumbprint: Option<String>,
    orders: Vec<Order>,
    authzs: Vec<Authz>,
    /// Cloudflare records: id to (name, content).
    records: HashMap<String, (String, String)>,
    stale_nonces: u32,
    identical_records: u32,
    ca: Option<(String, String)>,
    /// Authorizations deactivated by the client.
    deactivated: u32,
    /// Challenge records deleted while the CA was still validating them.
    premature_deletes: u32,
    /// Holds the next new order until notified, after notifying the first.
    pause_order: Option<(Arc<Notify>, Arc<Notify>)>,
}

impl State {
    fn nonce(&mut self) -> String {
        self.counter += 1;
        let nonce = format!("nonce-{}", self.counter);
        self.nonces.insert(nonce.clone());
        nonce
    }

    fn expected_record(&self, authz: &Authz) -> (String, String) {
        let thumbprint = self.thumbprint.as_deref().unwrap();
        let digest = ring::digest::digest(
            &ring::digest::SHA256,
            format!("{}.{thumbprint}", authz.token).as_bytes(),
        );
        let host = authz.identifier.trim_start_matches("*.");
        (
            format!("_acme-challenge.{host}"),
            base64url(digest.as_ref()),
        )
    }

    /// Adds an authorization as an earlier order (of this or an older server) left it.
    fn seed(&mut self, identifier: &str, challenge: &'static str) -> usize {
        self.authzs.push(Authz {
            identifier: identifier.into(),
            token: format!("seeded-{}", self.authzs.len()),
            status: "pending",
            challenge,
            error: None,
            reads_left: None,
        });
        self.authzs.len() - 1
    }

    /// Finishes validation: valid when the record is published.
    fn validate(&mut self, index: usize) {
        let expected = self.expected_record(&self.authzs[index]);
        let published = self.records.values().any(|record| *record == expected);
        let authz = &mut self.authzs[index];
        if published {
            authz.status = "valid";
            authz.challenge = "valid";
        } else {
            authz.status = "invalid";
            authz.challenge = "invalid";
            authz.error = Some(json!({
                "type": "urn:ietf:params:acme:error:unauthorized",
                "detail": format!("no TXT record found at {}", expected.0),
                "status": 403,
            }));
        }
    }

    fn authz_json(&self, base: &str, index: usize) -> Value {
        let authz = &self.authzs[index];
        let mut challenge = json!({
            "type": "dns-01",
            "url": format!("{base}/chall/{index}"),
            "token": authz.token,
            "status": authz.challenge,
        });
        if let Some(error) = &authz.error {
            challenge["error"] = error.clone();
        }
        json!({
            "status": authz.status,
            "identifier": { "type": "dns", "value": authz.identifier },
            "challenges": [challenge],
        })
    }

    fn order_json(&self, base: &str, index: usize) -> Value {
        let order = &self.orders[index];
        let statuses: Vec<&str> = order
            .authzs
            .iter()
            .map(|authz| self.authzs[*authz].status)
            .collect();
        let status = if order.certificate.is_some() {
            "valid"
        } else if statuses
            .iter()
            .any(|status| matches!(*status, "invalid" | "deactivated"))
        {
            "invalid"
        } else if statuses.iter().all(|status| *status == "valid") {
            "ready"
        } else {
            "pending"
        };
        let mut body = json!({
            "status": status,
            "identifiers": order.identifiers.iter().map(|value| json!({ "type": "dns", "value": value })).collect::<Vec<_>>(),
            "authorizations": order.authzs.iter().map(|i| format!("{base}/authz/{i}")).collect::<Vec<_>>(),
            "finalize": format!("{base}/finalize/{index}"),
        });
        if order.certificate.is_some() {
            body["certificate"] = format!("{base}/cert/{index}").into();
        }
        body
    }
}

type Shared = Arc<Mutex<State>>;

fn reply(status: u16, body: impl Into<Bytes>) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(body.into()));
    *response.status_mut() = StatusCode::from_u16(status).unwrap();
    response
}

fn acme(
    state: &mut State,
    status: u16,
    body: Value,
    location: Option<String>,
) -> Response<Full<Bytes>> {
    let mut response = reply(status, body.to_string());
    let nonce = state.nonce();
    let headers = response.headers_mut();
    headers.insert("replay-nonce", nonce.parse().unwrap());
    headers.insert("content-type", "application/json".parse().unwrap());
    if let Some(location) = location {
        headers.insert("location", location.parse().unwrap());
    }
    response
}

fn nginx_502() -> Response<Full<Bytes>> {
    reply(
        502,
        "<html>\n<head><title>502 Bad Gateway</title></head>\n<body>\n<center><h1>502 Bad Gateway</h1></center>\n</body>\n</html>\n",
    )
}

fn sign_csr(state: &State, csr: &[u8]) -> String {
    let (key, certificate) = state.ca.as_ref().unwrap();
    let key = rcgen::KeyPair::from_pem(key).unwrap();
    let issuer = rcgen::Issuer::from_ca_cert_pem(certificate, &key).unwrap();
    let request = rcgen::CertificateSigningRequestParams::from_der(&csr.to_vec().into()).unwrap();
    let leaf = request.signed_by(&issuer).unwrap();
    format!("{}\n{}", leaf.pem(), certificate)
}

async fn handle(
    state: Shared,
    base: String,
    request: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let query = request.uri().query().unwrap_or_default().to_owned();
    let body = request.into_body().collect().await.unwrap().to_bytes();
    if method == Method::POST && path == "/order" {
        let pause = state.lock().unwrap().pause_order.take();
        if let Some((reached, release)) = pause {
            reached.notify_one();
            release.notified().await;
        }
    }
    let mut state = state.lock().unwrap();
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    // Cloudflare.
    if segments.starts_with(&["cf", "zones", "zone", "dns_records"]) {
        return Ok(match (method, segments.get(4)) {
            (Method::POST, None) => {
                let record: Value = serde_json::from_slice(&body).unwrap();
                let (name, content) = (
                    record["name"].as_str().unwrap().to_owned(),
                    record["content"].as_str().unwrap().to_owned(),
                );
                if state
                    .records
                    .values()
                    .any(|existing| *existing == (name.clone(), content.clone()))
                {
                    state.identical_records += 1;
                    reply(400, json!({ "success": false, "errors": [{ "code": 81058, "message": "An identical record already exists." }], "messages": [], "result": null }).to_string())
                } else {
                    state.counter += 1;
                    let id = format!("record-{}", state.counter);
                    state.records.insert(id.clone(), (name, content));
                    reply(
                        200,
                        json!({ "success": true, "errors": [], "result": { "id": id } })
                            .to_string(),
                    )
                }
            }
            (Method::GET, None) => {
                let name = url::form_urlencoded::parse(query.as_bytes())
                    .find(|(key, _)| key == "name")
                    .map(|(_, value)| value.into_owned())
                    .unwrap_or_default();
                let found: Vec<Value> = state
                    .records
                    .iter()
                    .filter(|(_, (record, _))| *record == name)
                    .map(|(id, (_, content))| json!({ "id": id, "type": "TXT", "name": name, "content": format!("\"{content}\"") }))
                    .collect();
                reply(
                    200,
                    json!({ "success": true, "errors": [], "result": found }).to_string(),
                )
            }
            (Method::DELETE, Some(id)) => {
                if let Some(record) = state.records.remove(*id) {
                    let validating = state
                        .authzs
                        .iter()
                        .filter(|authz| {
                            authz.status == "pending" && authz.challenge == "processing"
                        })
                        .any(|authz| state.expected_record(authz) == record);
                    if validating {
                        state.premature_deletes += 1;
                    }
                }
                reply(
                    200,
                    json!({ "success": true, "errors": [], "result": { "id": id } }).to_string(),
                )
            }
            _ => reply(404, ""),
        });
    }

    match (&method, segments[0]) {
        (&Method::GET, "directory") => {
            if state.faults.garbage_directory > 0 {
                state.faults.garbage_directory -= 1;
                return Ok(reply(200, "<html><body>maintenance</body></html>"));
            }
            return Ok(reply(
                200,
                json!({
                    "newNonce": format!("{base}/nonce"),
                    "newAccount": format!("{base}/account"),
                    "newOrder": format!("{base}/order"),
                })
                .to_string(),
            ));
        }
        (&Method::HEAD | &Method::GET, "nonce") => {
            if state.faults.no_nonce > 0 {
                state.faults.no_nonce -= 1;
                return Ok(reply(503, ""));
            }
            let mut response = reply(200, "");
            let nonce = state.nonce();
            response
                .headers_mut()
                .insert("replay-nonce", nonce.parse().unwrap());
            return Ok(response);
        }
        (&Method::POST, _) => {}
        _ => return Ok(reply(404, "")),
    }

    // A signed request: check its nonce was issued and never used.
    let jws: Value = serde_json::from_slice(&body).unwrap();
    let protected: Value =
        serde_json::from_slice(&decode_base64url(jws["protected"].as_str().unwrap()).unwrap())
            .unwrap();
    let payload_b64 = jws["payload"].as_str().unwrap();
    let payload: Value = if payload_b64.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&decode_base64url(payload_b64).unwrap()).unwrap()
    };
    let nonce = protected["nonce"].as_str().unwrap();
    let bad_nonce = json!({ "type": "urn:ietf:params:acme:error:badNonce", "detail": "bad nonce", "status": 400 });
    if !state.nonces.remove(nonce) {
        state.stale_nonces += 1;
        return Ok(acme(&mut state, 400, bad_nonce, None));
    }
    if state.faults.bad_nonce > 0 {
        state.faults.bad_nonce -= 1;
        return Ok(acme(&mut state, 400, bad_nonce, None));
    }
    let index = |position: usize| -> usize { segments[position].parse().unwrap() };

    Ok(match segments[0] {
        "account" => {
            let jwk = &protected["jwk"];
            let input = format!(
                r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
                jwk["x"].as_str().unwrap(),
                jwk["y"].as_str().unwrap()
            );
            let digest = ring::digest::digest(&ring::digest::SHA256, input.as_bytes());
            state.thumbprint = Some(base64url(digest.as_ref()));
            acme(
                &mut state,
                201,
                json!({ "status": "valid" }),
                Some(format!("{base}/account/1")),
            )
        }
        "order" if segments.len() == 1 => {
            let identifiers: Vec<String> = payload["identifiers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|identifier| identifier["value"].as_str().unwrap().to_owned())
                .collect();
            state.counter += 1;
            // One token for every new authorization, so a hostname and its wildcard want the same record.
            let token = format!("token-{}", state.counter);
            let reuse_failed = std::mem::take(&mut state.faults.reuse_failed_once);
            let mut authzs = Vec::new();
            for identifier in &identifiers {
                let reusable = |authz: &Authz| {
                    authz.identifier == *identifier
                        && (matches!(authz.status, "pending" | "valid")
                            || (reuse_failed && authz.status == "invalid"))
                };
                let index = match state.authzs.iter().rposition(reusable) {
                    Some(index) => index,
                    None => {
                        state.authzs.push(Authz {
                            identifier: identifier.clone(),
                            token: token.clone(),
                            status: "pending",
                            challenge: "pending",
                            error: None,
                            reads_left: None,
                        });
                        let index = state.authzs.len() - 1;
                        if state.faults.leftover_record {
                            let record = state.expected_record(&state.authzs[index]);
                            if !state.records.values().any(|existing| *existing == record) {
                                state.counter += 1;
                                let id = format!("leftover-{}", state.counter);
                                state.records.insert(id, record);
                            }
                        }
                        index
                    }
                };
                authzs.push(index);
            }
            let index = state.orders.len();
            state.orders.push(Order {
                identifiers,
                authzs,
                certificate: None,
            });
            let body = state.order_json(&base, index);
            acme(&mut state, 201, body, Some(format!("{base}/order/{index}")))
        }
        "order" => {
            let body = state.order_json(&base, index(1));
            acme(&mut state, 200, body, None)
        }
        "authz" => {
            if state.faults.authz_502 > 0 {
                state.faults.authz_502 -= 1;
                return Ok(nginx_502());
            }
            let index = index(1);
            if payload["status"] == "deactivated" {
                if !matches!(state.authzs[index].status, "pending" | "valid") {
                    let problem = json!({ "type": "urn:ietf:params:acme:error:malformed", "detail": "cannot deactivate", "status": 400 });
                    return Ok(acme(&mut state, 400, problem, None));
                }
                state.authzs[index].status = "deactivated";
                state.deactivated += 1;
            } else if state.authzs[index].challenge == "processing" {
                let finished = match &mut state.authzs[index].reads_left {
                    Some(left) => {
                        *left = left.saturating_sub(1);
                        *left == 0
                    }
                    None => false,
                };
                if finished {
                    state.validate(index);
                }
            }
            let body = state.authz_json(&base, index);
            acme(&mut state, 200, body, None)
        }
        "chall" => {
            let index = index(1);
            // Answering a challenge again changes nothing.
            if state.authzs[index].challenge == "pending" && state.authzs[index].status == "pending"
            {
                if state.faults.invalid_challenges > 0 {
                    state.faults.invalid_challenges -= 1;
                    let expected = state.expected_record(&state.authzs[index]);
                    let authz = &mut state.authzs[index];
                    authz.status = "invalid";
                    authz.challenge = "invalid";
                    authz.error = Some(json!({
                        "type": "urn:ietf:params:acme:error:dns",
                        "detail": format!("DNS problem: NXDOMAIN looking up TXT for {}", expected.0),
                        "status": 400,
                    }));
                } else if state.faults.stuck_challenges > 0 {
                    state.faults.stuck_challenges -= 1;
                    state.authzs[index].challenge = "processing";
                } else if state.faults.slow_validation > 0 {
                    let reads = state.faults.slow_validation;
                    let authz = &mut state.authzs[index];
                    authz.challenge = "processing";
                    authz.reads_left = Some(reads);
                } else {
                    state.validate(index);
                }
            }
            let authz = &state.authzs[index];
            let body = json!({
                "type": "dns-01",
                "url": format!("{base}/chall/{index}"),
                "token": authz.token,
                "status": authz.challenge,
            });
            acme(&mut state, 200, body, None)
        }
        "finalize" => {
            let ready = state.order_json(&base, index(1))["status"] == "ready";
            if !ready {
                let problem = json!({ "type": "urn:ietf:params:acme:error:orderNotReady", "detail": "not ready", "status": 403 });
                return Ok(acme(&mut state, 403, problem, None));
            }
            let csr = decode_base64url(payload["csr"].as_str().unwrap()).unwrap();
            let chain = sign_csr(&state, &csr);
            state.orders[index(1)].certificate = Some(chain);
            let body = state.order_json(&base, index(1));
            acme(&mut state, 200, body, None)
        }
        "cert" => {
            let chain = state.orders[index(1)].certificate.clone().unwrap();
            let mut response = acme(&mut state, 200, Value::Null, None);
            *response.body_mut() = Full::new(Bytes::from(chain));
            response
        }
        _ => reply(404, ""),
    })
}

async fn fake(faults: Faults) -> (SocketAddr, Shared) {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = params.self_signed(&key).unwrap();
    let state: Shared = Arc::new(Mutex::new(State {
        faults,
        ca: Some((key.serialize_pem(), ca.pem())),
        ..State::default()
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let base = format!("http://{address}");
    let shared = state.clone();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let (state, base) = (shared.clone(), base.clone());
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |request| {
                    handle(state.clone(), base.clone(), request)
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(socket), service)
                    .await;
            });
        }
    });
    (address, state)
}

fn csr(hostname: &str) -> String {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params =
        rcgen::CertificateParams::new(vec![hostname.to_owned(), format!("*.{hostname}")]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, hostname);
    params.serialize_request(&key).unwrap().pem().unwrap()
}

/// Server arguments for the fake CA and DNS, and a certificate for the API domain so that only tunnel
/// certificates are ordered.
fn arguments(dir: &std::path::Path, fake: SocketAddr) -> Vec<String> {
    let key = rcgen::KeyPair::generate().unwrap();
    let certificate = rcgen::CertificateParams::new(vec![DOMAIN.to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let (cert_file, key_file) = (dir.join("api.pem"), dir.join("api.key"));
    std::fs::write(&cert_file, certificate.pem()).unwrap();
    std::fs::write(&key_file, key.serialize_pem()).unwrap();
    let jwk = opentunnel_server::acme::generate_account_jwk().unwrap();
    vec![
        "--issuer=acme".into(),
        format!("--acme-url=http://{fake}/directory"),
        format!("--acme-account-key-jwk={jwk}"),
        "--acme-eab-kid=kid".into(),
        "--acme-eab-hmac-key=aG1hYw".into(),
        "--acme-dns-propagation-timeout-ms=0".into(),
        "--acme-poll-interval-ms=10".into(),
        "--dns-provider=cloudflare".into(),
        "--cloudflare-zone-id=zone".into(),
        "--cloudflare-api-token=token".into(),
        format!("--cloudflare-api-url=http://{fake}/cf"),
        format!("--tls-cert-file={}", cert_file.display()),
        format!("--tls-key-file={}", key_file.display()),
    ]
}

async fn ready(server: &TestServer, id: &str) -> CertificateInfo {
    for _ in 0..600 {
        if let CertificateLookup::Ok(certificate) =
            server.service().certificate(id, "token").await.unwrap()
        {
            match &certificate.state {
                CertificateState::Ready { .. } => return certificate,
                CertificateState::Failed { reason } => panic!("{id} failed: {reason}"),
                _ => {}
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("{id} never got a certificate");
}

async fn job_row(url: &str, certificate: &str) -> (String, i32) {
    let pool = sqlx::MySqlPool::connect(url).await.unwrap();
    sqlx::query_as("SELECT status, attempts FROM jobs WHERE certificate_id = ?")
        .bind(certificate)
        .fetch_one(&pool)
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn issues_through_transient_ca_and_dns_failures() {
    let dir = tempfile::tempdir().unwrap();
    let Some(url) = common::database_url(dir.path()).await else {
        return;
    };
    let (fake, state) = fake(Faults {
        // More failed attempts than the three that used to be all.
        garbage_directory: 4,
        // One attempt's three nonce requests, then the next attempt's first.
        no_nonce: 4,
        bad_nonce: 2,
        // One attempt's three reads, then one more.
        authz_502: 4,
        leftover_record: true,
        ..Faults::default()
    })
    .await;

    // Issuance that gave up on a transient error before this server version, as 43 tunnels did in production.
    let store = Store::open(&url).await.unwrap();
    let now = opentunnel_server::clock::Clock::system().now_ms();
    let stuck_hostname = format!("stucktunnel1.{DOMAIN}");
    let stuck = StoredTunnel {
        version: 1,
        id: "stucktunnel1".into(),
        hostname: stuck_hostname.clone(),
        state: TunnelState::Offline,
        certificate_id: Some("cert_stuck".into()),
        token_hash: hash_token("token"),
        created_at: opentunnel_server::clock::iso(now - 60_000),
        deleted_at: None,
        certificate: Some(CertificateInfo {
            id: "cert_stuck".into(),
            state: CertificateState::Failed {
                reason: "ACME server returned no nonce".into(),
            },
        }),
        certificate_csr: Some(csr(&stuck_hostname)),
        certificate_identifiers: Some(vec![stuck_hostname.clone(), format!("*.{stuck_hostname}")]),
        certificate_started_at: Some(opentunnel_server::clock::iso(now - 60_000)),
        last_connected_at: None,
        renewal: None,
    };
    store.put_tunnel(&stuck, now - 60_000).await.unwrap();
    let job = Job {
        certificate_id: "cert_stuck".into(),
        tunnel_id: Some(stuck.id.clone()),
        kind: JobKind::Issue,
        identifiers: stuck.certificate_identifiers.clone().unwrap(),
        csr: stuck.certificate_csr.clone().unwrap(),
        attempts: 0,
        created_at: now - 60_000,
    };
    store.add_job(job, now - 60_000).await.unwrap();
    store
        .claim_job("cert_stuck", "old", now - 50_000)
        .await
        .unwrap()
        .unwrap();
    store
        .finish_job(
            "cert_stuck",
            "old",
            "failed",
            Some("ACME server returned no nonce".into()),
            now - 10_000,
        )
        .await
        .unwrap();

    let arguments = arguments(dir.path(), fake);
    let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let server = TestServer::start(dir.path(), &arguments).await.unwrap();

    let service = server.service();
    assert!(
        service
            .create("freshtunnel1", hash_token("token"))
            .await
            .unwrap()
            .is_some()
    );
    let fresh_csr = csr(&format!("freshtunnel1.{DOMAIN}"));
    service
        .bind_certificate("freshtunnel1", "token", &fresh_csr)
        .await
        .unwrap();

    let fresh = ready(&server, "freshtunnel1").await;
    let recovered = ready(&server, "stucktunnel1").await;
    for certificate in [&fresh, &recovered] {
        let CertificateState::Ready {
            certificate, chain, ..
        } = &certificate.state
        else {
            unreachable!()
        };
        assert!(certificate.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(chain.starts_with("-----BEGIN CERTIFICATE-----"));
    }
    let (fresh_status, fresh_attempts) = job_row(&url, &fresh.id).await;
    let (stuck_status, stuck_attempts) = job_row(&url, "cert_stuck").await;
    assert_eq!((&fresh_status[..], &stuck_status[..]), ("done", "done"));
    // Two jobs shared the faults; the four bad directories alone fail four attempts.
    assert!(fresh_attempts + stuck_attempts >= 4);
    server.stop().await;

    let state = state.lock().unwrap();
    let faults = &state.faults;
    assert_eq!(
        (
            faults.garbage_directory,
            faults.no_nonce,
            faults.bad_nonce,
            faults.authz_502
        ),
        (0, 0, 0, 0),
        "every fault was hit"
    );
    assert_eq!(state.stale_nonces, 0, "no nonce was used twice or made up");
    assert!(state.identical_records >= 1, "the leftover record was hit");
    // Every record this server created is gone, and so are the leftovers it adopted.
    assert!(
        !state.records.keys().any(|id| id.starts_with("record-")),
        "challenge records were cleaned up: {:?}",
        state.records
    );
    for order in state
        .orders
        .iter()
        .filter(|order| order.certificate.is_some())
    {
        for authz in &order.authzs {
            let expected = state.expected_record(&state.authzs[*authz]);
            assert!(!state.records.values().any(|record| *record == expected));
        }
    }
    assert_eq!(state.premature_deletes, 0);
}

/// An ACME client for the fake CA and DNS, without a server or database.
fn client(fake: SocketAddr) -> Acme {
    opentunnel_server::install_crypto_provider();
    let http = reqwest::Client::new();
    let dns = DnsProvider::Cloudflare {
        http: http.clone(),
        api: format!("http://{fake}/cf"),
        zone_id: "zone".into(),
        token: "token".into(),
    };
    let config = AcmeConfig {
        directory: format!("http://{fake}/directory"),
        email: "acme@opentunnel.test".into(),
        eab_kid: Some("kid".into()),
        eab_hmac_key: Some("aG1hYw".into()),
        account_key_jwk: Some(opentunnel_server::acme::generate_account_jwk().unwrap()),
        dns_propagation_timeout: Duration::ZERO,
        authorization_poll: Duration::from_millis(2),
        order_poll: Duration::from_millis(2),
    };
    Acme::new(config, http, Some(dns))
}

/// A hostname and its wildcard, and a CSR for them.
fn order(id: &str) -> (Vec<String>, String) {
    let hostname = format!("{id}.{DOMAIN}");
    (
        vec![hostname.clone(), format!("*.{hostname}")],
        csr(&hostname),
    )
}

async fn attempt(acme: &Acme, identifiers: &[String], csr: &str) -> anyhow::Result<()> {
    acme.issue(identifiers, csr, async |_| Ok(()))
        .await
        .map(drop)
}

/// Registers the account, so the fake knows its thumbprint before authorizations are seeded.
async fn register(acme: &Acme, state: &Shared) {
    let (identifiers, csr) = order("register0000");
    attempt(acme, &identifiers, &csr).await.unwrap();
    let state = state.lock().unwrap();
    assert!(state.thumbprint.is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn deactivates_an_authorization_stuck_in_processing_that_the_ca_keeps_reusing() {
    let (fake, state) = fake(Faults::default()).await;
    let acme = client(fake);
    register(&acme, &state).await;
    let (identifiers, csr) = order("stuckauthz00");
    // An attempt of an older server answered the challenge; validation never finished, and every new order for
    // the hostname gets this authorization back.
    let stuck = state.lock().unwrap().seed(&identifiers[0], "processing");
    let orders = state.lock().unwrap().orders.len();

    attempt(&acme, &identifiers, &csr).await.unwrap();

    let state = state.lock().unwrap();
    assert_eq!(state.authzs[stuck].status, "deactivated");
    assert_eq!(state.deactivated, 1);
    // The order with the stuck authorization, then a fresh one.
    assert_eq!(state.orders.len() - orders, 2);
    assert!(state.orders.last().unwrap().certificate.is_some());
    assert!(!state.orders.last().unwrap().authzs.contains(&stuck));
    assert_eq!(state.premature_deletes, 0);
    assert!(state.records.is_empty(), "{:?}", state.records);
}

#[tokio::test(flavor = "multi_thread")]
async fn deactivates_authorizations_left_pending_before_deleting_their_records() {
    let (fake, state) = fake(Faults::default()).await;
    let acme = client(fake);
    register(&acme, &state).await;
    let (identifiers, csr) = order("stucknow0000");
    // Validation of this attempt's challenges never finishes.
    state.lock().unwrap().faults.stuck_challenges = 2;

    let error = attempt(&acme, &identifiers, &csr).await.unwrap_err();
    assert_eq!(error.to_string(), "ACME authorization ended in pending");
    assert!(matches!(
        opentunnel_server::retry::classify(&error),
        opentunnel_server::retry::Class::Transient { .. }
    ));
    {
        let state = state.lock().unwrap();
        // Both shared the record name; it was deleted only once neither could be validated any more.
        assert_eq!(state.deactivated, 2);
        assert_eq!(state.premature_deletes, 0);
        assert!(state.records.is_empty(), "{:?}", state.records);
    }

    // The next attempt gets new authorizations, which validate.
    attempt(&acme, &identifiers, &csr).await.unwrap();
    let state = state.lock().unwrap();
    assert_eq!(state.premature_deletes, 0);
    assert!(state.records.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn keeps_records_published_while_validation_is_in_progress() {
    let (fake, state) = fake(Faults {
        // Longer than a few polls, with the records checked when validation finishes.
        slow_validation: 20,
        ..Faults::default()
    })
    .await;
    let acme = client(fake);
    let (identifiers, csr) = order("slowcheck000");
    attempt(&acme, &identifiers, &csr).await.unwrap();
    let state = state.lock().unwrap();
    assert_eq!(state.deactivated, 0);
    assert_eq!(state.premature_deletes, 0);
    assert!(state.records.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn answers_a_reused_pending_authorization() {
    let (fake, state) = fake(Faults::default()).await;
    let acme = client(fake);
    register(&acme, &state).await;
    let (identifiers, csr) = order("reusedauthz0");
    // An earlier order created it and was never answered.
    let reused = state.lock().unwrap().seed(&identifiers[0], "pending");
    let orders = state.lock().unwrap().orders.len();

    attempt(&acme, &identifiers, &csr).await.unwrap();

    let state = state.lock().unwrap();
    assert_eq!(state.authzs[reused].status, "valid");
    assert_eq!(state.deactivated, 0);
    assert_eq!(state.orders.len() - orders, 1);
    assert!(state.records.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn starts_over_after_an_invalid_authorization() {
    let (fake, state) = fake(Faults {
        invalid_challenges: 1,
        ..Faults::default()
    })
    .await;
    let acme = client(fake);
    let (identifiers, csr) = order("invalidauthz");

    let error = attempt(&acme, &identifiers, &csr).await.unwrap_err();
    let message = error.to_string();
    assert!(
        message.starts_with(&format!(
            "ACME authorization for {} ended in invalid: urn:ietf:params:acme:error:dns: DNS problem: NXDOMAIN",
            identifiers[0]
        )),
        "{message}"
    );
    // Not retried for a day, but the job's other attempts.
    assert_eq!(
        opentunnel_server::retry::classify(&error),
        opentunnel_server::retry::Class::Unknown
    );
    let failed = {
        let state = state.lock().unwrap();
        assert_eq!(state.premature_deletes, 0);
        assert!(state.records.is_empty());
        state
            .authzs
            .iter()
            .position(|authz| authz.status == "invalid")
            .unwrap()
    };

    // The CA hands the failed authorization out again once: that order is abandoned for a fresh one.
    state.lock().unwrap().faults.reuse_failed_once = true;
    let orders = state.lock().unwrap().orders.len();
    attempt(&acme, &identifiers, &csr).await.unwrap();
    let state = state.lock().unwrap();
    assert_eq!(state.orders.len() - orders, 2);
    assert!(state.orders[orders].authzs.contains(&failed));
    assert!(!state.orders.last().unwrap().authzs.contains(&failed));
    assert!(state.orders.last().unwrap().certificate.is_some());
    assert!(state.records.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn abandons_issuance_for_a_tunnel_deleted_meanwhile() {
    let dir = tempfile::tempdir().unwrap();
    let Some(url) = common::database_url(dir.path()).await else {
        return;
    };
    let (fake, state) = fake(Faults::default()).await;
    let (reached, release) = (Arc::new(Notify::new()), Arc::new(Notify::new()));
    state.lock().unwrap().pause_order = Some((reached.clone(), release.clone()));
    let arguments = arguments(dir.path(), fake);
    let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let server = TestServer::start(dir.path(), &arguments).await.unwrap();
    let service = server.service();
    service
        .create("deletedtunnl", hash_token("token"))
        .await
        .unwrap()
        .unwrap();
    service
        .bind_certificate(
            "deletedtunnl",
            "token",
            &csr(&format!("deletedtunnl.{DOMAIN}")),
        )
        .await
        .unwrap();
    let Some(record) = service.store.tunnel("deletedtunnl").await.unwrap() else {
        panic!("no tunnel");
    };
    let certificate = record.record.certificate_id.unwrap();

    // The job is placing its order when the tunnel is deleted.
    tokio::time::timeout(Duration::from_secs(10), reached.notified())
        .await
        .unwrap();
    service.remove("deletedtunnl", "token").await.unwrap();
    release.notify_one();

    let mut status = String::new();
    for _ in 0..200 {
        status = job_row(&url, &certificate).await.0;
        if status != "pending" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(status, "abandoned");
    let (pending, failed) = service.store.job_counts(0).await.unwrap();
    assert_eq!((pending, failed), (0, 0));
    server.stop().await;
}
