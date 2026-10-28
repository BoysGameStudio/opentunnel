//! Tencent Cloud DNSPod API 3.0, restricted to ACME DNS-01 TXT records.
//!
//! Official API references: CreateRecord (api/1427/56180), DescribeRecordList
//! (api/1427/56166), DeleteRecord (api/1427/56176), version 2021-03-23.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use ring::hmac;
use serde::Deserialize;
use serde_json::{Value, json};

const SERVICE: &str = "dnspod";
const VERSION: &str = "2021-03-23";
const DEFAULT_LINE: &str = "默认";
const PAGE_SIZE: u32 = 3000;
const MAX_PAGES: u32 = 1000;
const DELETE_TRIES: u32 = 4;

#[derive(Clone)]
pub struct DnsPod {
    http: reqwest::Client,
    api: url::Url,
    host: String,
    domain: String,
    secret_id: String,
    secret_key: String,
    request_timeout: Duration,
    retry_pause: Duration,
    index_timeout: Duration,
    index_poll: Duration,
}

#[derive(Debug, Deserialize)]
struct Envelope {
    #[serde(rename = "Response")]
    response: ResponseBody,
}

#[derive(Debug, Default, Deserialize)]
struct ResponseBody {
    #[serde(rename = "RecordId")]
    record_id: Option<u64>,
    #[serde(rename = "RecordList", default)]
    records: Vec<RecordItem>,
    #[serde(rename = "RecordCountInfo")]
    count: Option<RecordCount>,
    #[serde(rename = "Error")]
    error: Option<ErrorBody>,
    #[serde(rename = "RequestId", default)]
    request_id: String,
}

#[derive(Debug, Deserialize)]
struct RecordCount {
    #[serde(rename = "TotalCount", default)]
    total: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct RecordItem {
    #[serde(rename = "RecordId")]
    id: u64,
    #[serde(rename = "Name", default)]
    name: String,
    #[serde(rename = "Value", default)]
    value: String,
    #[serde(rename = "Type", default)]
    kind: String,
    #[serde(rename = "Line", default)]
    line: String,
}

#[derive(Debug, Deserialize)]
struct ErrorBody {
    #[serde(rename = "Code", default)]
    code: String,
}

#[derive(Debug)]
struct Failure {
    message: String,
    code: String,
    retryable: bool,
    retry_after: Option<Duration>,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never include request headers, credentials or upstream error text, which can reflect input.
        f.write_str(&self.message)
    }
}

impl std::error::Error for Failure {}

/// Waits for DNSPod's eventually consistent record index. Returns false at the bounded deadline.
async fn index_wait(deadline: tokio::time::Instant, poll: Duration) -> bool {
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() {
        return false;
    }
    tokio::time::sleep(remaining.min(poll)).await;
    tokio::time::Instant::now() < deadline
}

impl DnsPod {
    pub fn new(
        http: reqwest::Client,
        api: &str,
        domain: &str,
        secret_id: String,
        secret_key: String,
    ) -> Result<Self> {
        let api = url::Url::parse(api).context("invalid DNSPOD_API_URL")?;
        if !matches!(api.scheme(), "http" | "https")
            || api.host_str().is_none()
            || api.path() != "/"
            || api.query().is_some()
            || api.fragment().is_some()
        {
            bail!("DNSPOD_API_URL must be an HTTP(S) origin without a path or query");
        }
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        if domain.is_empty() || secret_id.is_empty() || secret_key.is_empty() {
            bail!("DNSPod domain and credentials must not be empty");
        }
        let mut host = api.host_str().expect("checked").to_owned();
        if let Some(port) = api.port() {
            host.push_str(&format!(":{port}"));
        }
        Ok(Self {
            http,
            api,
            host,
            domain,
            secret_id,
            secret_key,
            request_timeout: Duration::from_secs(30),
            retry_pause: Duration::from_secs(1),
            // DNSPod documents an indexing delay of about 30 seconds for new records.
            index_timeout: Duration::from_secs(30),
            index_poll: Duration::from_secs(1),
        })
    }

    fn challenge_name(&self, name: &str) -> Result<String> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        let suffix = format!(".{}", self.domain);
        let Some(subdomain) = name.strip_suffix(&suffix) else {
            bail!("DNSPod challenge name is outside the configured domain");
        };
        if subdomain != "_acme-challenge" && !subdomain.starts_with("_acme-challenge.") {
            bail!("DNSPod provider only manages _acme-challenge names");
        }
        Ok(subdomain.to_owned())
    }

    fn authorization(&self, action: &str, payload: &str, timestamp: u64) -> String {
        let algorithm = "TC3-HMAC-SHA256";
        let date = humantime::format_rfc3339_seconds(UNIX_EPOCH + Duration::from_secs(timestamp));
        let date = &date.to_string()[..10];
        let canonical_headers = format!(
            "content-type:application/json; charset=utf-8\nhost:{}\nx-tc-action:{}\n",
            self.host,
            action.to_ascii_lowercase()
        );
        let canonical = format!(
            "POST\n/\n\n{canonical_headers}\ncontent-type;host;x-tc-action\n{}",
            crate::crypto::hex(
                ring::digest::digest(&ring::digest::SHA256, payload.as_bytes()).as_ref()
            )
        );
        let scope = format!("{date}/{SERVICE}/tc3_request");
        let string_to_sign = format!(
            "{algorithm}\n{timestamp}\n{scope}\n{}",
            crate::crypto::hex(
                ring::digest::digest(&ring::digest::SHA256, canonical.as_bytes()).as_ref()
            )
        );
        let derive = |key: &[u8], value: &str| {
            hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), value.as_bytes())
                .as_ref()
                .to_vec()
        };
        let secret_date = derive(format!("TC3{}", self.secret_key).as_bytes(), date);
        let secret_service = derive(&secret_date, SERVICE);
        let secret_signing = derive(&secret_service, "tc3_request");
        let signature = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, &secret_signing),
            string_to_sign.as_bytes(),
        );
        format!(
            "{algorithm} Credential={}/{scope}, SignedHeaders=content-type;host;x-tc-action, Signature={}",
            self.secret_id,
            crate::crypto::hex(signature.as_ref())
        )
    }

    async fn call(
        &self,
        action: &str,
        payload: Value,
    ) -> std::result::Result<ResponseBody, Failure> {
        let payload = payload.to_string();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let response = self
            .http
            .post(self.api.clone())
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/json; charset=utf-8",
            )
            .header("X-TC-Action", action)
            .header("X-TC-Version", VERSION)
            .header("X-TC-Timestamp", timestamp.to_string())
            .header(
                reqwest::header::AUTHORIZATION,
                self.authorization(action, &payload, timestamp),
            )
            .body(payload)
            .timeout(self.request_timeout)
            .send()
            .await
            .map_err(|error| Failure {
                message: format!("DNSPod {action} request failed: {error}"),
                code: String::new(),
                retryable: error.is_timeout() || error.is_connect() || error.is_request(),
                retry_after: None,
            })?;
        let status = response.status();
        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<u64>().ok())
            .map(|seconds| Duration::from_secs(seconds.min(30)));
        let body = response.bytes().await.map_err(|error| Failure {
            message: format!("DNSPod {action} response could not be read: {error}"),
            code: String::new(),
            retryable: status == 429 || status.is_server_error(),
            retry_after,
        })?;
        let envelope: Envelope = serde_json::from_slice(&body).map_err(|_| Failure {
            message: format!("DNSPod {action} returned an unreadable response"),
            code: String::new(),
            retryable: status == 429 || status.is_server_error(),
            retry_after,
        })?;
        if !status.is_success() {
            return Err(Failure {
                message: format!("DNSPod {action} failed: HTTP {}", status.as_u16()),
                code: envelope
                    .response
                    .error
                    .map(|error| error.code)
                    .unwrap_or_default(),
                retryable: status == 429 || status.is_server_error(),
                retry_after,
            });
        }
        if let Some(error) = envelope.response.error {
            let retryable = matches!(
                error.code.as_str(),
                "RequestLimitExceeded"
                    | "RequestLimitExceeded.RequestLimitExceeded"
                    | "FailedOperation.FrequencyLimit"
                    | "InternalError"
            );
            let request_id = envelope.response.request_id;
            return Err(Failure {
                message: format!("DNSPod {action} failed: {} ({request_id})", error.code),
                code: error.code,
                retryable,
                retry_after,
            });
        }
        Ok(envelope.response)
    }

    async fn list(&self, name: &str) -> Result<Vec<RecordItem>> {
        let subdomain = self.challenge_name(name)?;
        let mut records = Vec::new();
        for page in 0..MAX_PAGES {
            let offset = page * PAGE_SIZE;
            let response = self
                .call(
                    "DescribeRecordList",
                    json!({
                        "Domain": self.domain,
                        "SubDomain": subdomain,
                        "RecordType": "TXT",
                        "RecordLine": DEFAULT_LINE,
                        "RecordLineId": "0",
                        "ErrorOnEmpty": "no",
                        "Offset": offset,
                        "Limit": PAGE_SIZE,
                    }),
                )
                .await?;
            let count = response.records.len() as u32;
            records.extend(response.records.into_iter().filter(|record| {
                record.kind == "TXT"
                    && record.line == DEFAULT_LINE
                    && record.name.eq_ignore_ascii_case(&subdomain)
            }));
            let total = response.count.map_or(0, |count| count.total);
            if count < PAGE_SIZE || u64::from(offset + count) >= total {
                return Ok(records);
            }
        }
        bail!("DNSPod record listing exceeded {MAX_PAGES} pages")
    }

    pub async fn create_txt(&self, name: &str, value: &str) -> Result<crate::dns::TxtRecord> {
        let subdomain = self.challenge_name(name)?;
        // Every active attempt owns only the ID returned by its own CreateRecord. Never adopt
        // an identical record: another process may still be using it, and DNSPod has no
        // cross-process ownership/lease operation or create idempotency key.
        let response = self
            .call(
                "CreateRecord",
                json!({
                    "Domain": self.domain,
                    "SubDomain": subdomain,
                    "RecordType": "TXT",
                    "RecordLine": DEFAULT_LINE,
                    "RecordLineId": "0",
                    "Value": value,
                }),
            )
            .await?;
        let id = response
            .record_id
            .context("DNSPod CreateRecord omitted RecordId")?;
        Ok(crate::dns::TxtRecord {
            name: name.into(),
            value: value.into(),
            id: Some(id.to_string()),
        })
    }

    #[cfg(test)]
    async fn find_txt(&self, name: &str, value: &str) -> Result<Option<String>> {
        Ok(self
            .list(name)
            .await?
            .into_iter()
            .find(|record| record.value.trim_matches('"') == value)
            .map(|record| record.id.to_string()))
    }

    async fn owns(&self, record: &crate::dns::TxtRecord, id: u64) -> Result<bool> {
        let deadline = tokio::time::Instant::now() + self.index_timeout;
        loop {
            let records = self.list(&record.name).await?;
            // A visible ID with a different value is authoritative: never wait and then delete it.
            if let Some(current) = records.iter().find(|current| current.id == id) {
                return Ok(current.value.trim_matches('"') == record.value);
            }
            // The ID may be missing because creation is not indexed yet, or because it is already gone.
            if !index_wait(deadline, self.index_poll).await {
                return Ok(false);
            }
        }
    }

    /// Deletes only the exact record ID returned by create/find, and only while its value still matches.
    pub async fn delete_txt(&self, record: &crate::dns::TxtRecord) -> Result<()> {
        let Some(id) = record.id.as_deref().and_then(|id| id.parse::<u64>().ok()) else {
            return Ok(());
        };
        if !self.owns(record, id).await? {
            return Ok(());
        }
        let mut pause = self.retry_pause;
        let mut last = None;
        for attempt in 1..=DELETE_TRIES {
            match self
                .call(
                    "DeleteRecord",
                    json!({ "Domain": self.domain, "RecordId": id }),
                )
                .await
            {
                Ok(_) => return Ok(()),
                Err(error) if error.code == "InvalidParameter.RecordIdInvalid" => {
                    if !self.owns(record, id).await? {
                        return Ok(());
                    }
                    last = Some(error);
                }
                Err(error) => {
                    let retryable = error.retryable;
                    if let Some(wait) = error.retry_after {
                        pause = pause.max(wait);
                    }
                    last = Some(error);
                    if !retryable {
                        break;
                    }
                }
            }
            if attempt < DELETE_TRIES {
                tokio::time::sleep(pause).await;
                pause *= 2;
            }
        }
        Err(last
            .unwrap_or_else(|| Failure {
                message: "DNSPod DeleteRecord failed".into(),
                code: String::new(),
                retryable: false,
                retry_after: None,
            })
            .into())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::Mutex;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    #[derive(Debug, Clone)]
    struct Seen {
        action: String,
        authorization: String,
        body: Value,
    }

    async fn mock(responses: Vec<(u16, String)>) -> (DnsPod, Arc<Mutex<Vec<Seen>>>) {
        crate::install_crypto_provider();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let capture = seen.clone();
        tokio::spawn(async move {
            for (status, body) in responses {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                let mut buffer = [0u8; 4096];
                let (headers, body_start, length) = loop {
                    let read = socket.read(&mut buffer).await.unwrap();
                    assert_ne!(read, 0);
                    bytes.extend_from_slice(&buffer[..read]);
                    if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                        let headers = String::from_utf8(bytes[..end].to_vec()).unwrap();
                        let length = headers
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(str::to_owned)
                            })
                            .and_then(|value| value.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        break (headers, end + 4, length);
                    }
                };
                while bytes.len() < body_start + length {
                    let read = socket.read(&mut buffer).await.unwrap();
                    bytes.extend_from_slice(&buffer[..read]);
                }
                let action = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("x-tc-action")
                            .then(|| value.trim().to_owned())
                    })
                    .unwrap();
                let authorization = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .starts_with("authorization:")
                            .then(|| line.to_owned())
                    })
                    .unwrap_or_default();
                capture.lock().unwrap().push(Seen {
                    action,
                    authorization,
                    body: serde_json::from_slice(&bytes[body_start..body_start + length]).unwrap(),
                });
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });
        let mut provider = DnsPod::new(
            reqwest::Client::new(),
            &api,
            "example.test",
            "test-secret-id".into(),
            "test-secret-key".into(),
        )
        .unwrap();
        provider.request_timeout = Duration::from_millis(100);
        provider.retry_pause = Duration::from_millis(1);
        provider.index_timeout = Duration::from_millis(100);
        provider.index_poll = Duration::from_millis(1);
        (provider, seen)
    }

    fn response(body: &str) -> (u16, String) {
        (200, body.into())
    }

    #[test]
    fn signs_tc3_without_exposing_the_secret_key() {
        crate::install_crypto_provider();
        let provider = DnsPod::new(
            reqwest::Client::new(),
            "https://dnspod.tencentcloudapi.com",
            "example.test",
            "id".into(),
            "key".into(),
        )
        .unwrap();
        let authorization = provider.authorization("CreateRecord", "{}", 1_700_000_000);
        assert!(authorization.starts_with("TC3-HMAC-SHA256 Credential=id/2023-11-14/dnspod/tc3_request, SignedHeaders=content-type;host;x-tc-action, Signature="));
        assert!(
            authorization
                .ends_with("16d1b3d29cc241bba4b90f5bb2f5739396283f62b2d1a6104b2c41680595ffd8")
        );
        assert!(!authorization.contains("TC3key"));
    }

    #[tokio::test]
    async fn creates_a_default_line_txt_and_returns_its_id() {
        let (provider, seen) = mock(vec![response(
            r#"{"Response":{"RecordId":162,"RequestId":"r"}}"#,
        )])
        .await;
        let record = provider
            .create_txt("_acme-challenge.demo.example.test", "value-a")
            .await
            .unwrap();
        assert_eq!(record.id.as_deref(), Some("162"));
        let seen = seen.lock().unwrap();
        assert_eq!(seen[0].action, "CreateRecord");
        assert_eq!(seen[0].body["SubDomain"], "_acme-challenge.demo");
        assert_eq!(seen[0].body["RecordLine"], "默认");
        assert_eq!(seen[0].body["RecordLineId"], "0");
        assert_eq!(seen[0].body["RecordType"], "TXT");
        assert!(seen[0].body.get("TTL").is_none());
        assert!(seen[0].authorization.contains("Credential=test-secret-id/"));
        assert!(!seen[0].authorization.contains("test-secret-key"));
    }

    #[tokio::test]
    async fn identical_create_is_refused_instead_of_adopting_a_shared_record() {
        let (provider, seen) = mock(vec![response(
            r#"{"Response":{"Error":{"Code":"InvalidParameter.DomainRecordExist"},"RequestId":"r1"}}"#,
        )])
        .await;
        let error = provider
            .create_txt("_acme-challenge.demo.example.test", "value-a")
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("InvalidParameter.DomainRecordExist")
        );
        // No Describe/Delete and no ownership claim on somebody else's RecordId.
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn identical_concurrent_attempts_clean_up_only_their_own_ids() {
        let (provider, seen) = mock(vec![
            response(r#"{"Response":{"RecordId":1,"RequestId":"create-1"}}"#),
            response(r#"{"Response":{"RecordId":2,"RequestId":"create-2"}}"#),
            response(r#"{"Response":{"RecordCountInfo":{"TotalCount":2},"RecordList":[{"RecordId":1,"Name":"_acme-challenge.demo","Value":"same","Type":"TXT","Line":"默认"},{"RecordId":2,"Name":"_acme-challenge.demo","Value":"same","Type":"TXT","Line":"默认"}],"RequestId":"list-1"}}"#),
            response(r#"{"Response":{"RequestId":"delete-1"}}"#),
            response(r#"{"Response":{"RecordCountInfo":{"TotalCount":1},"RecordList":[{"RecordId":2,"Name":"_acme-challenge.demo","Value":"same","Type":"TXT","Line":"默认"}],"RequestId":"list-2"}}"#),
            response(r#"{"Response":{"RequestId":"delete-2"}}"#),
        ])
        .await;
        let first = provider
            .create_txt("_acme-challenge.demo.example.test", "same")
            .await
            .unwrap();
        let second = provider
            .create_txt("_acme-challenge.demo.example.test", "same")
            .await
            .unwrap();
        assert_eq!(first.id.as_deref(), Some("1"));
        assert_eq!(second.id.as_deref(), Some("2"));

        provider.delete_txt(&first).await.unwrap();
        {
            let seen = seen.lock().unwrap();
            assert_eq!(seen.len(), 4);
            assert_eq!(seen[3].action, "DeleteRecord");
            assert_eq!(seen[3].body["RecordId"], 1);
            // The second attempt's required TXT remains; no delete of ID 2 occurred.
            assert!(!seen.iter().any(|request| {
                request.action == "DeleteRecord" && request.body["RecordId"] == 2
            }));
        }

        provider.delete_txt(&second).await.unwrap();
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 6);
        assert_eq!(seen[4].action, "DescribeRecordList");
        assert_eq!(seen[4].body["SubDomain"], "_acme-challenge.demo");
        assert_eq!(seen[5].action, "DeleteRecord");
        assert_eq!(seen[5].body["RecordId"], 2);
    }

    #[tokio::test]
    async fn delete_waits_for_indexing_then_preserves_other_values() {
        let (provider, seen) = mock(vec![
            response(r#"{"Response":{"RecordCountInfo":{"TotalCount":0},"RecordList":[],"RequestId":"r1"}}"#),
            response(r#"{"Response":{"RecordCountInfo":{"TotalCount":2},"RecordList":[{"RecordId":1,"Name":"_acme-challenge.demo","Value":"value-a","Type":"TXT","Line":"默认"},{"RecordId":2,"Name":"_acme-challenge.demo","Value":"value-b","Type":"TXT","Line":"默认"}],"RequestId":"r2"}}"#),
            response(r#"{"Response":{"RequestId":"r3"}}"#),
        ])
        .await;
        provider
            .delete_txt(&crate::dns::TxtRecord {
                name: "_acme-challenge.demo.example.test".into(),
                value: "value-a".into(),
                id: Some("1".into()),
            })
            .await
            .unwrap();
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 3);
        assert_eq!(seen[2].action, "DeleteRecord");
        assert_eq!(seen[2].body["RecordId"], 1);
    }

    #[tokio::test]
    async fn missing_record_index_wait_is_bounded() {
        let (mut provider, seen) = mock(
            (0..20)
                .map(|_| {
                    response(
                        r#"{"Response":{"RecordCountInfo":{"TotalCount":0},"RecordList":[],"RequestId":"r"}}"#,
                    )
                })
                .collect(),
        )
        .await;
        provider.index_timeout = Duration::from_millis(10);
        provider.index_poll = Duration::from_millis(2);
        provider
            .delete_txt(&crate::dns::TxtRecord {
                name: "_acme-challenge.demo.example.test".into(),
                value: "value-a".into(),
                id: Some("1".into()),
            })
            .await
            .unwrap();
        let calls = seen.lock().unwrap().len();
        assert!((1..=20).contains(&calls));
    }

    #[tokio::test]
    async fn deterministic_errors_are_not_retried_and_secrets_are_redacted() {
        let (provider, seen) = mock(vec![response(
            r#"{"Response":{"Error":{"Code":"InvalidParameterValue.DomainNotExists","Message":"test-secret-id test-secret-key value-a"},"RequestId":"request-safe"}}"#,
        )])
        .await;
        let error = provider
            .create_txt("_acme-challenge.demo.example.test", "value-a")
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(seen.lock().unwrap().len(), 1);
        assert!(error.contains("InvalidParameterValue.DomainNotExists"));
        assert!(error.contains("request-safe"));
        for secret in ["test-secret-id", "test-secret-key", "value-a"] {
            assert!(!error.contains(secret), "{error}");
        }
    }

    #[tokio::test]
    async fn delete_checks_id_and_value_and_preserves_concurrent_txt() {
        let (provider, seen) = mock(vec![
            response(r#"{"Response":{"RecordCountInfo":{"TotalCount":2},"RecordList":[{"RecordId":1,"Name":"_acme-challenge.demo","Value":"value-a","Type":"TXT","Line":"默认"},{"RecordId":2,"Name":"_acme-challenge.demo","Value":"value-b","Type":"TXT","Line":"默认"}],"RequestId":"r1"}}"#),
            response(r#"{"Response":{"RequestId":"r2"}}"#),
        ])
        .await;
        provider
            .delete_txt(&crate::dns::TxtRecord {
                name: "_acme-challenge.demo.example.test".into(),
                value: "value-a".into(),
                id: Some("1".into()),
            })
            .await
            .unwrap();
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[1].action, "DeleteRecord");
        assert_eq!(seen[1].body["RecordId"], 1);
    }

    #[tokio::test]
    async fn changed_or_foreign_record_is_not_deleted() {
        let (provider, seen) = mock(vec![response(
            r#"{"Response":{"RecordCountInfo":{"TotalCount":1},"RecordList":[{"RecordId":1,"Name":"_acme-challenge.demo","Value":"different","Type":"TXT","Line":"默认"}],"RequestId":"r"}}"#,
        )])
        .await;
        provider
            .delete_txt(&crate::dns::TxtRecord {
                name: "_acme-challenge.demo.example.test".into(),
                value: "value-a".into(),
                id: Some("1".into()),
            })
            .await
            .unwrap();
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn finds_a_value_on_a_later_page() {
        let first = (0..3000)
            .map(|id| format!(r#"{{"RecordId":{id},"Name":"_acme-challenge.demo","Value":"other","Type":"TXT","Line":"默认"}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let (provider, seen) = mock(vec![
            response(&format!(r#"{{"Response":{{"RecordCountInfo":{{"TotalCount":3001}},"RecordList":[{first}],"RequestId":"r1"}}}}"#)),
            response(r#"{"Response":{"RecordCountInfo":{"TotalCount":3001},"RecordList":[{"RecordId":3000,"Name":"_acme-challenge.demo","Value":"wanted","Type":"TXT","Line":"默认"}],"RequestId":"r2"}}"#),
        ])
        .await;
        assert_eq!(
            provider
                .find_txt("_acme-challenge.demo.example.test", "wanted")
                .await
                .unwrap()
                .as_deref(),
            Some("3000")
        );
        let seen = seen.lock().unwrap();
        assert_eq!(seen[1].body["Offset"], 3000);
        assert_eq!(seen[0].body["Limit"], 3000);
    }

    #[tokio::test]
    async fn retries_rate_limits_and_transport_timeouts() {
        let (provider, seen) = mock(vec![
            response(r#"{"Response":{"RecordList":[{"RecordId":1,"Name":"_acme-challenge.demo","Value":"value-a","Type":"TXT","Line":"默认"}],"RequestId":"r1"}}"#),
            (429, r#"{"Response":{"Error":{"Code":"RequestLimitExceeded"},"RequestId":"r2"}}"#.into()),
            response(r#"{"Response":{"RequestId":"r3"}}"#),
        ])
        .await;
        provider
            .delete_txt(&crate::dns::TxtRecord {
                name: "_acme-challenge.demo.example.test".into(),
                value: "value-a".into(),
                id: Some("1".into()),
            })
            .await
            .unwrap();
        assert_eq!(seen.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn rejects_non_challenge_names() {
        crate::install_crypto_provider();
        let provider = DnsPod::new(
            reqwest::Client::new(),
            "https://dnspod.tencentcloudapi.com",
            "example.test",
            "id".into(),
            "key".into(),
        )
        .unwrap();
        assert!(
            provider
                .create_txt("www.example.test", "value")
                .await
                .is_err()
        );
        assert!(
            provider
                .create_txt("_acme-challenge.other.test", "value")
                .await
                .is_err()
        );
    }
}

#[cfg(test)]
mod timeout_tests {
    use std::time::Duration;

    use tokio::net::TcpListener;

    use super::*;

    #[tokio::test]
    async fn create_times_out_without_blindly_retrying_a_possible_write() {
        crate::install_crypto_provider();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api = format!("http://{}", listener.local_addr().unwrap());
        let connections = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                held.push(socket);
            }
        });
        let mut provider = DnsPod::new(
            reqwest::Client::new(),
            &api,
            "example.test",
            "id".into(),
            "key".into(),
        )
        .unwrap();
        provider.request_timeout = Duration::from_millis(20);
        let error = provider
            .create_txt("_acme-challenge.demo.example.test", "value")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("request failed"), "{error:#}");
        connections.abort();
    }
}
