use serde::{Deserialize, Serialize};

pub const DEFAULT_API: &str = "https://opentunnel.xyz";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTunnelResponse {
    pub tunnel: TunnelInfo,
    pub token: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelState {
    Offline,
    Online,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelInfo {
    pub id: String,
    pub hostname: String,
    pub state: TunnelState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindCertificateRequest {
    pub csr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub id: String,
    pub state: CertificateState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum CertificateState {
    Challenge {
        token: String,
        key: String,
    },
    Issuing,
    Ready {
        certificate: String,
        chain: String,
        expiry: String,
    },
    Failed {
        reason: String,
    },
}

/// Error body returned by the HTTP API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    #[serde(rename = "_tag")]
    pub tag: String,
    #[serde(default)]
    pub message: String,
}

/// Retries of a failed API request: capped exponential backoff with jitter.
pub const RETRY_BASE_MS: u64 = 250;
pub const RETRY_MAX_MS: u64 = 8_000;
pub const RETRIES: u32 = 6;

/// How safely a request may be sent again after a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Repeat {
    /// Sending it twice has the effect of sending it once (reads, binding the same CSR): retried on any
    /// transient failure.
    Idempotent,
    /// Retried only when it cannot have reached the API (creating a tunnel, deleting one).
    Once,
}

/// Whether a response with `status` is a transient failure worth retrying.
pub fn retryable_status(status: u16, repeat: Repeat) -> bool {
    match repeat {
        Repeat::Idempotent => status == 429 || (500..=599).contains(&status),
        // Rate limited, the API's own "unavailable", or Cloudflare could not reach the server at all.
        Repeat::Once => matches!(status, 429 | 503 | 521 | 522 | 523 | 525),
    }
}

/// Before retry `attempt` (from 0): `RETRY_BASE_MS` doubling up to `RETRY_MAX_MS`, a random delay between half
/// of that and all of it. A `Retry-After` in seconds is followed instead, up to `RETRY_MAX_MS`. Returns the range in
/// milliseconds.
pub fn retry_delay_ms(attempt: u32, retry_after: Option<&str>) -> (u64, u64) {
    if let Some(seconds) = retry_after.and_then(|value| value.trim().parse::<u64>().ok()) {
        let delay = seconds.saturating_mul(1000).min(RETRY_MAX_MS);
        return (delay, delay);
    }
    let delay = RETRY_BASE_MS
        .saturating_mul(1 << attempt.min(16))
        .min(RETRY_MAX_MS);
    (delay / 2, delay)
}

/// What Cloudflare, which proxies the hosted API, means by its own 52x statuses.
pub fn cloudflare_reason(status: u16) -> Option<&'static str> {
    Some(match status {
        520 => "the server returned an unknown error",
        521 => "the server refused the connection",
        522 => "the connection to the server timed out",
        523 => "the server is unreachable",
        524 => "the server did not answer in time",
        525 => "the SSL handshake with the server failed",
        526 => "the server's certificate is invalid",
        527 => "the connection to the server failed",
        _ => return None,
    })
}

/// The message for an error response without an API error body.
pub fn status_message(status: u16, body: &str) -> String {
    if let Some(reason) = cloudflare_reason(status) {
        return format!("Cloudflare {status}: {reason}");
    }
    let body = body.trim();
    if body.is_empty() {
        format!("HTTP {status}")
    } else {
        body.chars().take(200).collect()
    }
}
