//! Whether a failed issuance attempt is worth repeating, and when. ZeroSSL fails often and briefly (502s from
//! its proxy, empty or HTML bodies, responses without a nonce), so those failures are retried with exponential
//! backoff for a day; errors that will not go away (a rejected identifier, a bad CSR, missing configuration)
//! fail at once, and anything unrecognized gets the original three attempts.

use std::time::Duration;

use crate::acme::{Problem, Transient};
use crate::clock::{DAY_MS, HOUR_MS};

/// Transient failures are retried until this long after the job was queued.
pub const RETRY_WINDOW_MS: u64 = DAY_MS;
/// The longest wait between two attempts.
pub const MAX_DELAY_MS: u64 = HOUR_MS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Likely to succeed later; `after` is the server's Retry-After.
    Transient { after: Option<Duration> },
    /// Will fail the same way again.
    Permanent,
    /// Unrecognized: a few attempts, as before.
    Unknown,
}

/// ACME problem types that no retry fixes (RFC 8555 section 6.7).
const PERMANENT_PROBLEMS: &[&str] = &[
    "rejectedIdentifier",
    "unsupportedIdentifier",
    "badCSR",
    "caa",
    "badSignatureAlgorithm",
    "badPublicKey",
    "externalAccountRequired",
    "accountDoesNotExist",
    "invalidContact",
    "unsupportedContact",
    "malformed",
];

const TRANSIENT_PROBLEMS: &[&str] = &["badNonce", "rateLimited", "serverInternal"];

/// Classifies an attempt's error by its typed causes, falling back to its message.
pub fn classify(error: &anyhow::Error) -> Class {
    for cause in error.chain() {
        if let Some(transient) = cause.downcast_ref::<Transient>() {
            return Class::Transient {
                after: transient.retry_after,
            };
        }
        if let Some(problem) = cause.downcast_ref::<Problem>() {
            return classify_problem(problem);
        }
        if let Some(error) = cause.downcast_ref::<reqwest::Error>() {
            if let Some(status) = error.status() {
                return classify_status(status.as_u16(), None);
            }
            if error.is_timeout()
                || error.is_connect()
                || error.is_request()
                || error.is_body()
                || error.is_decode()
            {
                return Class::Transient { after: None };
            }
        }
    }
    classify_reason(&format!("{error:#}"))
}

fn classify_problem(problem: &Problem) -> Class {
    let kind = problem.kind.rsplit(':').next().unwrap_or_default();
    if PERMANENT_PROBLEMS.contains(&kind) {
        return Class::Permanent;
    }
    if TRANSIENT_PROBLEMS.contains(&kind) {
        return Class::Transient {
            after: problem.retry_after,
        };
    }
    classify_status(problem.status, problem.retry_after)
}

fn classify_status(status: u16, after: Option<Duration>) -> Class {
    match status {
        429 | 500..=599 => Class::Transient { after },
        408 => Class::Transient { after: None },
        _ => Class::Unknown,
    }
}

/// Classifies a recorded failure reason (`jobs.last_error`), for failures recorded before the errors were
/// typed and for deciding which failed jobs to queue again.
pub fn classify_reason(reason: &str) -> Class {
    const PERMANENT: &[&str] = &[
        "Failed to persist certificate state",
        " are required",
        "is not a P-256 private JWK",
        "is not base64url",
        "CSR is not PEM",
        "did not offer dns-01",
        "a certificate for another key",
    ];
    const TRANSIENT: &[&str] = &[
        "returned no nonce",
        "error decoding response body",
        "error sending request",
        "operation timed out",
        "connection closed",
        "connection reset",
        "status server error",
        "authorization ended in pending",
        "An identical record already exists",
        "ACME directory",
    ];
    if PERMANENT.iter().any(|needle| reason.contains(needle)) {
        return Class::Permanent;
    }
    for problem in PERMANENT_PROBLEMS {
        if reason.contains(&format!("acme:error:{problem}")) {
            return Class::Permanent;
        }
    }
    for problem in TRANSIENT_PROBLEMS {
        if reason.contains(&format!("acme:error:{problem}")) {
            return Class::Transient { after: None };
        }
    }
    if TRANSIENT.iter().any(|needle| reason.contains(needle)) {
        return Class::Transient { after: None };
    }
    // "... | HTTP 502 | ..." from an ACME request.
    if let Some(index) = reason.find("| HTTP ")
        && let Ok(status) = reason[index + 7..]
            .chars()
            .take(3)
            .collect::<String>()
            .parse::<u16>()
    {
        return classify_status(status, None);
    }
    Class::Unknown
}

/// The wait before attempt `attempts + 1` after `attempts` failed ones: `base` doubled per attempt, capped at
/// an hour, with "equal jitter" (between half and all of it) from `jitter` in [0, 1) so that orders failed
/// together do not all come back together.
pub fn backoff(base_ms: u64, attempts: u32, jitter: f64) -> u64 {
    let exponent = attempts.saturating_sub(1).min(32);
    let delay = base_ms
        .saturating_mul(1u64 << exponent)
        .clamp(1, MAX_DELAY_MS);
    let half = delay / 2;
    half + (half as f64 * jitter.clamp(0.0, 1.0)) as u64
}

/// When to run a failed job again, or `None` to give up. `attempts` counts the failed attempts so far
/// (including this one), `queued_at` is when the job was queued.
pub fn next_attempt(
    class: Class,
    attempts: u32,
    base_ms: u64,
    queued_at: u64,
    now: u64,
    jitter: f64,
) -> Option<u64> {
    match class {
        Class::Permanent => None,
        Class::Unknown if attempts >= crate::jobs::ATTEMPTS => None,
        Class::Unknown => Some(now + backoff(base_ms, attempts, jitter)),
        Class::Transient { after } => {
            let delay = backoff(base_ms, attempts, jitter).max(
                after
                    .map_or(0, |after| after.as_millis() as u64)
                    .min(MAX_DELAY_MS),
            );
            let at = now + delay;
            (at <= queued_at + RETRY_WINDOW_MS).then_some(at)
        }
    }
}

/// A uniform value in [0, 1) for [`backoff`].
pub fn jitter() -> f64 {
    let bytes = crate::crypto::random_bytes::<4>();
    f64::from(u32::from_le_bytes(bytes)) / (f64::from(u32::MAX) + 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRODUCTION_FAILURES: &[&str] = &[
        "ACME server returned no nonce",
        "error decoding response body for url (https://acme.zerossl.com/v2/DV90): expected value at line 1 column 1",
        "fetching the ACME directory: error sending request for url (https://acme.zerossl.com/v2/DV90): operation timed out",
        "HTTP status server error (502 Bad Gateway) for url (https://acme.zerossl.com/v2/DV90)",
        "ACME request to https://acme.zerossl.com/v2/DV90/authz/PW1xyIA7-tJ_s2xqgqJ7lA failed | HTTP 502 | <html>\\n<head><title>502 Bad Gateway</title></head>",
        "ACME authorization ended in pending",
        "An identical record already exists.",
    ];

    #[test]
    fn retries_every_transient_failure_seen_in_production() {
        for reason in PRODUCTION_FAILURES {
            assert_eq!(
                classify_reason(reason),
                Class::Transient { after: None },
                "{reason}"
            );
            assert!(matches!(
                classify(&anyhow::anyhow!("{reason}")),
                Class::Transient { .. }
            ));
        }
    }

    #[test]
    fn fails_fast_on_permanent_errors() {
        for reason in [
            "urn:ietf:params:acme:error:rejectedIdentifier: DNS identifier is invalid [opentunnel.xyz] | HTTP 400 | {}",
            "urn:ietf:params:acme:error:badCSR: bad | HTTP 400 | {}",
            "ACME_EAB_KID and ACME_EAB_HMAC_KEY are required",
            "ACME_ACCOUNT_KEY_JWK is not a P-256 private JWK",
            "Failed to persist certificate state: tunnel or certificate not found",
        ] {
            assert_eq!(classify_reason(reason), Class::Permanent, "{reason}");
        }
        assert_eq!(
            classify_reason("ACME authorization ended in invalid"),
            Class::Unknown
        );
        assert_eq!(
            classify_reason("ACME request to x failed | HTTP 404 | nope"),
            Class::Unknown
        );
        assert_eq!(
            classify_reason("urn:ietf:params:acme:error:rateLimited: slow down | HTTP 429 | {}"),
            Class::Transient { after: None }
        );
    }

    #[test]
    fn classifies_typed_errors() {
        let problem = |status, kind: &str, retry_after| {
            anyhow::Error::new(Problem {
                status,
                kind: format!("urn:ietf:params:acme:error:{kind}"),
                retry_after,
                message: "x".into(),
            })
            .context("issuing")
        };
        let after = Some(Duration::from_secs(90));
        assert_eq!(
            classify(&problem(429, "rateLimited", after)),
            Class::Transient { after }
        );
        assert_eq!(
            classify(&problem(503, "", None)),
            Class::Transient { after: None }
        );
        assert_eq!(
            classify(&problem(400, "badNonce", None)),
            Class::Transient { after: None }
        );
        assert_eq!(
            classify(&problem(400, "rejectedIdentifier", None)),
            Class::Permanent
        );
        assert_eq!(
            classify(&problem(403, "unauthorized", None)),
            Class::Unknown
        );
        let transient = anyhow::Error::new(Transient {
            message: "ACME server returned no nonce (HTTP 503)".into(),
            retry_after: None,
        });
        assert_eq!(classify(&transient), Class::Transient { after: None });
    }

    #[test]
    fn backs_off_exponentially_with_jitter_up_to_an_hour() {
        let base = 15_000;
        assert_eq!(backoff(base, 1, 0.999_999), 14_999);
        assert_eq!(backoff(base, 1, 0.0), 7_500);
        assert_eq!(backoff(base, 2, 0.0), 15_000);
        assert_eq!(backoff(base, 3, 0.0), 30_000);
        assert_eq!(backoff(base, 9, 0.0), MAX_DELAY_MS / 2);
        assert!((MAX_DELAY_MS - 10..MAX_DELAY_MS).contains(&backoff(base, 40, 0.999_999)));
        for attempts in 1..60 {
            for jitter in [0.0, 0.3, 0.999] {
                let delay = backoff(base, attempts, jitter);
                assert!(
                    (3_750..=MAX_DELAY_MS).contains(&delay),
                    "{attempts} {jitter}"
                );
            }
        }
        let j = jitter();
        assert!((0.0..1.0).contains(&j));
    }

    #[test]
    fn retries_transient_failures_for_a_day() {
        let transient = Class::Transient { after: None };
        let (base, queued) = (15_000, 1_000_000);
        // Without jitter (the longest waits), count the attempts a day allows.
        let (mut now, mut attempts) = (queued, 1);
        while let Some(at) = next_attempt(transient, attempts, base, queued, now, 0.999_999) {
            assert!(at - now <= MAX_DELAY_MS);
            now = at;
            attempts += 1;
        }
        assert!(now - queued <= RETRY_WINDOW_MS);
        assert!(now - queued > RETRY_WINDOW_MS - MAX_DELAY_MS);
        assert!((25..40).contains(&attempts), "{attempts} attempts");

        // Retry-After is honored, up to the cap.
        let after = Class::Transient {
            after: Some(Duration::from_secs(600)),
        };
        assert_eq!(
            next_attempt(after, 1, base, queued, queued, 0.0),
            Some(queued + 600_000)
        );
        let long = Class::Transient {
            after: Some(Duration::from_secs(86_400)),
        };
        assert_eq!(
            next_attempt(long, 1, base, queued, queued, 0.0),
            Some(queued + MAX_DELAY_MS)
        );

        assert_eq!(
            next_attempt(Class::Permanent, 1, base, queued, queued, 0.0),
            None
        );
        assert_eq!(
            next_attempt(Class::Unknown, 2, base, queued, queued, 0.0),
            Some(queued + 15_000)
        );
        assert_eq!(
            next_attempt(Class::Unknown, 3, base, queued, queued, 0.0),
            None
        );
    }
}
