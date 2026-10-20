//! Authentication between machines without sending the shared secret (`INTERNAL_TOKEN`): every proof is an
//! HMAC-SHA256 keyed with it over fresh nonces or a timestamp, the roles and the machine IDs involved, so a
//! listener that answers the private network learns nothing it could reuse.
//!
//! - Mesh links: a challenge and response both ways (`mesh.rs`).
//! - Forwarded visitors and control requests: signed with a timestamp and a nonce, which the receiver accepts
//!   once and only within [`MAX_SKEW_MS`] of its own clock (`cluster.rs`).

use std::collections::HashMap;
use std::sync::Mutex;

use ring::hmac;

use crate::crypto::{hex, random_bytes};

/// How far a signed request's timestamp may be from the receiver's clock.
pub const MAX_SKEW_MS: u64 = 30_000;
/// Nonces remembered at most; beyond it the expired ones are dropped, then the oldest.
const MAX_NONCES: usize = 100_000;

pub struct Secret {
    key: hmac::Key,
}

/// A fresh random nonce, 32 hex characters.
pub fn nonce() -> String {
    hex(&random_bytes::<16>())
}

/// Each part prefixed with its length, so no two different lists of parts sign the same bytes.
fn message(parts: &[&str]) -> Vec<u8> {
    let mut message = Vec::with_capacity(parts.iter().map(|part| part.len() + 4).sum());
    for part in parts {
        message.extend_from_slice(&(part.len() as u32).to_be_bytes());
        message.extend_from_slice(part.as_bytes());
    }
    message
}

impl Secret {
    pub fn new(token: &str) -> Self {
        Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, token.as_bytes()),
        }
    }

    /// The proof over `parts` (the first is a label naming the purpose and role), as lowercase hex.
    pub fn sign(&self, parts: &[&str]) -> String {
        hex(hmac::sign(&self.key, &message(parts)).as_ref())
    }

    /// Whether `proof` is [`sign`](Self::sign) of `parts`, compared in constant time.
    pub fn verify(&self, parts: &[&str], proof: &str) -> bool {
        let Some(tag) = decode_hex(proof) else {
            return false;
        };
        hmac::verify(&self.key, &message(parts), &tag).is_ok()
    }
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) || value.len() > 128 {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(value.get(index..index + 2)?, 16).ok())
        .collect()
}

/// Whether a signed timestamp is close enough to `now`.
pub fn fresh(timestamp: u64, now: u64) -> bool {
    timestamp.abs_diff(now) <= MAX_SKEW_MS
}

/// Nonces of signed requests already accepted, so a captured request cannot be replayed while it is fresh.
#[derive(Default)]
pub struct Nonces {
    seen: Mutex<HashMap<String, u64>>,
}

impl Nonces {
    /// Records `nonce` (signed at `timestamp`) unless it was seen before. Returns whether it is new.
    pub fn first_use(&self, nonce: &str, timestamp: u64, now: u64) -> bool {
        let mut seen = self.seen.lock().expect("nonces lock");
        if seen.len() >= MAX_NONCES {
            let cutoff = now.saturating_sub(MAX_SKEW_MS);
            seen.retain(|_, at| *at >= cutoff);
            if seen.len() >= MAX_NONCES {
                // Only reachable with that many valid requests within the window: forget the oldest half.
                let mut times: Vec<u64> = seen.values().copied().collect();
                times.sort_unstable();
                let median = times[times.len() / 2];
                seen.retain(|_, at| *at > median);
            }
        }
        if seen.contains_key(nonce) {
            return false;
        }
        seen.insert(nonce.to_owned(), timestamp);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proofs_verify_only_for_the_same_secret_and_parts() {
        let secret = Secret::new("secret");
        let proof = secret.sign(&["mesh/2 accept", "a", "b", "n1", "n2"]);
        assert_eq!(proof.len(), 64);
        assert!(secret.verify(&["mesh/2 accept", "a", "b", "n1", "n2"], &proof));
        assert!(!secret.verify(&["mesh/2 dial", "a", "b", "n1", "n2"], &proof));
        assert!(!secret.verify(&["mesh/2 accept", "a", "b", "n1", "n3"], &proof));
        // Moving bytes between parts changes the message.
        assert!(!secret.verify(&["mesh/2 accept", "ab", "", "n1", "n2"], &proof));
        assert!(!Secret::new("other").verify(&["mesh/2 accept", "a", "b", "n1", "n2"], &proof));
        assert!(!secret.verify(&["mesh/2 accept", "a", "b", "n1", "n2"], "zz"));
        assert!(!secret.verify(&["mesh/2 accept", "a", "b", "n1", "n2"], ""));
    }

    #[test]
    fn nonces_are_accepted_once_and_timestamps_only_when_fresh() {
        let nonces = Nonces::default();
        assert!(nonces.first_use("a", 1_000, 1_000));
        assert!(!nonces.first_use("a", 1_000, 1_001));
        assert!(nonces.first_use("b", 1_000, 1_001));
        assert!(fresh(100_000, 100_000 + MAX_SKEW_MS));
        assert!(fresh(100_000 + MAX_SKEW_MS, 100_000));
        assert!(!fresh(100_000, 100_001 + MAX_SKEW_MS));
        assert_ne!(nonce(), nonce());
    }
}
