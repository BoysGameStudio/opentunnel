//! The hosted OpenTunnel service: one process that routes public TLS by SNI to tunnel clients over their
//! bridge WebSockets without decrypting it, serves the HTTP API and website on the API domain with its own
//! certificate, and issues and renews tunnel certificates. See `docs/protocol.md` and `docs/server.md`.

pub mod acme;
pub mod admin;
pub mod analytics;
pub mod bridge;
pub mod clock;
pub mod cluster;
pub mod config;
pub mod crypto;
pub mod csr;
pub mod dns;
mod dnspod;
pub mod http;
pub mod issuer;
pub mod jobs;
pub mod limits;
pub mod logging;
pub mod mesh;
pub mod metrics;
pub mod migration;
pub mod net;
pub mod peer_auth;
pub mod proxy_protocol;
pub mod record;
pub mod relay;
pub mod retry;
pub mod server;
pub mod service;
pub mod sni;
pub mod store;
pub mod tls;
pub mod website;
pub mod websocket;

/// Installs the ring crypto provider as the process default for rustls.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
