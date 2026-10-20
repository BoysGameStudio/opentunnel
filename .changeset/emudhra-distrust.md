---
"opentunnel": patch
---

The CLI and Rust client no longer trust the eight eMudhra intermediate CA certificates whose private keys were disclosed as compromised on 2026-10-20. The bundled roots move to `webpki-root-certs` 1.0.10, and `rustls-webpki` 0.103.16 rejects chains through those intermediates even when the operating system's trust store still carries their roots.
