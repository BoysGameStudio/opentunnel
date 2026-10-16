---
"opentunnel": patch
---

The CLI and Rust client work behind TLS-inspecting corporate proxies. The API and bridge connections to `opentunnel.xyz` now trust the OS trust store (honoring `SSL_CERT_FILE` and `SSL_CERT_DIR`) in addition to the bundled Mozilla roots, instead of failing with `invalid peer certificate: UnknownIssuer`. A specific CA can be added with `--ca-cert <path>` or `OPENTUNNEL_CA_CERT` (a PEM file with one or more certificates); the background service is registered with it. Rust: `ClientOptions::ca_cert`, `opentunnel::tls::read_ca_certificates`. The TypeScript SDK README documents the runtime equivalents (`NODE_EXTRA_CA_CERTS`, `--use-system-ca`, `DENO_CERT`). Tunneled visitor traffic is unchanged.
