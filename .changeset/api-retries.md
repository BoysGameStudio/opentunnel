---
"@opentunnel/client": patch
"@opentunnel/protocol": patch
"opentunnel": patch
---

API requests survive brief outages of the hosted API, such as Cloudflare answering 525 while a server restarts. The CLI and the SDK retry network errors, 429 and 5xx (including Cloudflare's 520-527) with capped exponential backoff: reads and certificate requests on any transient failure, creating or deleting a tunnel only when the request cannot have arrived. Errors now name the HTTP status and, for Cloudflare's codes, what they mean (`Failed to read certificate: Cloudflare 525: the SSL handshake with the server failed (HTTP 525)` instead of `Failed to read certificate`), and a failed bridge upgrade in the CLI names its status too. When the certificate check before connecting still fails, a saved certificate that has not expired is used, so `tunnel.ensure` and `connect` no longer fail on a 525. `@opentunnel/protocol` exports the shared policy as `ApiRetry`.
