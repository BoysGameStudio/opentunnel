---
"@opentunnel/client": patch
"opentunnel": patch
---

The bridge WebSocket now goes through the same HTTP proxy as the API calls (#59): `HTTPS_PROXY` for `wss://`, `HTTP_PROXY` for `ws://`, then `ALL_PROXY`, except for hosts in `NO_PROXY`. Behind an egress proxy, tunnel creation used to succeed while the bridge dialed the server directly and never attached. On Bun the SDK resolves the proxy for the bridge itself, since Bun's `WebSocket` ignores these variables; on Node and Deno the runtime applies the same settings to `fetch` and `WebSocket`. A new `proxy` option on `create` and `OpenTunnelClient.layer` sets the proxy for the API and the bridge regardless of the environment (on Node it needs the optional `undici` peer dependency). The CLI and Rust client tunnel the bridge through `http://` or `https://` proxies with `CONNECT` (basic auth from the URL), chosen by the same rules reqwest uses for the API. A SOCKS proxy stops the tunnel with an error naming it instead of being bypassed.
