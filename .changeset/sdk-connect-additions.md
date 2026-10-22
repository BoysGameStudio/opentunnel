---
"@opentunnel/client": minor
"@opentunnel/protocol": minor
---

SDK additions for CLIs that wrap dev servers (#56): `connect({ signal })` now cancels an attach in progress (and the certificate work it started) and rejects with the signal's reason; `onRouteConflict: "fail"` makes `connect` reject with `code: "route_conflict"` instead of retrying, and a `route-conflict` event reports each conflict (see it before `connect` resolves with the new `onEvent` option); `connection.urls` maps each route to its public URL; `isValidRouteName`, `ROUTE_LABEL_PATTERN`, `ROOT_ROUTE`, and `publicUrl` are exported; `ensure({ onProgress })` reports progress, starting with the new `checking-certificate` stage. Fatal attach errors carry their code on `OpenTunnelClientError.code`. The protocol package exports `Names.LABEL_PATTERN` and `Names.publicHostname`.
