---
"opentunnel": patch
---

The CLI and Rust client no longer drop their bridge, and every connection on it, when the server pauses reading it. The bridge's read loop used to wait for room in the send queue before it could queue a ping, a pong or a reset; while the server held back a slow visitor's data, uploads filled that queue, the client stopped reading the bridge, and the server closed it after 30 s. Control messages now have their own queue, sent first, and the read loop waits at most 5 s (was 30 s) for a local connection that stops reading before resetting it, including when the server ends the connection.
