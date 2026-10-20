---
"opentunnel": patch
---

Route URLs no longer leak to other users on the same machine. The CLI writes the profile config (`~/.config/opentunnel/<profile>.toml`) and the service log (`~/.local/state/opentunnel/<profile>/daemon.log`), which contain route names, readable only by you, and tightens files left world-readable by earlier versions whenever it runs. The systemd unit and launchd agent run the service with a 0077 umask. Without `XDG_RUNTIME_DIR`, the control-socket directory in the shared temporary directory must be a 0700 directory owned by you; the CLI refuses one created by another user. The Rust client requires rustls 0.23.46.
