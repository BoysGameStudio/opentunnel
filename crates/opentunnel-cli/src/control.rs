//! Messages on the daemon's Unix control socket: one JSON request line and
//! one JSON response line per connection.

use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use opentunnel::Status;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Command {
    Status,
    Reload,
    Stop,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    pub command: Command,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<DaemonStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    NoTunnel,
    Provisioning,
    Running,
    Stopped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub pid: u32,
    pub version: String,
    pub profile: String,
    pub phase: Phase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel: Option<TunnelStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub started_at: u64,
}

/// Mirror of [`opentunnel::Status`] that can also be deserialized.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelStatus {
    pub state: String,
    pub hostname: String,
    pub routes: opentunnel::Routes,
    pub session: Option<String>,
    pub connections: usize,
    pub last_error: Option<String>,
    pub connected_at: Option<u64>,
}

impl From<Status> for TunnelStatus {
    fn from(status: Status) -> Self {
        let state = serde_json::to_value(&status.state)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_default();
        Self {
            state,
            hostname: status.hostname,
            routes: status.routes,
            session: status.session,
            connections: status.connections,
            last_error: status.last_error,
            connected_at: status.connected_at,
        }
    }
}

pub struct Paths {
    pub socket: PathBuf,
    pub lock: PathBuf,
    pub log: PathBuf,
    pub last_error: PathBuf,
}

pub fn paths(profile: &str) -> Paths {
    let runtime = opentunnel::paths::runtime_dir();
    let state = opentunnel::paths::state_dir().join(profile);
    Paths {
        socket: runtime.join(format!("{profile}.sock")),
        lock: runtime.join(format!("{profile}.lock")),
        log: state.join("daemon.log"),
        last_error: state.join("last-error.json"),
    }
}

/// Creates the directory holding control sockets and locks, and checks that
/// it belongs to the current user. Without `$XDG_RUNTIME_DIR` it lives in the
/// shared temporary directory, where another user could create it first to
/// intercept the control socket, so a directory that is not a real 0700
/// directory owned by the current user is refused.
pub fn runtime_dir() -> Result<PathBuf> {
    let dir = opentunnel::paths::runtime_dir();
    if let Some(parent) = dir.parent() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    match fs::DirBuilder::new().mode(0o700).create(&dir) {
        Err(error) if error.kind() != io::ErrorKind::AlreadyExists => {
            return Err(error).with_context(|| format!("creating {}", dir.display()));
        }
        _ => {}
    }
    // SAFETY: getuid has no preconditions and cannot fail.
    check_runtime_dir(&dir, unsafe { libc::getuid() })?;
    Ok(dir)
}

fn check_runtime_dir(dir: &Path, uid: u32) -> Result<()> {
    let metadata =
        fs::symlink_metadata(dir).with_context(|| format!("inspecting {}", dir.display()))?;
    let insecure = if !metadata.file_type().is_dir() {
        "is not a directory"
    } else if metadata.uid() != uid {
        "is owned by another user"
    } else if metadata.permissions().mode() & 0o077 != 0 {
        "is accessible to other users"
    } else {
        return Ok(());
    };
    bail!(
        "refusing to use {} for the control socket: it {insecure}; remove it or set XDG_RUNTIME_DIR",
        dir.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_runtime_dirs_other_users_control() {
        let root = std::env::temp_dir().join(format!("opentunnel-runtime-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        // SAFETY: getuid has no preconditions and cannot fail.
        let uid = unsafe { libc::getuid() };

        let private = root.join("private");
        fs::DirBuilder::new().mode(0o700).create(&private).unwrap();
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(check_runtime_dir(&private, uid).is_ok());
        assert!(check_runtime_dir(&private, uid.wrapping_add(1)).is_err());

        let open = root.join("open");
        fs::create_dir(&open).unwrap();
        fs::set_permissions(&open, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(check_runtime_dir(&open, uid).is_err());

        let link = root.join("link");
        std::os::unix::fs::symlink(&private, &link).unwrap();
        assert!(check_runtime_dir(&link, uid).is_err());

        let _ = fs::remove_dir_all(root);
    }
}
