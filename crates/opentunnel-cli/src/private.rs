//! Owner-only files and directories. A route's name is the only secret in its
//! URL, so the profile config and the service log, which both contain route
//! names, must not be readable by other local users.

use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use crate::{config, control};

/// Creates `dir` (and missing parents) as 0700, tightening it if it exists.
pub fn create_dir(dir: &Path) -> io::Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    restrict(dir, 0o700)
}

/// Writes `content` to a file only the current user can read.
pub fn write(path: &Path, content: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.set_permissions(Permissions::from_mode(0o600))?;
    file.write_all(content)
}

/// Opens a log file for appending, creating it readable only by the current user.
pub fn open_append(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    file.set_permissions(Permissions::from_mode(0o600))?;
    Ok(file)
}

/// Removes group and other access from `path` if it exists.
fn restrict(path: &Path, mode: u32) -> io::Result<()> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.permissions().mode() & 0o077 != 0 => {
            fs::set_permissions(path, Permissions::from_mode(mode))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Tightens files that earlier versions created world-readable: the profile
/// config, the service log, and the directories holding them. Best effort.
pub fn tighten(profile: &str) {
    let config = config::path(profile);
    let paths = control::paths(profile);
    let directories = [
        config.parent(),
        paths.log.parent().and_then(Path::parent),
        paths.log.parent(),
    ];
    for directory in directories.into_iter().flatten() {
        let _ = restrict(directory, 0o700);
    }
    for file in [&config, &paths.log, &paths.last_error] {
        let _ = restrict(file, 0o600);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn creates_and_tightens_owner_only_paths() {
        let root = std::env::temp_dir().join(format!(
            "opentunnel-private-{}-{}",
            std::process::id(),
            rand_suffix()
        ));
        let dir = root.join("nested");
        create_dir(&dir).unwrap();
        assert_eq!(mode(&dir), 0o700);

        let file = dir.join("config.toml");
        fs::write(&file, "old").unwrap();
        fs::set_permissions(&file, Permissions::from_mode(0o644)).unwrap();
        write(&file, b"new").unwrap();
        assert_eq!(mode(&file), 0o600);
        assert_eq!(fs::read_to_string(&file).unwrap(), "new");

        let log = dir.join("daemon.log");
        fs::write(&log, "").unwrap();
        fs::set_permissions(&log, Permissions::from_mode(0o644)).unwrap();
        restrict(&log, 0o600).unwrap();
        assert_eq!(mode(&log), 0o600);
        fs::set_permissions(&log, Permissions::from_mode(0o644)).unwrap();
        drop(open_append(&log).unwrap());
        assert_eq!(mode(&log), 0o600);

        fs::set_permissions(&dir, Permissions::from_mode(0o755)).unwrap();
        create_dir(&dir).unwrap();
        assert_eq!(mode(&dir), 0o700);
        let _ = fs::remove_dir_all(root);
    }

    fn rand_suffix() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }
}
