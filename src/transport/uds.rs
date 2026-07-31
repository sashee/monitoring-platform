//! Unix socket lifecycle (SPEC §8.1).
//!
//! This module *constructs* a listener and hands it back; it never runs a server. That is what
//! keeps iroh and a possible future socket-activation constructor additive (SPEC §9.2).

use anyhow::{Context, Result, bail};
use std::fs;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;
use tokio::net::UnixListener;

/// Binds the socket, reclaiming a stale one but never touching anything else.
pub fn bind(path: &Path) -> Result<UnixListener> {
    reclaim_if_stale(path)?;

    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty() && !p.exists()) {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating socket directory {}", parent.display()))?;
    }

    let listener = UnixListener::bind(path)
        .with_context(|| format!("binding unix socket {}", path.display()))?;

    // Defence in depth only. Between bind() and here the socket carries 0777 & ~umask, so real
    // access control comes from the containing directory's mode (SPEC §8.1, §9.2).
    fs::set_permissions(path, fs::Permissions::from_mode(0o660))
        .with_context(|| format!("setting permissions on {}", path.display()))?;

    Ok(listener)
}

/// Unlinks the path only if it is provably a dead socket.
///
/// A live listener means another instance is running, and a non-socket file means the path is not
/// ours — both are startup failures rather than something to clean up.
fn reclaim_if_stale(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("inspecting {}", path.display())),
    };

    if !metadata.file_type().is_socket() {
        bail!(
            "{} exists and is not a socket; refusing to remove it",
            path.display()
        );
    }

    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_) => bail!(
            "{} is already served by a running instance",
            path.display()
        ),
        Err(_) => {
            tracing::info!(path = %path.display(), "removing stale socket");
            fs::remove_file(path)
                .with_context(|| format!("removing stale socket {}", path.display()))?;
            Ok(())
        }
    }
}

/// Removes the socket on shutdown. Best-effort: a failure here must not mask the real exit reason.
pub fn cleanup(path: &Path) {
    match fs::remove_file(path) {
        Ok(()) => tracing::debug!(path = %path.display(), "removed socket"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!(path = %path.display(), error = %e, "could not remove socket"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn binds_and_sets_group_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.sock");

        let listener = bind(&path).unwrap();
        assert!(fs::symlink_metadata(&path).unwrap().file_type().is_socket());
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o660, "socket should be group-accessible only");

        drop(listener);
        cleanup(&path);
        assert!(!path.exists());
    }

    /// SPEC §8.1: a dead socket must be reclaimed, so a crash does not wedge the next start.
    #[tokio::test]
    async fn reclaims_a_stale_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.sock");

        let first = bind(&path).unwrap();
        drop(first); // leaves the file behind with no listener

        assert!(path.exists(), "precondition: the stale file is still there");
        let second = bind(&path);
        assert!(second.is_ok(), "should have reclaimed: {:?}", second.err());
    }

    /// A live listener means another instance owns the path.
    #[tokio::test]
    async fn refuses_to_steal_a_live_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.sock");

        let _held = bind(&path).unwrap();
        let err = bind(&path).unwrap_err().to_string();
        assert!(err.contains("already served"), "unexpected error: {err}");
    }

    /// SPEC §8.1: never unlink a path that was not verified to be a dead socket.
    #[tokio::test]
    async fn refuses_to_remove_a_regular_file_and_leaves_it_intact() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-a-socket");
        fs::write(&path, b"important").unwrap();

        let err = bind(&path).unwrap_err().to_string();
        assert!(err.contains("is not a socket"), "unexpected error: {err}");
        assert_eq!(fs::read(&path).unwrap(), b"important", "the file must be untouched");
    }
}
