//! Unix socket lifecycle (SPEC.md §8.1).
//!
//! This module *constructs* a listener and hands it back; it never runs a server. That is what
//! keeps iroh and socket activation additive (SPEC.md §9.2).
//!
//! Reading `LISTEN_FDS` is deliberately **not** here: `sd_notify::listen_fds_and_unset_env` is
//! `unsafe` because it mutates the environment, and must run before any thread exists. That is a
//! `main()` concern. [`adopt`] takes the descriptor it produced and nothing more.

use anyhow::{Context, Result, bail};
use std::fs;
use std::os::fd::{FromRawFd, RawFd};
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
    // access control comes from the containing directory's mode (SPEC.md §8.1, §9.2).
    fs::set_permissions(path, fs::Permissions::from_mode(0o660))
        .with_context(|| format!("setting permissions on {}", path.display()))?;

    Ok(listener)
}

/// Wraps a listening socket the service manager already created and bound.
///
/// This is what removes the startup ordering race for the collector: the socket unit creates the
/// endpoint before any client can connect, so a client blocks rather than failing, and the
/// service inherits it already listening. Nothing here creates or unlinks a path — systemd owns
/// the file's whole lifetime, which is also why the caller must not run [`cleanup`] on it.
///
/// # Safety-adjacent
///
/// Taking ownership of `fd` is only sound if the caller does not also own it. In practice `fd`
/// comes from `sd_notify::listen_fds`, which yields each descriptor once.
pub fn adopt(fd: RawFd) -> Result<UnixListener> {
    // SAFETY: systemd guarantees the descriptors from SD_LISTEN_FDS_START are open and owned by
    // this process, and `sd_notify::listen_fds` yields each exactly once, so this is the only
    // owner. A non-socket fd here fails below rather than being used.
    let std_listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };

    // systemd hands the descriptor over in blocking mode; tokio's reactor requires otherwise, and
    // a blocking accept() would stall the whole epoll loop the moment the backlog empties.
    std_listener
        .set_nonblocking(true)
        .with_context(|| format!("setting O_NONBLOCK on inherited fd {fd}"))?;

    UnixListener::from_std(std_listener)
        .with_context(|| format!("adopting inherited socket fd {fd}"))
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
///
/// Only for a path this process created with [`bind`]. A socket-activated listener from [`adopt`]
/// belongs to systemd, which recreates it on the next start.
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
    use std::os::fd::IntoRawFd;

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

    /// SPEC.md §8.1: a dead socket must be reclaimed, so a crash does not wedge the next start.
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

    /// SPEC.md §8.1: never unlink a path that was not verified to be a dead socket.
    #[tokio::test]
    async fn refuses_to_remove_a_regular_file_and_leaves_it_intact() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-a-socket");
        fs::write(&path, b"important").unwrap();

        let err = bind(&path).unwrap_err().to_string();
        assert!(err.contains("is not a socket"), "unexpected error: {err}");
        assert_eq!(fs::read(&path).unwrap(), b"important", "the file must be untouched");
    }

    /// The socket-activation path: a blocking listener created elsewhere must come back usable,
    /// which means non-blocking and accepting. Stands in for what systemd hands over.
    #[tokio::test]
    async fn adopts_a_listener_created_by_someone_else() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.sock");

        let raw = std::os::unix::net::UnixListener::bind(&path).unwrap().into_raw_fd();
        let listener = adopt(raw).unwrap();

        let client = tokio::net::UnixStream::connect(&path).await.unwrap();
        let (accepted, _) = listener.accept().await.unwrap();
        drop((client, accepted));
    }

    /// systemd hands the descriptor over blocking, and a blocking accept() would stall the epoll
    /// loop rather than yield to it. Asserted on the descriptor itself: the alternative — timing
    /// out an `accept()` — proves the same thing far more slowly and flakily.
    #[tokio::test]
    async fn adoption_clears_blocking_mode() {
        use std::os::fd::AsRawFd;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.sock");

        let raw = std::os::unix::net::UnixListener::bind(&path).unwrap().into_raw_fd();
        // SAFETY: reading the descriptor's flags; `raw` is open and owned by this process.
        assert_eq!(
            unsafe { libc::fcntl(raw, libc::F_GETFL) } & libc::O_NONBLOCK,
            0,
            "precondition: a plainly bound listener is blocking, as systemd's is"
        );

        let listener = adopt(raw).unwrap();
        // SAFETY: same, through the adopted listener, which still owns the descriptor.
        assert_ne!(
            unsafe { libc::fcntl(listener.as_raw_fd(), libc::F_GETFL) } & libc::O_NONBLOCK,
            0,
            "adopt must clear blocking mode"
        );
    }
}
