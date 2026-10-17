//! Keeping other Unix users off a socket. The guard is the directory: a
//! socket lives in a directory only its owner can enter. The peer's uid is
//! checked on every accept as well. Neither keeps out another process of the
//! same user; that boundary is agent-bridle's.

use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

fn me() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// Create `dir` (mode 0700) if absent; refuse one that is not ours or that
/// group or others can enter.
///
/// # Errors
/// I/O, or a directory that is not private.
pub fn private_dir(dir: &Path) -> io::Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let meta = std::fs::symlink_metadata(dir)?;
    if !meta.is_dir() || meta.uid() != me() || meta.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} must be a directory only its owner can enter",
                dir.display()
            ),
        ));
    }
    Ok(())
}

/// Bind a Unix socket (mode 0600) in a private directory, replacing a stale
/// socket file.
///
/// # Errors
/// I/O, or a directory that is not private.
pub fn bind_private(path: &Path) -> io::Result<UnixListener> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "socket path has no parent"))?;
    private_dir(dir)?;
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Whether a peer with `peer` uid may use a socket owned by `own`.
#[must_use]
pub fn uid_allowed(peer: u32, own: u32) -> bool {
    peer == own
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn peer_uid(s: &UnixStream) -> io::Result<u32> {
    Ok(rustix::net::sockopt::socket_peercred(s)?.uid.as_raw())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn peer_uid(s: &UnixStream) -> io::Result<u32> {
    use std::os::fd::AsRawFd;
    let (mut uid, mut gid) = (0, 0);
    // SAFETY: the fd is a live socket and both out-pointers are valid.
    if unsafe { libc::getpeereid(s.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(uid)
}

/// Refuse a connection from another Unix user.
///
/// # Errors
/// The peer is another user, or its credentials cannot be read.
pub fn peer_ok(s: &UnixStream) -> io::Result<()> {
    if uid_allowed(peer_uid(s)?, me()) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "connection from another user",
        ))
    }
}
