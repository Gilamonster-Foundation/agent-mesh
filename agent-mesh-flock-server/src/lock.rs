//! The exclusive lock on the log file.

use crate::ServerError;
use std::fs::File;

/// Take a non-blocking exclusive lock; held until `file` is dropped.
#[cfg(unix)]
pub fn lock_exclusive(file: &File) -> Result<(), ServerError> {
    use rustix::fs::{flock, FlockOperation};
    match flock(file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(()),
        Err(e) if e == rustix::io::Errno::WOULDBLOCK => Err(ServerError::Locked),
        Err(e) => Err(ServerError::Io(e.into())),
    }
}

/// Non-unix hosts are not supported for the server yet.
#[cfg(not(unix))]
pub fn lock_exclusive(_file: &File) -> Result<(), ServerError> {
    Err(ServerError::BadFiles(
        "the flock server needs a unix host".into(),
    ))
}
