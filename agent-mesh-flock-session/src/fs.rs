//! The few filesystem steps an atomic save needs, behind a trait so a test
//! can model power loss between any two of them.

use std::io;
use std::path::Path;

/// File operations, in the order a durable replace needs them.
pub trait Fs {
    /// Create or truncate `path` with `bytes` (not yet durable).
    ///
    /// # Errors
    /// I/O.
    fn write(&self, path: &Path, bytes: &[u8]) -> io::Result<()>;
    /// Make the file's contents durable.
    ///
    /// # Errors
    /// I/O.
    fn sync_file(&self, path: &Path) -> io::Result<()>;
    /// Replace `to` with `from` (not yet durable).
    ///
    /// # Errors
    /// I/O.
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;
    /// Make the directory's entries durable.
    ///
    /// # Errors
    /// I/O.
    fn sync_dir(&self, dir: &Path) -> io::Result<()>;
    /// Take the exclusive writer lock on `dir`, held until the returned
    /// guard is dropped; a second holder is refused.
    ///
    /// # Errors
    /// I/O, or `WouldBlock` when another holder has it.
    fn lock_dir(&self, dir: &Path) -> io::Result<Box<dyn std::any::Any + Send>>;
    /// Read `path`, `None` if absent.
    ///
    /// # Errors
    /// I/O other than absence.
    fn read(&self, path: &Path) -> io::Result<Option<Vec<u8>>>;
}

/// The real filesystem.
pub struct RealFs;

impl Fs for RealFs {
    fn write(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        std::fs::write(path, bytes)
    }
    fn sync_file(&self, path: &Path) -> io::Result<()> {
        std::fs::File::open(path)?.sync_all()
    }
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        std::fs::rename(from, to)
    }
    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        std::fs::File::open(dir)?.sync_all()
    }
    fn lock_dir(&self, dir: &Path) -> io::Result<Box<dyn std::any::Any + Send>> {
        use rustix::fs::{flock, FlockOperation};
        let f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join("reader.lock"))?;
        flock(&f, FlockOperation::NonBlockingLockExclusive)
            .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))?;
        Ok(Box::new(f))
    }
    fn read(&self, path: &Path) -> io::Result<Option<Vec<u8>>> {
        match std::fs::read(path) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// Replace `dir/name` with `bytes` so that, once this returns, the new
/// contents survive power loss: write a temporary file, fsync it, rename it
/// over the target, fsync the directory. There must be one caller at a time
/// per directory (see [`Fs::lock_dir`]): the temporary name is shared.
///
/// # Errors
/// I/O. Before the rename the old file is intact; after it the new file may
/// already be visible even if the directory fsync then fails, in which case
/// the save is reported as failed and its head is not witnessed.
pub fn save_atomic(fs: &dyn Fs, dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    let tmp = dir.join(format!("{name}.tmp"));
    fs.write(&tmp, bytes)?;
    fs.sync_file(&tmp)?;
    fs.rename(&tmp, &dir.join(name))?;
    fs.sync_dir(dir)
}
