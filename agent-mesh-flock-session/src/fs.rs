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
    fn read(&self, path: &Path) -> io::Result<Option<Vec<u8>>> {
        match std::fs::read(path) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// Replace `dir/name` with `bytes` so that, once this returns, the new
/// contents survive power loss, and until then the old ones do: write a
/// temporary file, fsync it, rename it over the target, fsync the directory.
///
/// # Errors
/// I/O; the old file is intact on any error.
pub fn save_atomic(fs: &dyn Fs, dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    let tmp = dir.join(format!("{name}.tmp"));
    fs.write(&tmp, bytes)?;
    fs.sync_file(&tmp)?;
    fs.rename(&tmp, &dir.join(name))?;
    fs.sync_dir(dir)
}
