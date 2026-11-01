//! Crash-safe file publication: write to a fresh sibling, sync it, rename it
//! over the destination, sync the directory.
//!
//! The temp file is created with `create_new` under an unpredictable name and
//! mode 0600, so a symlink or file planted at a guessable path is never
//! followed or truncated. One helper for the revocation log (`amesh`) and the
//! `Seen` record (this crate), so there is a single copy of the dance.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// A fresh temp file beside `dest`: `create_new` (never follows or truncates an
/// existing path) under an unpredictable name, mode 0600 on Unix.
///
/// # Errors
/// An I/O error creating the file, or `AlreadyExists` after repeated name clashes.
pub fn create_tmp(dir: &Path, dest: &Path) -> io::Result<(PathBuf, File)> {
    let name = dest
        .file_name()
        .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
    for _ in 0..8 {
        let tmp = dir.join(format!(".{name}.{:032x}.tmp", rand::random::<u128>()));
        let mut o = OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        match o.open(&tmp) {
            Ok(f) => return Ok((tmp, f)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!("could not create a temp file in {}", dir.display()),
    ))
}

/// Replace `dest` with `bytes` atomically and durably: temp file, `sync_all`,
/// rename, then `sync_all` on the directory (Unix). On failure the temp file
/// is removed and `dest` is untouched.
///
/// # Errors
/// Any I/O error along the way.
pub fn atomic_write(dest: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = match dest.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let (tmp, mut f) = create_tmp(dir, dest)?;
    let written = f
        .write_all(bytes)
        .and_then(|()| f.sync_all())
        .and_then(|()| fs::rename(&tmp, dest));
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn replaces_the_destination_and_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("f.json");
        atomic_write(&dest, b"one").unwrap();
        atomic_write(&dest, b"two").unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"two");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn a_symlink_at_a_guessed_temp_name_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        fs::write(&victim, "precious").unwrap();
        let dest = dir.path().join("f.json");
        for guess in ["f.tmp", "f.json.tmp", "f.json.tmp.1"] {
            let _ = std::os::unix::fs::symlink(&victim, dir.path().join(guess));
        }
        atomic_write(&dest, b"data").unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "precious");
    }

    #[test]
    fn a_failed_rename_removes_the_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("is-a-dir");
        fs::create_dir(&dest).unwrap();
        fs::write(dest.join("x"), "x").unwrap();
        assert!(atomic_write(&dest, b"data").is_err());
        let leftovers: Vec<_> = fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(leftovers.len(), 1, "only the directory remains");
    }
}
