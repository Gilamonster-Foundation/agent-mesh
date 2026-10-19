//! Reading one cited file from a home root. The only code that turns a
//! requested path into a file on disk, so it is where the root is enforced.
//!
//! The file is opened by [`Beneath`](crate::Beneath): the root is opened once
//! and the path is resolved relative to that descriptor, with `..`, absolute
//! paths and every symlink refused, so there is no checked pathname for a
//! swapped directory to make stale (Linux `openat2`; a descriptor-relative
//! walk elsewhere). A link that stays inside the root is refused too. The
//! descriptor is then checked: a regular file, within one message. What is
//! read is the opened inode, never half of two files.
//!
//! The limit, stated: the root is opened by its path, so a swap of the root
//! directory (or an ancestor) before it is opened is the owner's own mapping
//! changing. Mounts inside the root are part of the tree (no `NO_XDEV`), and
//! so are hard links.

use crate::wire::MAX_FILE;
use crate::Beneath;
use std::io::Read as _;
use std::path::Path;

/// Why a path under a root cannot be read, when it crosses a link or leaves
/// the root.
const LINK: &str = "outside the root or through a link";

/// The bytes at `rel` under `root`, or why not.
pub(crate) fn read_under(root: &Path, rel: &str) -> Result<Vec<u8>, String> {
    if rel.is_empty() || rel.contains('\0') {
        return Err("not a usable path".into());
    }
    let beneath = Beneath::root(root).map_err(|_| "the root is not available".to_owned())?;
    let mut file = beneath.open(Path::new(rel)).map_err(|e| {
        match (e.kind(), e.raw_os_error()) {
            (std::io::ErrorKind::NotFound, _) => "missing",
            (std::io::ErrorKind::InvalidInput, _) => "outside the root",
            (_, Some(code)) if is_link_or_escape(code) => LINK,
            _ => "not readable",
        }
        .to_owned()
    })?;
    let meta = file.metadata().map_err(|_| "not readable".to_owned())?;
    if !meta.is_file() {
        return Err("not a regular file".into());
    }
    if meta.len() > MAX_FILE as u64 {
        return Err("too large".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_FILE as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "not readable".to_owned())?;
    if bytes.len() > MAX_FILE {
        return Err("too large".into());
    }
    Ok(bytes)
}

/// ELOOP (a symlink refused), EXDEV (`RESOLVE_BENEATH` escape) and ENOTDIR
/// (`O_DIRECTORY` on a link, or a file used as a directory).
fn is_link_or_escape(code: i32) -> bool {
    use rustix::io::Errno;
    [Errno::LOOP, Errno::XDEV, Errno::NOTDIR]
        .iter()
        .any(|e| e.raw_os_error() == code)
}
