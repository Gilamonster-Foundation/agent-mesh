//! Reading one cited file from a home root. The only code that turns a
//! requested path into a file on disk, so it is where the root is enforced.
//!
//! The path is refused lexically if it is absolute or names `..`; then the
//! root and the joined path are canonicalized and the result must still be
//! under the canonical root (a symlink out of the root, in any component, is
//! caught here); then the file is opened without following a final link and
//! without blocking, and checked: a regular file, within the size limit.
//! After the open the path is resolved again and must name the same file.
//!
//! The limit, stated: between the canonicalization and the open a directory
//! component can be swapped for a link; the open follows it, and the
//! re-check catches that unless the swap is undone before the re-check. What
//! is read is always the opened inode, so a file replaced after the open is
//! not read half old and half new. Anyone who can write inside the root
//! outpaces this; the roots are the owner's own directories.

use crate::wire::MAX_FILE;
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Component, Path, PathBuf};

fn unavailable(why: &str) -> String {
    why.to_owned()
}

/// The bytes at `rel` under `root`, or why not.
pub(crate) fn read_under(root: &Path, rel: &str) -> Result<Vec<u8>, String> {
    read_under_with(root, rel, &mut || {}, &mut || {})
}

/// [`read_under`], calling `after_resolve` between resolving the path and
/// opening it, and `after_open` between opening it and the re-check: the two
/// windows the module comment names, so that a test can land a swap in each.
fn read_under_with(
    root: &Path,
    rel: &str,
    after_resolve: &mut dyn FnMut(),
    after_open: &mut dyn FnMut(),
) -> Result<Vec<u8>, String> {
    if rel.is_empty() || rel.contains('\0') {
        return Err(unavailable("not a usable path"));
    }
    let mut under = PathBuf::new();
    for part in Path::new(rel).components() {
        match part {
            Component::Normal(p) => under.push(p),
            Component::CurDir => {}
            _ => return Err(unavailable("outside the root")),
        }
    }
    let root = std::fs::canonicalize(root).map_err(|_| unavailable("the root is not available"))?;
    let joined = root.join(&under);
    let path = std::fs::canonicalize(&joined).map_err(|e| {
        unavailable(if e.kind() == std::io::ErrorKind::NotFound {
            "missing"
        } else {
            "not readable"
        })
    })?;
    if !path.starts_with(&root) {
        return Err(unavailable("outside the root"));
    }
    after_resolve();
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .map_err(|_| unavailable("not readable"))?;
    let meta = file.metadata().map_err(|_| unavailable("not readable"))?;
    if !meta.is_file() {
        return Err(unavailable("not a regular file"));
    }
    if meta.len() > MAX_FILE as u64 {
        return Err(unavailable("too large"));
    }
    after_open();
    let same = std::fs::canonicalize(&joined).is_ok_and(|again| again == path)
        && std::fs::symlink_metadata(&path)
            .is_ok_and(|now| now.dev() == meta.dev() && now.ino() == meta.ino());
    if !same {
        return Err(unavailable("changed while it was being opened"));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_FILE as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| unavailable("not readable"))?;
    if bytes.len() > MAX_FILE {
        return Err(unavailable("too large"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::read_under_with;
    use std::os::unix::fs::symlink;

    /// A root with `d/f`, and a sibling directory with its own `f`.
    fn tree() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("root");
        let other = t.path().join("other");
        std::fs::create_dir_all(root.join("d")).unwrap();
        std::fs::create_dir(&other).unwrap();
        std::fs::write(root.join("d").join("f"), b"inside").unwrap();
        std::fs::write(other.join("f"), b"outside").unwrap();
        (t, root, other)
    }

    #[test]
    fn a_directory_swapped_for_a_link_after_the_path_was_resolved_is_caught() {
        let (_t, root, other) = tree();
        let got = read_under_with(
            &root,
            "d/f",
            &mut || {
                std::fs::rename(root.join("d"), root.join("d.old")).unwrap();
                symlink(&other, root.join("d")).unwrap();
            },
            &mut || {},
        );
        assert_eq!(got, Err("changed while it was being opened".to_owned()));
    }

    #[test]
    fn a_file_replaced_between_the_open_and_the_re_check_is_caught() {
        let (_t, root, _other) = tree();
        let f = root.join("d").join("f");
        let got = read_under_with(&root, "d/f", &mut || {}, &mut || {
            std::fs::write(root.join("d").join("new"), b"another file").unwrap();
            std::fs::rename(root.join("d").join("new"), &f).unwrap();
        });
        assert_eq!(got, Err("changed while it was being opened".to_owned()));
    }

    #[test]
    fn without_a_swap_the_hooks_change_nothing() {
        let (_t, root, _other) = tree();
        assert_eq!(
            read_under_with(&root, "d/f", &mut || {}, &mut || {}),
            Ok(b"inside".to_vec())
        );
    }
}
