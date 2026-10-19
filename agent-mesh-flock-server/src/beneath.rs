//! Open a file strictly beneath a root directory, with no pathname
//! re-resolution between a check and the open.
//!
//! A pathname that was checked (canonicalized, prefix-compared) is resolved
//! again by `open`, and a directory on it can become a link in between. Here
//! the root is opened once, and everything after is relative to that
//! descriptor, so nothing outside it is reachable through it:
//!
//! - Linux: one `openat2` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS` (which
//!   includes no magic links): the kernel refuses `..` that climbs out, an
//!   absolute path and any symlink anywhere on the path, atomically. Not
//!   `RESOLVE_NO_XDEV`: a mount inside the root is the owner's own doing and
//!   is part of the tree they mapped.
//! - Elsewhere (macOS, or a Linux without `openat2`): a walk, one component at
//!   a time, each `openat` relative to the descriptor of the one before, with
//!   `O_NOFOLLOW` (and `O_DIRECTORY` on every directory), so a link at any
//!   component is refused and the descriptor held is the directory that was
//!   opened, whatever the name is swapped for afterwards.
//!
//! Both refuse **every** symlink, including one that stays inside the root.
//! Hard links and mounts are not links in this sense: a file with a name in the
//! tree is in the tree.

use rustix::fs::{Mode, OFlags};
use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::path::{Component, Path};

/// A root directory held open.
#[derive(Debug)]
pub struct Beneath {
    dir: OwnedFd,
}

fn invalid(why: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, why)
}

impl Beneath {
    /// Open `root` (it is the anchor: it may itself be reached through
    /// links, the owner chose it).
    ///
    /// # Errors
    /// The root is missing or not a directory.
    pub fn root(root: &Path) -> io::Result<Self> {
        let dir = rustix::fs::open(
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        Ok(Self { dir })
    }

    /// Open `rel` for reading, without blocking (a fifo does not wait for a
    /// writer): the caller checks it is a regular file.
    ///
    /// # Errors
    /// An absolute path, an empty one or one naming `..` (`InvalidInput`); a
    /// symlink anywhere on it, or anything that would leave the root; a file
    /// that is not there.
    pub fn open(&self, rel: &Path) -> io::Result<File> {
        let parts = parts(rel)?;
        #[cfg(target_os = "linux")]
        match self.open_linux(&parts) {
            Err(e) if e.raw_os_error() == Some(rustix::io::Errno::NOSYS.raw_os_error()) => {}
            other => return other,
        }
        self.walk(&parts, &mut |_| {})
    }

    #[cfg(target_os = "linux")]
    fn open_linux(&self, parts: &[&std::ffi::OsStr]) -> io::Result<File> {
        use rustix::fs::ResolveFlags;
        let path: std::path::PathBuf = parts.iter().collect();
        let fd = rustix::fs::openat2(
            &self.dir,
            &path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
        )?;
        Ok(File::from(fd))
    }

    /// The component walk, always available; `between` runs after each
    /// directory is opened and before the next component is.
    fn walk(&self, parts: &[&std::ffi::OsStr], between: &mut dyn FnMut(usize)) -> io::Result<File> {
        let (last, dirs) = parts.split_last().ok_or_else(|| invalid("empty path"))?;
        let mut held: Option<OwnedFd> = None;
        for (i, name) in dirs.iter().enumerate() {
            let at = held.as_ref().unwrap_or(&self.dir);
            let next = rustix::fs::openat(
                at,
                *name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            held = Some(next);
            between(i);
        }
        let at = held.as_ref().unwrap_or(&self.dir);
        let fd = rustix::fs::openat(
            at,
            *last,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        Ok(File::from(fd))
    }

    /// Test-only: the component walk with a hook after each directory.
    #[doc(hidden)]
    pub fn open_by_walk(&self, rel: &Path, between: &mut dyn FnMut(usize)) -> io::Result<File> {
        self.walk(&parts(rel)?, between)
    }
}

/// The normal components of `rel`; absolute, empty and `..` are refused
/// before the file system is touched (`.` is skipped).
fn parts(rel: &Path) -> io::Result<Vec<&std::ffi::OsStr>> {
    let mut out = vec![];
    for c in rel.components() {
        match c {
            Component::Normal(p) => out.push(p),
            Component::CurDir => {}
            _ => return Err(invalid("path leaves its root")),
        }
    }
    if out.is_empty() {
        return Err(invalid("empty path"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::Beneath;
    use std::io::Read as _;
    use std::os::unix::fs::symlink;
    use std::path::Path;

    /// `root/dir/file` ("inside") and `outside/file` ("outside").
    fn tree() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("root");
        let outside = t.path().join("outside");
        std::fs::create_dir_all(root.join("dir")).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(root.join("dir/file"), b"inside").unwrap();
        std::fs::write(outside.join("file"), b"outside").unwrap();
        (t, root, outside)
    }

    fn read(mut f: std::fs::File) -> String {
        let mut s = String::new();
        f.read_to_string(&mut s).unwrap();
        s
    }

    #[test]
    fn a_file_beneath_the_root_opens_by_either_route() {
        let (_t, root, _o) = tree();
        let b = Beneath::root(&root).unwrap();
        assert_eq!(read(b.open(Path::new("dir/file")).unwrap()), "inside");
        assert_eq!(read(b.open(Path::new("./dir/./file")).unwrap()), "inside");
        let w = b.open_by_walk(Path::new("dir/file"), &mut |_| {}).unwrap();
        assert_eq!(read(w), "inside");
        // two directories deep: each is opened relative to the one before
        std::fs::create_dir_all(root.join("a/b")).unwrap();
        std::fs::write(root.join("a/b/deep"), b"deep").unwrap();
        assert_eq!(read(b.open(Path::new("a/b/deep")).unwrap()), "deep");
        let w = b.open_by_walk(Path::new("a/b/deep"), &mut |_| {}).unwrap();
        assert_eq!(read(w), "deep");
    }

    #[test]
    fn an_intermediate_link_to_outside_is_refused_by_either_route() {
        let (_t, root, outside) = tree();
        symlink(&outside, root.join("out")).unwrap();
        let b = Beneath::root(&root).unwrap();
        assert!(b.open(Path::new("out/file")).is_err());
        assert!(b.open_by_walk(Path::new("out/file"), &mut |_| {}).is_err());
    }

    #[test]
    fn every_link_is_refused_even_one_that_stays_inside() {
        let (_t, root, _o) = tree();
        symlink("dir/file", root.join("alias")).unwrap();
        symlink("dir", root.join("dalias")).unwrap();
        let b = Beneath::root(&root).unwrap();
        for p in ["alias", "dalias/file"] {
            assert!(b.open(Path::new(p)).is_err(), "{p}");
            assert!(b.open_by_walk(Path::new(p), &mut |_| {}).is_err(), "{p}");
        }
    }

    #[test]
    fn dotdot_absolute_and_empty_never_reach_the_file_system() {
        let (_t, root, outside) = tree();
        let b = Beneath::root(&root).unwrap();
        let abs = outside.join("file");
        for p in [
            Path::new("../outside/file"),
            Path::new("dir/../dir/file"),
            abs.as_path(),
            Path::new(""),
            Path::new("."),
        ] {
            let e = b.open(p).unwrap_err();
            assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{p:?}");
        }
    }

    /// The directory is swapped for a link to outside after it was opened and
    /// before the file in it is: the walk holds the descriptor it opened, so
    /// the file comes from the original directory, never from outside.
    #[test]
    fn a_directory_swapped_for_a_link_mid_walk_cannot_redirect_the_open() {
        let (_t, root, outside) = tree();
        let b = Beneath::root(&root).unwrap();
        let f = b
            .open_by_walk(Path::new("dir/file"), &mut |_| {
                std::fs::rename(root.join("dir"), root.join("dir.old")).unwrap();
                symlink(&outside, root.join("dir")).unwrap();
            })
            .unwrap();
        assert_eq!(read(f), "inside");
    }

    /// The same swap before the call: the link is found and refused.
    #[test]
    fn a_directory_that_is_already_a_link_is_refused() {
        let (_t, root, outside) = tree();
        std::fs::rename(root.join("dir"), root.join("dir.old")).unwrap();
        symlink(&outside, root.join("dir")).unwrap();
        let b = Beneath::root(&root).unwrap();
        assert!(b.open(Path::new("dir/file")).is_err());
        assert!(b.open_by_walk(Path::new("dir/file"), &mut |_| {}).is_err());
    }

    #[test]
    fn a_missing_file_is_not_found_and_a_file_root_is_refused() {
        let (_t, root, _o) = tree();
        let b = Beneath::root(&root).unwrap();
        let e = b.open(Path::new("dir/none")).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
        assert!(Beneath::root(&root.join("dir/file")).is_err());
        assert_eq!(
            Beneath::root(&root.join("nope")).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
    }
}
