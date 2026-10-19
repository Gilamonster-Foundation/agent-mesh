//! "Changed since cited": compare a cited file's id with the bytes on this
//! host now. Events cite files as `root/path` plus the id of the bytes at the
//! time; the roster does not declare roots yet, so the operator maps them
//! (`--root name=path`, home-local). Nothing here writes: files are opened for
//! reading, never created, and a path that leaves its root is never opened.

use agent_mesh_flock::FileRef;
use agent_mesh_flock_server::Beneath;
use content_addressable::RawContentId;
use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};

/// The most bytes read from one file. A bigger file is `?`, not a prefix hash
/// that would claim something about bytes never read.
pub const MAX_BYTES: u64 = 64 * 1024 * 1024;

/// Root names mapped to directories on this host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Roots(BTreeMap<String, PathBuf>);

impl Roots {
    /// Map `name` to `dir`.
    pub fn insert(&mut self, name: &str, dir: PathBuf) {
        self.0.insert(name.to_owned(), dir);
    }

    /// Parse `name=path` (the first `=` splits).
    ///
    /// # Errors
    /// No `=`, or an empty name or path.
    pub fn parse(spec: &str) -> Result<(String, PathBuf), String> {
        match spec.split_once('=') {
            Some((n, p)) if !n.is_empty() && !p.is_empty() => Ok((n.to_owned(), p.into())),
            _ => Err(format!("expected name=path, got {spec:?}")),
        }
    }
}

/// What the bytes on this host say about a cited file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileState {
    /// The bytes still have the cited id.
    Same,
    /// The bytes differ: the file changed since it was cited.
    Changed {
        /// The id of the bytes now.
        current: RawContentId,
    },
    /// Not known, and why: the root is not mapped, the path leaves it, the
    /// file is missing, is not a regular file, is too big or cannot be read.
    Unavailable(String),
}

/// One state per cited file.
pub type Drift = BTreeMap<FileKey, FileState>;

/// A cited file as a map key: root, path and the id it was cited with.
pub type FileKey = (String, String, String);

/// The key of `f`.
#[must_use]
pub fn key(f: &FileRef) -> FileKey {
    (f.root.clone(), f.path.clone(), f.id.to_string())
}

fn no(why: &str) -> FileState {
    FileState::Unavailable(why.to_owned())
}

/// Check one cited file against the bytes under `roots`.
///
/// The file is opened strictly beneath the mapped root by
/// [`Beneath`]: relative to the root's own descriptor, with every symlink on
/// the way refused (a link that stays inside the root too: it is `?`), so no
/// directory swapped for a link between a check and the open can lead out.
#[must_use]
pub fn check(roots: &Roots, f: &FileRef) -> FileState {
    check_with(roots, f, &mut || {})
}

/// [`check`], calling `after_root` once the root is open and before the file
/// is: the window in which a pathname-based check could be lied to. A test
/// lands a directory swap there.
#[doc(hidden)]
#[must_use]
pub fn check_with(roots: &Roots, f: &FileRef, after_root: &mut dyn FnMut()) -> FileState {
    let Some(base) = roots.0.get(&f.root) else {
        return no("root not mapped");
    };
    let Ok(dir) = Beneath::root(base) else {
        return no("root missing");
    };
    after_root();
    let file = match dir.open(Path::new(&f.path)) {
        Ok(file) => file,
        Err(e) => {
            return no(match e.kind() {
                std::io::ErrorKind::NotFound => "file missing",
                std::io::ErrorKind::InvalidInput => "path leaves its root",
                _ => "path leaves its root or crosses a link",
            })
        }
    };
    read_id(file).map_or_else(FileState::Unavailable, |current| {
        if current == f.id {
            FileState::Same
        } else {
            FileState::Changed { current }
        }
    })
}

/// Hash what `file` (already opened beneath the root) holds.
fn read_id(file: std::fs::File) -> Result<RawContentId, String> {
    let meta = file.metadata().map_err(|e| format!("cannot stat: {e}"))?;
    if !meta.is_file() {
        return Err("not a regular file".to_owned());
    }
    if meta.len() > MAX_BYTES {
        return Err("file too big to check".to_owned());
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read: {e}"))?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err("file too big to check".to_owned());
    }
    Ok(RawContentId::from_content(&bytes))
}

/// Check every file in `files` (once each).
#[must_use]
pub fn check_all<'a>(roots: &Roots, files: impl IntoIterator<Item = &'a FileRef>) -> Drift {
    let mut out = Drift::new();
    for f in files {
        out.entry(key(f)).or_insert_with(|| check(roots, f));
    }
    out
}
