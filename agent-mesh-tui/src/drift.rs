//! "Changed since cited": compare a cited file's id with the bytes on this
//! host now. Events cite files as `root/path` plus the id of the bytes at the
//! time; the roster does not declare roots yet, so the operator maps them
//! (`--root name=path`, home-local). Nothing here writes: files are opened for
//! reading, never created, and a path that leaves its root is never opened.

use agent_mesh_flock::FileRef;
use content_addressable::RawContentId;
use rustix::fs::{Mode, OFlags};
use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

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
#[must_use]
pub fn check(roots: &Roots, f: &FileRef) -> FileState {
    let Some(base) = roots.0.get(&f.root) else {
        return no("root not mapped");
    };
    let rel = Path::new(&f.path);
    // lexical first: an absolute path or `..` never reaches the file system
    if f.path.is_empty()
        || rel.is_absolute()
        || rel
            .components()
            .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir))
    {
        return no("path leaves its root");
    }
    let Ok(base) = std::fs::canonicalize(base) else {
        return no("root missing");
    };
    // then the real path: a symlink anywhere on it may lead out
    let Ok(real) = std::fs::canonicalize(base.join(rel)) else {
        return no("file missing");
    };
    if !real.starts_with(&base) {
        return no("path leaves its root");
    }
    read_id(&real).map_or_else(FileState::Unavailable, |current| {
        if current == f.id {
            FileState::Same
        } else {
            FileState::Changed { current }
        }
    })
}

/// Read `real` (already resolved, so no symlink on it) and hash it.
fn read_id(real: &Path) -> Result<RawContentId, String> {
    // O_NOFOLLOW: if the last component was swapped for a link after the
    // check, the open fails instead of following it.
    let fd = rustix::fs::open(
        real,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| format!("cannot open: {e}"))?;
    let file = std::fs::File::from(fd);
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
