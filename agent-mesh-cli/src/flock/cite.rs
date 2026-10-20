//! `--cite root:path`: turn a file under a declared, mapped root into the
//! `FileRef` an event carries. The CLI hashes the bytes itself (the session
//! signs what it is handed, as it does the body) with the same rule the TUI
//! uses to check them, and opens the file strictly beneath the root, so a
//! path or link cannot name a file outside it.

use agent_mesh_flock::FileRef;
use agent_mesh_flock_server::{file_id, Beneath, Snapshot};
use anyhow::{anyhow, bail, Context, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// `root:path` into its two halves (the first `:` splits).
fn split(spec: &str) -> Result<(&str, &str)> {
    match spec.split_once(':') {
        Some((root, path)) if !root.is_empty() && !path.is_empty() => Ok((root, path)),
        _ => bail!("--cite wants root:path, got {spec:?}"),
    }
}

/// The files `cites` name, as the log will cite them.
///
/// `declared` is the roster's roots, `mapped` the local `--root name=path`
/// mapping.
///
/// # Errors
/// A root the roster does not declare or this host does not map, a path
/// outside its root or through a link, a file that is missing, not regular,
/// too big or unreadable.
pub fn resolve(
    cites: &[String],
    declared: &[String],
    mapped: &BTreeMap<String, PathBuf>,
) -> Result<Vec<FileRef>> {
    let mut out: Vec<FileRef> = Vec::new();
    for spec in cites {
        let (root, path) = split(spec)?;
        if !declared.iter().any(|d| d == root) {
            bail!("--cite {spec}: the roster does not declare a root named {root:?}");
        }
        let Some(base) = mapped.get(root) else {
            bail!("--cite {spec}: root {root:?} is declared but not mapped on this host; add --root {root}=<dir>");
        };
        let dir = Beneath::root(base)
            .with_context(|| format!("--cite {spec}: root {root:?} ({})", base.display()))?;
        let file = dir.open(Path::new(path)).map_err(|e| {
            anyhow!(
                "--cite {spec}: {}",
                match e.kind() {
                    std::io::ErrorKind::NotFound => "no such file".to_owned(),
                    std::io::ErrorKind::InvalidInput => "the path leaves its root".to_owned(),
                    _ => "the path leaves its root or crosses a link".to_owned(),
                }
            )
        })?;
        let id = file_id(file).map_err(|why| anyhow!("--cite {spec}: {why}"))?;
        if !out.iter().any(|f| f.root == root && f.path == path) {
            out.push(FileRef {
                root: root.to_owned(),
                path: path.to_owned(),
                id,
            });
        }
    }
    Ok(out)
}

/// The roots the roster of the flock in `dir` declares.
///
/// # Errors
/// The log cannot be read.
pub fn declared_roots(dir: &Path) -> Result<Vec<String>> {
    let snap = Snapshot::read(dir).with_context(|| format!("read the log in {}", dir.display()))?;
    Ok(snap.board().roots().to_vec())
}
