//! `amesh keygen` — generate a fresh user key.

use agent_mesh_core::UserKey;
use anyhow::{Context, Result};
use std::path::PathBuf;

/// Generate a new [`UserKey`] and write it to disk.
///
/// `home` is the resolved config directory; `path` overrides the
/// default `<home>/user.key` location when supplied. Refuses to
/// overwrite an existing key file.
pub fn run(home: PathBuf, path: Option<PathBuf>) -> Result<()> {
    let key_path = path.unwrap_or_else(|| home.join("user.key"));
    if key_path.exists() {
        anyhow::bail!(
            "key already exists at {} — refusing to overwrite",
            key_path.display()
        );
    }
    let key = UserKey::generate();
    key.save(&key_path)
        .with_context(|| format!("save key to {}", key_path.display()))?;
    let fp = key.fingerprint();
    println!("generated user key at {}", key_path.display());
    println!("fingerprint: {}", fp.hex());
    println!("short:       {}", fp.short());
    Ok(())
}
