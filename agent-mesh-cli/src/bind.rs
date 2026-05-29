//! `amesh bind github` — cross-sign the user key with a GitHub SSH
//! ed25519 key.

use agent_mesh_core::{GitHubBinding, UserKey};
use anyhow::{Context, Result};
use ssh_key::PrivateKey as SshPrivateKey;
use std::path::PathBuf;

/// Read the user key, read the SSH key, produce a [`GitHubBinding`],
/// and write it to `<home>/user.github.sig` as pretty-printed JSON.
pub fn github(home: PathBuf, ssh_key: Option<PathBuf>, username: Option<String>) -> Result<()> {
    let user_key_path = home.join("user.key");
    let user = UserKey::load(&user_key_path).with_context(|| {
        format!(
            "load user key at {} — run `amesh keygen` first",
            user_key_path.display()
        )
    })?;

    let ssh_path = ssh_key.unwrap_or_else(default_ssh_key_path);
    let ssh_pem = std::fs::read_to_string(&ssh_path)
        .with_context(|| format!("read SSH key from {}", ssh_path.display()))?;
    let ssh = SshPrivateKey::from_openssh(&ssh_pem)
        .context("parse SSH key (must be ed25519, unencrypted)")?;

    let binding = GitHubBinding::sign(&user.public(), &ssh, username.clone())?;

    let binding_path = home.join("user.github.sig");
    if let Some(parent) = binding_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let json = serde_json::to_string_pretty(&binding)?;
    std::fs::write(&binding_path, json)?;

    println!("github binding written to {}", binding_path.display());
    if let Some(u) = username {
        println!("username hint: {u}");
    }
    println!(
        "ssh pubkey fingerprint (first 16 hex chars): {}",
        &hex::encode(binding.ssh_pubkey)[..16]
    );
    Ok(())
}

/// Default SSH key location, `~/.ssh/id_ed25519`. Falls back to a
/// relative path if `$HOME` is unset.
fn default_ssh_key_path() -> PathBuf {
    dirs::home_dir()
        .map(|h| h.join(".ssh/id_ed25519"))
        .unwrap_or_else(|| PathBuf::from("id_ed25519"))
}
