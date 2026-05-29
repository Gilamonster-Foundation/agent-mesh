//! `amesh verify` — fetch a GitHub user's public keys and check that
//! one of them validates a binding file.

use agent_mesh_protocol::{ssh_pubkey_ed25519_bytes, GitHubBinding};
use anyhow::{Context, Result};
use ssh_key::PublicKey as SshPublicKey;
use std::path::PathBuf;

/// Verify a binding against `https://github.com/<github_user>.keys`.
///
/// Returns `Ok(())` on the first ed25519 key that validates the
/// binding; errors out if no key in the response succeeds.
pub async fn run(binding_path: PathBuf, github_user: String) -> Result<()> {
    let json = std::fs::read_to_string(&binding_path)
        .with_context(|| format!("read binding from {}", binding_path.display()))?;
    let binding: GitHubBinding = serde_json::from_str(&json)?;

    let url = format!("https://github.com/{github_user}.keys");
    let resp = reqwest::get(&url)
        .await
        .with_context(|| format!("fetch {url}"))?;
    if !resp.status().is_success() {
        anyhow::bail!(
            "github.com returned {} for {}.keys",
            resp.status(),
            github_user
        );
    }
    let keys_text = resp.text().await?;

    let mut tried = 0;
    for line in keys_text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let parsed = match SshPublicKey::from_openssh(line) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let bytes = match ssh_pubkey_ed25519_bytes(&parsed) {
            Ok(b) => b,
            Err(_) => continue, // not an ed25519 key, skip
        };
        tried += 1;
        if binding.verify(&bytes).is_ok() {
            println!("binding verified");
            println!(
                "  agent-mesh user: {}",
                binding.user_pubkey.fingerprint().hex()
            );
            println!("  github user:     {github_user}");
            return Ok(());
        }
    }

    anyhow::bail!(
        "no ed25519 key in github.com/{github_user}.keys verified the binding (tried {tried} keys)"
    );
}
