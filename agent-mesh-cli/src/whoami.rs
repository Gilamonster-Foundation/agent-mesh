//! `amesh whoami` — print the local user identity.

use agent_mesh_protocol::UserKey;
use anyhow::{Context, Result};
use std::path::PathBuf;

/// Load the user key from `<home>/user.key` and print its
/// fingerprint, plus any GitHub binding hint we find alongside it.
pub fn run(home: PathBuf) -> Result<()> {
    let key_path = home.join("user.key");
    let key = UserKey::load(&key_path)
        .with_context(|| format!("load {} — run `amesh keygen` first?", key_path.display()))?;
    let fp = key.fingerprint();
    println!("user fingerprint: {}", fp.hex());
    println!("short:            {}", fp.short());

    let binding_path = home.join("user.github.sig");
    if binding_path.exists() {
        let json = std::fs::read_to_string(&binding_path)?;
        let binding: agent_mesh_protocol::GitHubBinding = serde_json::from_str(&json)?;
        match binding.github_username.as_deref() {
            Some(u) => println!("github binding:   {u} (hint)"),
            None => println!("github binding:   (no username hint)"),
        }
    } else {
        println!("github binding:   none (run `amesh bind github` to add one)");
    }

    Ok(())
}
