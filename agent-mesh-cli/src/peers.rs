//! `amesh peers` — list LAN peers seen via mDNS.
//!
//! Starts a [`Browser`](agent_mesh_discovery::Browser), collects
//! `Resolved`/`Removed` events for `--listen` seconds, then prints a
//! tabular summary tagged with `SAME?` based on the local user
//! fingerprint.

use crate::util;
use agent_mesh_core::UserKey;
use agent_mesh_discovery::{Browser, BrowserEvent, PeerInfo};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::PathBuf;

/// Run the `peers` subcommand.
pub async fn run(home: PathBuf, listen: String, same_user_only: bool) -> Result<()> {
    let key_path = home.join("user.key");
    let user = UserKey::load(&key_path)
        .with_context(|| format!("load {} — run `amesh keygen` first", key_path.display()))?;
    let our_user_fp = user.fingerprint();

    let listen_dur = util::parse_duration(&listen)?;
    println!("listening for peers for {listen_dur:?}...");

    let (_handle, mut rx) = Browser::start()?;
    let mut peers: HashMap<String, PeerInfo> = HashMap::new();

    let deadline = tokio::time::sleep(listen_dur);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => break,
            event = rx.recv() => {
                let Some(event) = event else { break };
                match event {
                    BrowserEvent::Resolved(peer) => {
                        peers.insert(peer.instance.clone(), peer);
                    }
                    BrowserEvent::Removed { instance } => {
                        peers.remove(&instance);
                    }
                }
            }
        }
    }

    let mut sorted: Vec<&PeerInfo> = peers
        .values()
        .filter(|p| !same_user_only || p.is_same_user(&our_user_fp))
        .collect();
    sorted.sort_by(|a, b| a.role.cmp(&b.role).then_with(|| a.host.cmp(&b.host)));

    println!();
    println!("discovered {} peer(s):", sorted.len());
    println!();
    println!(
        "{:<14} {:<6} {:<24} {:<6} CAPABILITIES",
        "AGENT", "SAME?", "ROLE@HOST", "PORT"
    );
    for p in &sorted {
        let same_marker = if p.is_same_user(&our_user_fp) {
            "yes"
        } else {
            "no"
        };
        let role_host = format!("{}@{}", p.role, p.host);
        let caps = p.capabilities.join(",");
        let agent_short = p.agent_fp.short();
        let port = p.port;
        println!("{agent_short:<14} {same_marker:<6} {role_host:<24} {port:<6} {caps}");
    }
    Ok(())
}
