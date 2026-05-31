//! `amesh announce` — broadcast this agent's presence on the LAN.
//!
//! Issues an ephemeral [`AgentKey`] for the announce session, then
//! starts an mDNS responder via [`agent_mesh_discovery::Announcer`].
//! Holds the announcer alive either for a bounded duration (when
//! `--duration` is supplied) or until the user hits Ctrl-C.

use crate::util;
use agent_mesh_discovery::{AnnounceConfig, Announcer};
use agent_mesh_protocol::{AgentKey, AgentMetadata, Caveats, UserKey};
use anyhow::{Context, Result};
use std::path::PathBuf;

/// Run the `announce` subcommand.
pub async fn run(
    home: PathBuf,
    capabilities: Vec<String>,
    role: String,
    host: Option<String>,
    duration: Option<String>,
) -> Result<()> {
    let key_path = home.join("user.key");
    let user = UserKey::load(&key_path)
        .with_context(|| format!("load {} — run `amesh keygen` first", key_path.display()))?;

    let host = host.unwrap_or_else(util::current_hostname);

    // Issue an ephemeral agent key for this announce session. The
    // mesh never sees the private half; the user/agent fingerprints
    // are what go on the wire in the mDNS TXT record.
    let agent = AgentKey::issue(
        &user,
        AgentMetadata {
            role: role.clone(),
            host: host.clone(),
            capabilities: capabilities.clone(),
            issued_at: util::now_rfc3339(),
            expires_at: None,
            caveats: Caveats::top(),
        },
    );

    let agent_fp = agent.fingerprint();
    let user_fp = user.fingerprint();

    let _handle = Announcer::start(AnnounceConfig {
        agent_fp,
        // `amesh announce` is discovery-only — no transport bound,
        // so we don't publish a pubkey. Peers who want to dial
        // should use `amesh listen` instead (Phase 2).
        agent_pubkey: None,
        user_fp,
        capabilities: capabilities.clone(),
        role: role.clone(),
        host: host.clone(),
        port: 0,
    })?;

    println!(
        "announcing as agent_fp={} user_fp={}",
        agent_fp.hex(),
        user_fp.hex()
    );
    println!("  role={role} host={host} capabilities={capabilities:?}");

    if let Some(d) = duration {
        let dur = util::parse_duration(&d)?;
        println!("  duration={dur:?}");
        tokio::time::sleep(dur).await;
        println!("announce duration {dur:?} elapsed; stopping");
    } else {
        println!("  ctrl-c to stop");
        tokio::signal::ctrl_c().await.context("wait for ctrl-c")?;
        println!("ctrl-c received; stopping");
    }
    Ok(())
}
