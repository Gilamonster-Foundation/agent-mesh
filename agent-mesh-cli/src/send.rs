//! `amesh send` — discover a peer by fingerprint, dial it, and ship
//! a single signed envelope.
//!
//! Flow:
//!
//! 1. Load `user.key`, issue an ephemeral agent key for this send.
//! 2. Start a [`PeerResolver`]; wait up to `--timeout` for the peer
//!    fingerprint to appear on mDNS.
//! 3. Bind a local ephemeral [`Endpoint`].
//! 4. Dial the peer by iroh `PublicKey` (the raw 32-byte pubkey
//!    advertised in the peer's TXT record, alongside the
//!    fingerprint) and the addrs the resolver supplied.
//! 5. Drive the cert-chain handshake.
//! 6. Build a [`SignedEnvelope`] with the user's payload bytes,
//!    send it, finish the stream.

use std::path::PathBuf;
use std::str::FromStr;

use crate::util;
use agent_mesh_core::{AgentKey, AgentMetadata, Fingerprint, Recipient, SignedEnvelope, UserKey};
use agent_mesh_transport::{
    do_handshake, identity::agent_pubkey_to_iroh, send_envelope, Endpoint, PeerResolver,
};
use anyhow::{anyhow, Context, Result};

/// Run the `send` subcommand.
pub async fn run(home: PathBuf, peer_fp: String, payload: String, timeout: String) -> Result<()> {
    let key_path = home.join("user.key");
    let user = UserKey::load(&key_path)
        .with_context(|| format!("load {} — run `amesh keygen` first", key_path.display()))?;

    let target_fp = Fingerprint::from_str(&peer_fp)
        .with_context(|| format!("parse peer fingerprint {peer_fp:?}"))?;
    let dur = util::parse_duration(&timeout)?;

    // Ephemeral agent for this send session — the cert chain in the
    // envelope proves which user it belongs to; the agent itself
    // doesn't outlive this command.
    let host = util::current_hostname();
    let agent = AgentKey::issue(
        &user,
        AgentMetadata {
            role: "amesh-send".into(),
            host: host.clone(),
            capabilities: vec![],
            issued_at: util::now_rfc3339(),
            expires_at: None,
        },
    );

    println!("resolving peer {peer_fp} (timeout {dur:?})...");
    let (resolver, _resolver_handle) = PeerResolver::start()?;
    let peer = resolver
        .resolve(&target_fp, dur)
        .await
        .ok_or_else(|| anyhow!("peer {peer_fp} did not appear within {dur:?}"))?;

    if !peer.is_same_user(&user.fingerprint()) {
        return Err(anyhow!(
            "peer {peer_fp} belongs to user {} (we are {}); no pact exists",
            peer.user_fp.hex(),
            user.fingerprint().hex(),
        ));
    }
    if peer.port == 0 {
        return Err(anyhow!(
            "peer {peer_fp} advertised port 0 — discovery-only, not reachable. \
             ask the peer to run `amesh listen` instead of `amesh announce`."
        ));
    }
    let pubkey_bytes = peer
        .agent_pubkey
        .ok_or_else(|| anyhow!("peer {peer_fp} did not publish its ed25519 pubkey in mDNS — older `amesh announce`? need `amesh listen`."))?;
    let iroh_pubkey = agent_pubkey_to_iroh(&pubkey_bytes)
        .ok_or_else(|| anyhow!("peer {peer_fp} advertised invalid ed25519 pubkey bytes"))?;

    let local_ep = Endpoint::bind(&agent, 0).await?;
    let socket_addrs: Vec<std::net::SocketAddr> = peer
        .addrs
        .iter()
        .copied()
        .map(|ip| std::net::SocketAddr::new(ip, peer.port))
        .collect();
    println!("dialing peer at {socket_addrs:?} (alpn agent-mesh/v1)...");
    let conn = local_ep.dial(iroh_pubkey, socket_addrs).await?;
    let (mut send, mut recv) = conn.open_bi().await.context("open bidi stream")?;

    let peer_cert = do_handshake(agent.cert(), &mut send, &mut recv, true).await?;
    let peer_agent_fp = peer_cert.agent_fingerprint();

    let envelope = SignedEnvelope::new(
        &agent,
        Recipient::Direct {
            agent_fp: peer_agent_fp,
        },
        0,
        payload.into_bytes(),
    );
    send_envelope(&mut send, &envelope).await?;
    send.finish().context("finish send stream")?;

    println!(
        "sent envelope to {} ({} bytes payload)",
        peer_agent_fp.short(),
        envelope.payload.len()
    );
    local_ep.close().await;
    Ok(())
}
