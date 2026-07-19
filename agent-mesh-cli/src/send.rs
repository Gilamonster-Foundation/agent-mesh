//! `amesh send` — ship a single signed envelope to a peer, dialing it
//! either by mDNS discovery (resolve mode) or by explicit endpoint
//! (direct mode).
//!
//! Flow:
//!
//! 1. Load `user.key`, issue an ephemeral agent key for this send.
//! 2. Obtain the peer's `(iroh PublicKey, [SocketAddr])` dial route:
//!    * **resolve** — start a [`PeerResolver`] and wait up to
//!      `--timeout` for the peer fingerprint to appear on mDNS; the
//!      resolver supplies the pubkey and addrs.
//!    * **direct** (`--addr`/`--pubkey`) — the caller already knows
//!      the endpoint (WAN / WireGuard, or a loopback test); no mDNS.
//! 3. Bind a local ephemeral [`Endpoint`] and dial.
//! 4. Drive the cert-chain handshake.
//! 5. Build a [`SignedEnvelope`] with the user's payload bytes,
//!    send it, finish the stream.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use crate::util;
use agent_mesh_protocol::{
    AgentKey, AgentMetadata, Caveats, Fingerprint, Recipient, SignedEnvelope, UserKey,
};
use agent_mesh_transport::{
    do_handshake, identity::agent_pubkey_to_iroh, iroh_reexports::PublicKey, send_envelope,
    Endpoint, PeerResolver,
};
use anyhow::{anyhow, Context, Result};

/// Run the `send` subcommand.
///
/// `--addr`/`--pubkey` (direct mode) and the positional `peer_fp`
/// (resolve mode) are mutually exclusive ways to name the peer;
/// [`dial_route`] enforces the combinations.
pub async fn run(
    home: PathBuf,
    peer_fp: Option<String>,
    addr: Option<String>,
    pubkey: Option<String>,
    payload: String,
    timeout: String,
) -> Result<()> {
    let key_path = home.join("user.key");
    let user = UserKey::load(&key_path)
        .with_context(|| format!("load {} — run `amesh keygen` first", key_path.display()))?;

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
            caveats: Caveats::top(),
        },
    );

    let (iroh_pubkey, socket_addrs) = dial_route(&user, peer_fp, addr, pubkey, &timeout).await?;

    let local_ep = Endpoint::bind(&agent, 0).await?;
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
    send.stopped()
        .await
        .context("wait for peer to drain send stream")?;

    println!(
        "sent envelope to {} ({} bytes payload)",
        peer_agent_fp.short(),
        envelope.payload.len()
    );
    local_ep.close().await;
    Ok(())
}

/// Resolve the CLI's peer-naming arguments into an iroh dial route:
/// the peer's `PublicKey` and the socket addresses to try.
///
/// * **Direct** — `addr` is `Some`: `pubkey` is required and `addr`
///   must parse as a `SocketAddr`; mDNS is skipped. If the positional
///   `peer_fp` is also supplied it is treated as a checksum and must
///   equal `blake3(pubkey)`.
/// * **Resolve** — `addr` is `None`: `peer_fp` is required, `pubkey`
///   must be absent (it is only meaningful with `--addr`), and the
///   peer is located over mDNS.
async fn dial_route(
    user: &UserKey,
    peer_fp: Option<String>,
    addr: Option<String>,
    pubkey: Option<String>,
    timeout: &str,
) -> Result<(PublicKey, Vec<SocketAddr>)> {
    match addr {
        Some(addr) => {
            let pubkey_hex = pubkey.ok_or_else(|| {
                anyhow!("--addr requires --pubkey (the peer's 64-char hex agent pubkey)")
            })?;
            let pubkey_bytes = parse_pubkey_hex(&pubkey_hex)?;
            let sock: SocketAddr = addr
                .parse()
                .with_context(|| format!("parse --addr {addr:?} as <ip>:<port>"))?;

            // Optional checksum: if a fingerprint was also given, it must
            // match the one derived from the pubkey. Catches a copy-paste
            // mismatch between the two before we dial.
            if let Some(fp) = peer_fp {
                let expected = Fingerprint::from_str(&fp)
                    .with_context(|| format!("parse peer fingerprint {fp:?}"))?;
                let derived = Fingerprint::of_bytes(&pubkey_bytes);
                if derived != expected {
                    return Err(anyhow!(
                        "positional fingerprint {} does not match --pubkey (blake3 = {}); \
                         drop the positional or fix the pubkey",
                        expected.short(),
                        derived.short(),
                    ));
                }
            }

            let iroh_pubkey = agent_pubkey_to_iroh(&pubkey_bytes)
                .ok_or_else(|| anyhow!("--pubkey is not a valid ed25519 point"))?;
            Ok((iroh_pubkey, vec![sock]))
        }
        None => {
            if pubkey.is_some() {
                return Err(anyhow!(
                    "--pubkey only applies to direct dial; pass --addr too"
                ));
            }
            let peer_fp = peer_fp.ok_or_else(|| {
                anyhow!("give a peer fingerprint to resolve, or --addr/--pubkey to dial directly")
            })?;
            let target_fp = Fingerprint::from_str(&peer_fp)
                .with_context(|| format!("parse peer fingerprint {peer_fp:?}"))?;
            let dur = util::parse_duration(timeout)?;

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
            let pubkey_bytes = peer.agent_pubkey.ok_or_else(|| {
                anyhow!("peer {peer_fp} did not publish its ed25519 pubkey in mDNS — older `amesh announce`? need `amesh listen`.")
            })?;
            let iroh_pubkey = agent_pubkey_to_iroh(&pubkey_bytes)
                .ok_or_else(|| anyhow!("peer {peer_fp} advertised invalid ed25519 pubkey bytes"))?;
            let socket_addrs = peer
                .addrs
                .iter()
                .copied()
                .map(|ip| SocketAddr::new(ip, peer.port))
                .collect();
            Ok((iroh_pubkey, socket_addrs))
        }
    }
}

/// Parse a 64-char hex string into a 32-byte ed25519 pubkey.
fn parse_pubkey_hex(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s.trim())
        .with_context(|| "--pubkey must be 64-char hex (32 bytes)".to_string())?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow!("--pubkey decoded to {} bytes, need 32", v.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_user() -> UserKey {
        UserKey::generate()
    }

    #[test]
    fn parse_pubkey_hex_roundtrips_32_bytes() {
        let hexstr = "ab".repeat(32);
        let parsed = parse_pubkey_hex(&hexstr).unwrap();
        assert_eq!(parsed, [0xab; 32]);
    }

    #[test]
    fn parse_pubkey_hex_rejects_wrong_length() {
        let err = parse_pubkey_hex(&"ab".repeat(16)).unwrap_err();
        assert!(err.to_string().contains("16 bytes"), "got: {err}");
    }

    #[tokio::test]
    async fn direct_dial_requires_pubkey() {
        let user = test_user();
        let err = dial_route(&user, None, Some("127.0.0.1:47800".into()), None, "10s")
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("--addr requires --pubkey"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn pubkey_without_addr_is_rejected() {
        let user = test_user();
        let err = dial_route(&user, None, None, Some("ab".repeat(32)), "10s")
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("--pubkey only applies to direct dial"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn no_peer_and_no_addr_is_rejected() {
        let user = test_user();
        let err = dial_route(&user, None, None, None, "10s")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("dial directly"), "got: {err}");
    }

    #[tokio::test]
    async fn direct_dial_with_mismatched_fingerprint_is_rejected() {
        let user = test_user();
        // A valid ed25519 pubkey to dial, but a fingerprint that does
        // not derive from it.
        let pk = "ab".repeat(32);
        let err = dial_route(
            &user,
            Some("00".repeat(32)),
            Some("127.0.0.1:47800".into()),
            Some(pk),
            "10s",
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("does not match --pubkey"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn direct_dial_matching_fingerprint_yields_route() {
        let user = test_user();
        // Derive a real agent pubkey + its fingerprint so the checksum
        // path succeeds and produces a dial route.
        let agent = AgentKey::issue(
            &user,
            AgentMetadata {
                role: "t".into(),
                host: "t".into(),
                capabilities: vec![],
                issued_at: "2026-06-08T00:00:00Z".into(),
                expires_at: None,
                caveats: Caveats::top(),
            },
        );
        let pk = agent.public_bytes();
        let fp = Fingerprint::of_bytes(&pk);
        let (_iroh_pubkey, addrs) = dial_route(
            &user,
            Some(fp.hex()),
            Some("127.0.0.1:47800".into()),
            Some(hex::encode(pk)),
            "10s",
        )
        .await
        .expect("route builds");
        assert_eq!(
            addrs,
            vec!["127.0.0.1:47800".parse::<SocketAddr>().unwrap()]
        );
    }
}
