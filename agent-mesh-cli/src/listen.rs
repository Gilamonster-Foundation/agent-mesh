//! `amesh listen` — bind a QUIC endpoint, announce it on mDNS, accept
//! incoming envelopes, print each one as JSON to stdout.
//!
//! This is `amesh announce` + transport listener in one. While
//! `amesh announce` is discovery-only (TXT carries no pubkey, peers
//! can find but not dial), `amesh listen` publishes the pubkey *and*
//! the bound iroh UDP port — making the agent fully reachable.
//!
//! Each accepted connection runs an independent handshake task; a
//! single listener can serve many peers concurrently.

use std::path::PathBuf;
use std::time::Duration;

use crate::util;
use agent_mesh_core::{AgentKey, AgentMetadata, CertChain, UserKey};
use agent_mesh_discovery::{AnnounceConfig, Announcer};
use agent_mesh_transport::{do_handshake, iroh_reexports::Incoming, recv_envelope, Endpoint};
use anyhow::{Context, Result};
use serde::Serialize;

/// JSON record printed per received envelope.
#[derive(Debug, Serialize)]
struct ReceivedRecord {
    sender_agent_fp: String,
    sender_user_fp: String,
    sequence: u64,
    /// UTF-8 view of payload if it's valid UTF-8; otherwise hex.
    payload: PayloadView,
}

#[derive(Debug, Serialize)]
#[serde(tag = "encoding", rename_all = "snake_case")]
enum PayloadView {
    Utf8 { text: String },
    Hex { hex: String },
}

impl PayloadView {
    fn of(bytes: &[u8]) -> Self {
        match std::str::from_utf8(bytes) {
            Ok(s) => Self::Utf8 { text: s.into() },
            Err(_) => Self::Hex {
                hex: hex::encode(bytes),
            },
        }
    }
}

/// Run the `listen` subcommand.
pub async fn run(home: PathBuf, duration: Option<String>) -> Result<()> {
    let key_path = home.join("user.key");
    let user = UserKey::load(&key_path)
        .with_context(|| format!("load {} — run `amesh keygen` first", key_path.display()))?;
    let host = util::current_hostname();

    let agent = AgentKey::issue(
        &user,
        AgentMetadata {
            role: "amesh-listen".into(),
            host: host.clone(),
            capabilities: vec![],
            issued_at: util::now_rfc3339(),
            expires_at: None,
        },
    );
    let agent_fp = agent.fingerprint();
    let agent_pubkey = agent.public_bytes();
    let user_fp = user.fingerprint();

    // Bind iroh first so we know the port to announce.
    let endpoint = Endpoint::bind(&agent, 0).await?;
    let port = endpoint.port();

    let _announcer = Announcer::start(AnnounceConfig {
        agent_fp,
        agent_pubkey: Some(agent_pubkey),
        user_fp,
        capabilities: vec![],
        role: "amesh-listen".into(),
        host: host.clone(),
        port,
    })?;

    println!("listening on udp/{port}");
    println!("  agent_fp={}", agent_fp.hex());
    println!("  user_fp ={}", user_fp.hex());
    println!("  host    ={host}");
    let stop_deadline = if let Some(d) = duration {
        let dur = util::parse_duration(&d)?;
        println!("  duration={dur:?}");
        Some(tokio::time::Instant::now() + dur)
    } else {
        println!("  ctrl-c to stop");
        None
    };

    let cert = agent.cert().clone();

    loop {
        let accept_fut = endpoint.accept();
        let next = match stop_deadline {
            Some(deadline) => {
                tokio::select! {
                    biased;
                    _ = tokio::time::sleep_until(deadline) => break,
                    _ = tokio::signal::ctrl_c() => {
                        println!("ctrl-c received; stopping");
                        break;
                    },
                    next = accept_fut => next,
                }
            }
            None => {
                tokio::select! {
                    biased;
                    _ = tokio::signal::ctrl_c() => {
                        println!("ctrl-c received; stopping");
                        break;
                    },
                    next = accept_fut => next,
                }
            }
        };
        let Some(incoming) = next else {
            // Endpoint closed.
            break;
        };
        let cert = cert.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_one(incoming, &cert).await {
                tracing::warn!(error = %e, "listener: connection error");
                eprintln!("connection error: {e}");
            }
        });
    }
    endpoint.close().await;
    Ok(())
}

async fn handle_one(incoming: Incoming, our_cert: &CertChain) -> Result<()> {
    let conn = incoming.await.context("await QUIC handshake")?;
    // First (and for now only) bidi stream per connection. Keep
    // accepting until the peer closes its send side.
    loop {
        let (mut send, mut recv) = match conn.accept_bi().await {
            Ok(streams) => streams,
            Err(e) => {
                tracing::debug!(error = %e, "accept_bi ended (peer closed)");
                return Ok(());
            }
        };
        // Use a deadline so a stalled handshake can't pin a stream.
        let peer_cert = match tokio::time::timeout(
            Duration::from_secs(5),
            do_handshake(our_cert, &mut send, &mut recv, false),
        )
        .await
        {
            Ok(Ok(cert)) => cert,
            Ok(Err(e)) => {
                eprintln!("rejected handshake: {e}");
                continue;
            }
            Err(_) => {
                eprintln!("handshake timed out after 5s");
                continue;
            }
        };
        // Now drain one envelope (Phase 2 ships one-shot envelopes
        // per stream; multi-message streams come later).
        match recv_envelope(&mut recv).await {
            Ok(env) => {
                let record = ReceivedRecord {
                    sender_agent_fp: env.sender_agent_fp().hex(),
                    sender_user_fp: env.sender_user_fp().hex(),
                    sequence: env.sequence,
                    payload: PayloadView::of(env.payload.as_ref()),
                };
                let line = serde_json::to_string(&record).expect("serialize record");
                println!("{line}");
                let _ = send.finish();
                // Reference peer_cert so it's not unused; the
                // tracing line below is the audit trail.
                tracing::debug!(peer = %peer_cert.agent_fingerprint().short(), "envelope received");
            }
            Err(e) => {
                eprintln!("envelope error: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_view_utf8_for_ascii() {
        match PayloadView::of(b"hello") {
            PayloadView::Utf8 { text } => assert_eq!(text, "hello"),
            other => panic!("expected utf8, got {other:?}"),
        }
    }

    #[test]
    fn payload_view_hex_for_invalid_utf8() {
        let bad = [0xffu8, 0xfe, 0xfd];
        match PayloadView::of(&bad) {
            PayloadView::Hex { hex } => assert_eq!(hex, "fffefd"),
            other => panic!("expected hex, got {other:?}"),
        }
    }
}
