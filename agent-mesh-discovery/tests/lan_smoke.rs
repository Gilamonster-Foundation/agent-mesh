//! End-to-end LAN smoke test: one announcer + one browser running in
//! the same process must see each other over mDNS within 10s.
//!
//! mDNS uses multicast on 224.0.0.251:5353. This test works on
//! loopback in most environments, including unprivileged CI runners.
//! If the runner has multicast disabled (uncommon for ubuntu-latest
//! GitHub Actions images), this test will time out; that's a real
//! failure to investigate, not a flake to silence.

use agent_mesh_discovery::{AnnounceConfig, Announcer, Browser, BrowserEvent};
use agent_mesh_protocol::Fingerprint;
use std::time::Duration;

fn fp_of(seed: u8) -> Fingerprint {
    Fingerprint([seed; 32])
}

fn hostname_or_default() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "test-host".to_string())
}

#[tokio::test(flavor = "multi_thread")]
async fn announce_and_browse_round_trip() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let user_fp = fp_of(42);
    let agent_fp = fp_of(7);

    let _announcer = Announcer::start(AnnounceConfig {
        agent_fp,
        agent_pubkey: None,
        user_fp,
        capabilities: vec!["ollama".into()],
        role: "test-worker".into(),
        host: hostname_or_default(),
        port: 0,
    })
    .expect("start announcer");

    let (_handle, mut rx) = Browser::start().expect("start browser");

    let timeout = tokio::time::sleep(Duration::from_secs(10));
    tokio::pin!(timeout);
    let mut saw_self = false;
    loop {
        tokio::select! {
            _ = &mut timeout => break,
            event = rx.recv() => {
                let Some(event) = event else { break };
                if let BrowserEvent::Resolved(peer) = event {
                    if peer.agent_fp == agent_fp {
                        assert_eq!(peer.user_fp, user_fp);
                        assert_eq!(peer.capabilities, vec!["ollama".to_string()]);
                        assert_eq!(peer.role, "test-worker");
                        assert!(peer.is_same_user(&user_fp));
                        saw_self = true;
                        break;
                    }
                }
            }
        }
    }

    assert!(saw_self, "browser did not see the announcer within 10s");
}

#[tokio::test(flavor = "multi_thread")]
async fn browser_returns_no_peers_when_no_announcers() {
    // Starting a browser when nobody is announcing should yield no
    // `Resolved` events within a short window. (`Removed` events for
    // stale records from prior test runs are acceptable.)
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (_handle, mut rx) = Browser::start().expect("start browser");

    let timeout = tokio::time::sleep(Duration::from_millis(500));
    tokio::pin!(timeout);
    let our_user_fp = fp_of(99);
    loop {
        tokio::select! {
            _ = &mut timeout => break,
            event = rx.recv() => {
                let Some(event) = event else { break };
                if let BrowserEvent::Resolved(peer) = event {
                    // Other test processes might run concurrently;
                    // any peer we see must NOT match our private
                    // fingerprint (we never announce one).
                    assert!(
                        !peer.is_same_user(&our_user_fp),
                        "unexpected same-user peer: {peer:?}"
                    );
                }
            }
        }
    }
}
