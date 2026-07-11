//! Request/reply round-trip integration tests over the REAL iroh transport.
//!
//! Tiering (#166): the request/reply/inbox/reply-routing LOGIC is covered
//! deterministically, with no sockets, by the in-memory-transport test in
//! `bus.rs` (`request_reply_roundtrip_over_in_memory_transport`) plus the
//! `inbox` unit tests. The tests here exercise the *real* QUIC/mDNS stack:
//!
//! - [`request_reply_roundtrip_via_direct_dial_no_mdns`] — real QUIC over
//!   loopback, no multicast. Deterministic enough to gate every PR; it is the
//!   per-PR real-transport smoke.
//! - [`request_reply_roundtrip`] and [`reply_reaches_quiet_asker_via_dial_back`]
//!   additionally depend on **mDNS multicast discovery**, which is flaky on
//!   hosted CI runners (no reliable multicast; the resolve races a 5s
//!   timeout). They are `#[ignore]`d — run them on demand with
//!   `cargo test -- --ignored` on a real LAN. Their bus-logic coverage is
//!   already provided by the deterministic tests above; what they uniquely
//!   touch is the real multicast-discovery path.

use agent_mesh_bus::{Bus, BusOptions, PeerEndpoint, Topic};
use agent_mesh_protocol::{AgentKey, AgentMetadata, Caveats, UserKey};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

fn agent(user: &UserKey, role: &str) -> AgentKey {
    AgentKey::issue(
        user,
        AgentMetadata {
            role: role.into(),
            host: "test".into(),
            capabilities: vec!["test".into()],
            issued_at: "2026-05-28T12:00:00Z".into(),
            expires_at: None,
            caveats: Caveats::top(),
        },
    )
}

// Real mDNS multicast discovery — flaky on hosted CI (see the module doc).
// The bus-logic round-trip is covered deterministically in-memory in `bus.rs`.
#[ignore = "real mDNS multicast discovery; flaky on hosted CI. Run with --ignored on a real LAN. Logic covered by the in-memory-transport test in bus.rs."]
#[tokio::test(flavor = "multi_thread")]
async fn request_reply_roundtrip() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let user = UserKey::generate();
    let alice = agent(&user, "alice");
    let bob = agent(&user, "bob");
    let bob_fp = bob.fingerprint();

    let alice_bus = Bus::bind(&user, alice, 0).await.unwrap();
    let bob_bus = Bus::bind(&user, bob, 0).await.unwrap();

    let topic = Topic::new(user.fingerprint(), "echo");
    bob_bus.handle_requests(topic.clone(), |body| async move {
        Ok(format!("echo: {}", String::from_utf8_lossy(&body)).into_bytes())
    });

    // Brief pause for handler registration + mDNS discovery to settle.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let reply = alice_bus
        .request(bob_fp, &topic, b"hi".to_vec(), Duration::from_secs(10))
        .await
        .expect("request reply");
    assert_eq!(reply, b"echo: hi");

    alice_bus.close().await.unwrap();
    bob_bus.close().await.unwrap();
}

/// Regression test for the reply dial-back path: an asker that is NOT
/// announced over mDNS must still receive its reply, because the
/// responder dials back the UDP source the request physically came
/// from instead of resolving the asker by fingerprint.
///
/// Before dial-back landed this timed out — the responder waited 5s for an
/// mDNS announce that never came (the same failure mode as the cold-start
/// race where an announced asker's record simply hasn't propagated yet).
///
/// Still resolves BOB over mDNS multicast, so it carries the same
/// hosted-CI flakiness as [`request_reply_roundtrip`] and is likewise
/// `#[ignore]`d — run on demand on a real LAN.
#[ignore = "real mDNS multicast discovery (resolves bob); flaky on hosted CI. Run with --ignored on a real LAN."]
#[tokio::test(flavor = "multi_thread")]
async fn reply_reaches_quiet_asker_via_dial_back() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let user = UserKey::generate();
    let alice = agent(&user, "quiet-asker");
    let bob = agent(&user, "bob");
    let bob_fp = bob.fingerprint();

    // Quiet bind: alice never announces, so mDNS resolution of her
    // fingerprint is impossible by construction.
    let alice_bus = Bus::bind_with(&user, alice, 0, BusOptions { announce: false })
        .await
        .unwrap();
    let bob_bus = Bus::bind(&user, bob, 0).await.unwrap();

    let topic = Topic::new(user.fingerprint(), "echo");
    bob_bus.handle_requests(topic.clone(), |body| async move {
        Ok(format!("echo: {}", String::from_utf8_lossy(&body)).into_bytes())
    });

    // Brief pause for handler registration + bob's mDNS announce to
    // settle (alice still needs to resolve *bob*).
    tokio::time::sleep(Duration::from_millis(500)).await;

    let reply = alice_bus
        .request(bob_fp, &topic, b"hi".to_vec(), Duration::from_secs(10))
        .await
        .expect("reply must arrive via dial-back despite no asker announce");
    assert_eq!(reply, b"echo: hi");

    alice_bus.close().await.unwrap();
    bob_bus.close().await.unwrap();
}

/// Direct-dial (#29): a request/reply round-trip where the asker dials
/// the responder by an explicit `(agent_pubkey, SocketAddr)` and
/// **neither bus announces over mDNS**. This is the WAN / WireGuard
/// dial path — the phone has L3 reachability to a known agent address
/// but no multicast, so the resolver is skipped entirely.
///
/// Both buses bind quiet (`announce: false`), so mDNS discovery is
/// impossible by construction: if `request_direct` leaned on the
/// resolver at all, this would time out. The reply still routes back
/// over the freshly-dialed reverse connection by correlation id.
#[tokio::test(flavor = "multi_thread")]
async fn request_reply_roundtrip_via_direct_dial_no_mdns() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let user = UserKey::generate();
    let alice = agent(&user, "alice");
    let bob = agent(&user, "bob");
    // Capture bob's agent pubkey before the AgentKey is moved into the
    // bus — this plus bob's bound port is the entire dial route.
    let bob_pubkey = bob.public_bytes();

    // Quiet binds: NO mDNS announcement on either side.
    let alice_bus = Bus::bind_with(&user, alice, 0, BusOptions { announce: false })
        .await
        .unwrap();
    let bob_bus = Bus::bind_with(&user, bob, 0, BusOptions { announce: false })
        .await
        .unwrap();

    let topic = Topic::new(user.fingerprint(), "echo");
    bob_bus.handle_requests(topic.clone(), |body| async move {
        Ok(format!("echo: {}", String::from_utf8_lossy(&body)).into_bytes())
    });

    // Brief pause only for handler registration to settle — there is
    // no discovery to wait on.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // The explicit dial route: bob's agent pubkey + his loopback addr.
    let bob_endpoint = PeerEndpoint::new(
        bob_pubkey,
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), bob_bus.local_port()),
    );
    // The fingerprint the bus will address the envelope to is derived
    // from the pubkey — it must match bob's announced identity.
    assert_eq!(bob_endpoint.fingerprint(), bob_bus.agent_fingerprint());

    let reply = alice_bus
        .request_direct(
            bob_endpoint,
            &topic,
            b"hi".to_vec(),
            Duration::from_secs(10),
        )
        .await
        .expect("direct-dial request must round-trip without mDNS");
    assert_eq!(reply, b"echo: hi");

    alice_bus.close().await.unwrap();
    bob_bus.close().await.unwrap();
}
