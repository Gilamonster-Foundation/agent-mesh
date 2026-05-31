//! 30-line request/reply round-trip — the canonical "the bus works"
//! integration test for Phase 3. Two `Bus` instances in the same
//! process under the same user fingerprint exchange one request and
//! one reply over real loopback UDP via QUIC + mDNS.

use agent_mesh_bus::{Bus, Topic};
use agent_mesh_protocol::{AgentKey, AgentMetadata, Caveats, UserKey};
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
