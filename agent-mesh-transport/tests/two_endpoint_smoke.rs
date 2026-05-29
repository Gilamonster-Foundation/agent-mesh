//! End-to-end smoke tests: two endpoints in the same process,
//! talking to each other over real loopback UDP.
//!
//! These are integration tests because they exercise the public
//! surface of `agent-mesh-transport` the way the CLI does — bind,
//! dial, handshake, exchange envelope, verify.

use std::time::Duration;

use agent_mesh_core::{AgentKey, AgentMetadata, Fingerprint, Recipient, SignedEnvelope, UserKey};
use agent_mesh_transport::{
    do_handshake, identity::agent_pubkey_to_iroh, recv_envelope, send_envelope, Endpoint,
    TransportError,
};

/// Issue a deterministic-metadata agent key for tests.
fn agent_for(user: &UserKey, role: &str) -> AgentKey {
    AgentKey::issue(
        user,
        AgentMetadata {
            role: role.into(),
            host: "test-host".into(),
            capabilities: vec!["test".into()],
            issued_at: "2026-05-28T00:00:00Z".into(),
            expires_at: None,
        },
    )
}

/// Try to wrap the body in a 10s wall-clock fence. Tests can be
/// slow if iroh's initial bind warms a lot of state, but they
/// MUST NOT hang forever.
async fn within_10s<F: std::future::Future<Output = ()>>(label: &str, fut: F) {
    if tokio::time::timeout(Duration::from_secs(10), fut)
        .await
        .is_err()
    {
        panic!("{label} did not complete within 10s");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn two_endpoints_same_user_can_exchange_envelope() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    within_10s("same-user exchange", async {
        let user = UserKey::generate();
        let alice = agent_for(&user, "alice");
        let bob = agent_for(&user, "bob");
        let bob_fp = bob.fingerprint();
        let alice_cert = alice.cert().clone();
        let bob_cert = bob.cert().clone();

        let alice_ep = Endpoint::bind(&alice, 0).await.expect("alice bind");
        let bob_ep = Endpoint::bind(&bob, 0).await.expect("bob bind");

        let bob_pubkey =
            agent_pubkey_to_iroh(&bob.public_bytes()).expect("bob pubkey -> iroh PublicKey");
        let bob_addrs: Vec<std::net::SocketAddr> = bob_ep
            .local_socket_addrs()
            .into_iter()
            .map(|s| match s {
                std::net::SocketAddr::V6(v6) if v6.ip().is_unspecified() => {
                    std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                        "::1".parse().unwrap(),
                        v6.port(),
                        v6.flowinfo(),
                        v6.scope_id(),
                    ))
                }
                std::net::SocketAddr::V4(v4) if v4.ip().is_unspecified() => {
                    std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                        "127.0.0.1".parse().unwrap(),
                        v4.port(),
                    ))
                }
                other => other,
            })
            .collect();

        // Bob accepts.
        let bob_handle = tokio::spawn(async move {
            let incoming = bob_ep.accept().await.expect("bob got incoming");
            let conn = incoming.await.expect("bob handshake");
            let (mut send, mut recv) = conn.accept_bi().await.expect("bob accept_bi");
            let peer_cert = do_handshake(&bob_cert, &mut send, &mut recv, false)
                .await
                .expect("bob handshake");
            let env = recv_envelope(&mut recv).await.expect("bob recv envelope");
            (peer_cert, env)
        });

        // Alice dials.
        let conn = alice_ep
            .dial(bob_pubkey, bob_addrs)
            .await
            .expect("alice dial");
        let (mut send, mut recv) = conn.open_bi().await.expect("alice open_bi");
        let peer_cert = do_handshake(&alice_cert, &mut send, &mut recv, true)
            .await
            .expect("alice handshake");
        assert_eq!(peer_cert.agent_fingerprint(), bob.fingerprint());

        let env = SignedEnvelope::new(
            &alice,
            Recipient::Direct { agent_fp: bob_fp },
            0,
            b"hello".to_vec(),
        );
        send_envelope(&mut send, &env)
            .await
            .expect("alice send envelope");
        send.finish().expect("alice finish stream");

        let (bob_peer_cert, received) = bob_handle.await.expect("bob task joined");
        assert_eq!(bob_peer_cert.agent_fingerprint(), alice.fingerprint());
        assert_eq!(received.payload.as_ref(), b"hello");
        received.verify().expect("received envelope verifies");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn different_users_rejected_by_handshake() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    within_10s("different-user rejection", async {
        let user_a = UserKey::generate();
        let user_b = UserKey::generate();
        let alice = agent_for(&user_a, "alice");
        let bob = agent_for(&user_b, "bob");

        let alice_cert = alice.cert().clone();
        let bob_cert = bob.cert().clone();

        let alice_ep = Endpoint::bind(&alice, 0).await.expect("alice bind");
        let bob_ep = Endpoint::bind(&bob, 0).await.expect("bob bind");

        let bob_pubkey = agent_pubkey_to_iroh(&bob.public_bytes()).expect("bob iroh pubkey");
        let bob_addrs: Vec<std::net::SocketAddr> = bob_ep
            .local_socket_addrs()
            .into_iter()
            .map(|s| match s {
                std::net::SocketAddr::V6(v6) if v6.ip().is_unspecified() => {
                    std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                        "::1".parse().unwrap(),
                        v6.port(),
                        v6.flowinfo(),
                        v6.scope_id(),
                    ))
                }
                std::net::SocketAddr::V4(v4) if v4.ip().is_unspecified() => {
                    std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                        "127.0.0.1".parse().unwrap(),
                        v4.port(),
                    ))
                }
                other => other,
            })
            .collect();

        let bob_handle = tokio::spawn(async move {
            let incoming = bob_ep.accept().await.expect("bob incoming");
            let conn = incoming.await.expect("bob handshake");
            let (mut send, mut recv) = conn.accept_bi().await.expect("bob accept_bi");
            // Acceptor side should see DifferentUser and refuse.
            do_handshake(&bob_cert, &mut send, &mut recv, false).await
        });

        let conn = alice_ep
            .dial(bob_pubkey, bob_addrs)
            .await
            .expect("alice dial");
        let (mut send, mut recv) = conn.open_bi().await.expect("alice open_bi");
        let res = do_handshake(&alice_cert, &mut send, &mut recv, true).await;

        // Both sides should err with DifferentUser.
        match res {
            Err(TransportError::DifferentUser { .. }) => {}
            other => panic!("alice expected DifferentUser, got {other:?}"),
        }
        let bob_res = bob_handle.await.expect("bob joined");
        match bob_res {
            Err(TransportError::DifferentUser { .. }) => {}
            other => panic!("bob expected DifferentUser, got {other:?}"),
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn tampered_payload_is_rejected_on_receipt() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    within_10s("tampered envelope rejection", async {
        let user = UserKey::generate();
        let alice = agent_for(&user, "alice");
        let bob = agent_for(&user, "bob");
        let bob_fp = bob.fingerprint();
        let alice_cert = alice.cert().clone();
        let bob_cert = bob.cert().clone();

        let alice_ep = Endpoint::bind(&alice, 0).await.expect("alice bind");
        let bob_ep = Endpoint::bind(&bob, 0).await.expect("bob bind");

        let bob_pubkey = agent_pubkey_to_iroh(&bob.public_bytes()).unwrap();
        let bob_addrs: Vec<std::net::SocketAddr> = bob_ep
            .local_socket_addrs()
            .into_iter()
            .map(|s| match s {
                std::net::SocketAddr::V6(v6) if v6.ip().is_unspecified() => {
                    std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                        "::1".parse().unwrap(),
                        v6.port(),
                        v6.flowinfo(),
                        v6.scope_id(),
                    ))
                }
                std::net::SocketAddr::V4(v4) if v4.ip().is_unspecified() => {
                    std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                        "127.0.0.1".parse().unwrap(),
                        v4.port(),
                    ))
                }
                other => other,
            })
            .collect();

        let bob_handle = tokio::spawn(async move {
            let incoming = bob_ep.accept().await.expect("incoming");
            let conn = incoming.await.expect("connect");
            let (mut send, mut recv) = conn.accept_bi().await.expect("accept_bi");
            do_handshake(&bob_cert, &mut send, &mut recv, false)
                .await
                .expect("handshake");
            recv_envelope(&mut recv).await
        });

        let conn = alice_ep.dial(bob_pubkey, bob_addrs).await.expect("dial");
        let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");
        do_handshake(&alice_cert, &mut send, &mut recv, true)
            .await
            .expect("handshake");

        let mut env = SignedEnvelope::new(
            &alice,
            Recipient::Direct { agent_fp: bob_fp },
            0,
            b"original".to_vec(),
        );
        // Tamper after signing so verify() fails on Bob's side.
        env.payload = serde_bytes::ByteBuf::from(b"tampered".to_vec());
        send_envelope(&mut send, &env).await.expect("send");
        send.finish().expect("finish");

        let bob_res = bob_handle.await.expect("bob join");
        match bob_res {
            Err(TransportError::BadEnvelope(_)) => {}
            other => panic!("expected BadEnvelope, got {other:?}"),
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn fingerprint_referenced_in_test_to_keep_used() {
    // Anchors that `Fingerprint` is in the prelude of this test
    // module — silences `unused_imports` if other tests grow to
    // not reference it directly.
    let fp = Fingerprint::of_bytes(b"x");
    assert_eq!(fp.hex().len(), 64);
}
