//! `Bus::close` returns only once the endpoint's socket is released (#152): a
//! restarted bus can bind the same port straight away, with no retry and no
//! sleep. The in-flight case is the deterministic one: a handler that never
//! returns holds the per-inbound task, which holds the transport, which holds
//! the endpoint, until `close` aborts and awaits it.

use agent_mesh_bus::{Bus, BusOptions, PeerEndpoint, Topic};
use agent_mesh_protocol::{AgentKey, AgentMetadata, Caveats, UserKey};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

fn agent(user: &UserKey, role: &str) -> AgentKey {
    AgentKey::issue(
        user,
        AgentMetadata {
            role: role.into(),
            host: "test".into(),
            capabilities: vec!["test".into()],
            issued_at: "2026-10-19T00:00:00Z".into(),
            expires_at: None,
            caveats: Caveats::top(),
        },
    )
}

const QUIET: BusOptions = BusOptions { announce: false };

#[tokio::test(flavor = "multi_thread")]
async fn a_bus_whose_handler_is_still_running_releases_its_port_when_close_returns() {
    let user = UserKey::generate();
    let (alice, bob) = (agent(&user, "alice"), agent(&user, "bob"));
    let bob_pub = bob.public_bytes();
    let alice_bus = Arc::new(Bus::bind_with(&user, alice, 0, QUIET).await.unwrap());
    let bob_bus = Bus::bind_with(&user, bob, 0, QUIET).await.unwrap();
    let port = bob_bus.local_port();

    // a handler that has started and never finishes
    let (entered_tx, mut entered_rx) = mpsc::unbounded_channel::<()>();
    let topic = Topic::new(user.fingerprint(), "stuck");
    bob_bus.handle_requests(topic.clone(), move |_| {
        let entered = entered_tx.clone();
        async move {
            let _ = entered.send(());
            std::future::pending::<()>().await;
            Ok(Vec::new())
        }
    });
    let peer = PeerEndpoint::new(bob_pub, SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port));
    let ask = {
        let alice_bus = alice_bus.clone();
        tokio::spawn(async move {
            alice_bus
                .request_direct(peer, &topic, b"x".to_vec(), Duration::from_secs(60))
                .await
        })
    };
    // causal: wait for the handler to be running, not for a clock
    entered_rx.recv().await.expect("the handler started");

    bob_bus.close().await.unwrap();

    // the very next bind on the same port: no retry, no sleep
    let again = Bus::bind_with(&user, agent(&user, "bob2"), port, QUIET)
        .await
        .expect("the port is free the moment close returns");
    assert_eq!(again.local_port(), port);
    again.close().await.unwrap();
    ask.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bus_that_has_served_a_connection_releases_its_port_when_close_returns() {
    let user = UserKey::generate();
    let (alice, bob) = (agent(&user, "alice"), agent(&user, "bob"));
    let bob_pub = bob.public_bytes();
    let alice_bus = Bus::bind_with(&user, alice, 0, QUIET).await.unwrap();
    let bob_bus = Bus::bind_with(&user, bob, 0, QUIET).await.unwrap();
    let port = bob_bus.local_port();
    let topic = Topic::new(user.fingerprint(), "echo");
    bob_bus.handle_requests(topic.clone(), |b| async move { Ok(b) });
    let peer = PeerEndpoint::new(bob_pub, SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port));
    let reply = alice_bus
        .request_direct(peer, &topic, b"hi".to_vec(), Duration::from_secs(10))
        .await
        .unwrap();
    assert_eq!(reply, b"hi");

    bob_bus.close().await.unwrap();

    let again = Bus::bind_with(&user, agent(&user, "bob2"), port, QUIET)
        .await
        .expect("the port is free the moment close returns");
    again.close().await.unwrap();
    alice_bus.close().await.unwrap();
}
