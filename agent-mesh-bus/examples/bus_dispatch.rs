//! Phase-3 gate-1 reference: dispatch foreman over agent-mesh-bus.
//!
//! Companion to `examples/nats_dispatch.rs` — same shape, same wire
//! types, different transport. Both examples are referenced from
//! `docs/decisions/bus_vs_nats.md`.
//!
//! Run:  `cargo run --example bus_dispatch -p agent-mesh-bus`
//!
//! No broker, no config, no external services. Two `Bus` instances
//! in one process, same user fingerprint → auto-team trust →
//! request/reply round-trip.

use agent_mesh_bus::{Bus, Topic};
use agent_mesh_protocol::{AgentKey, AgentMetadata, Caveats, UserKey};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Serialize, Deserialize)]
struct TaskRequest {
    prompt: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct TaskReply {
    diff: String,
    model_id: String,
}

fn agent(user: &UserKey, role: &str) -> AgentKey {
    AgentKey::issue(
        user,
        AgentMetadata {
            role: role.into(),
            host: "localhost".into(),
            capabilities: vec!["dispatch-worker".into()],
            issued_at: "2026-05-28T00:00:00Z".into(),
            expires_at: None,
            caveats: Caveats::top(),
        },
    )
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .try_init()
        .ok();

    // Trust root: one user, two agents (auto-team).
    let user = UserKey::generate();
    let foreman = agent(&user, "dispatch-foreman");
    let worker = agent(&user, "dispatch-worker");
    let worker_fp = worker.fingerprint();

    let foreman_bus = Bus::bind(&user, foreman, 0).await?;
    let worker_bus = Bus::bind(&user, worker, 0).await?;

    let topic = Topic::new(user.fingerprint(), "dispatch/jobs");

    // Worker side: register a handler that "runs" the job.
    worker_bus.handle_requests(topic.clone(), |body| async move {
        let req: TaskRequest =
            serde_json::from_slice(&body).map_err(agent_mesh_bus::BusError::from)?;
        let reply = TaskReply {
            diff: format!("--- a/foo\n+++ b/bar\n@@ -1 +1 @@\n-{}\n+bar\n", req.prompt),
            model_id: "qwen2.5-coder:32b".to_string(),
        };
        serde_json::to_vec(&reply).map_err(agent_mesh_bus::BusError::from)
    });

    // Let mDNS settle.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let job = TaskRequest {
        prompt: "rename foo to bar".into(),
    };
    let body = serde_json::to_vec(&job)?;

    let reply_bytes = foreman_bus
        .request(worker_fp, &topic, body, Duration::from_secs(10))
        .await?;
    let reply: TaskReply = serde_json::from_slice(&reply_bytes)?;
    println!(
        "worker {}: replied with diff:\n{}",
        reply.model_id, reply.diff
    );

    foreman_bus.close().await?;
    worker_bus.close().await?;
    Ok(())
}
