//! Phase-3 gate-1 reference: dispatch foreman over async-nats.
//!
//! Companion to `examples/bus_dispatch.rs`. Same scenario, same wire
//! types, different transport. Referenced by
//! `docs/decisions/bus_vs_nats.md`.
//!
//! Compile-check only in CI (`cargo build --example nats_dispatch -p
//! agent-mesh-bus`). Actually running it requires a `nats-server`
//! on `127.0.0.1:4222`:
//!
//! ```text
//! nats-server &
//! cargo run --example nats_dispatch -p agent-mesh-bus
//! ```
//!
//! The contrast with the bus example IS the comparison: the bus
//! example needs zero external services to run end-to-end; this one
//! silently assumes a running broker (and, in production, NKey/JWT
//! credentials, subject permissions, monitoring, TLS, ...).

use anyhow::Result;
use async_nats::Subscriber;
use bytes::Bytes;
use futures::StreamExt;
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

const SUBJECT: &str = "dispatch.foreman.jobs";

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .try_init()
        .ok();

    let client = async_nats::connect("nats://127.0.0.1:4222").await?;

    // Worker side: subscribe, reply to each request.
    let worker_client = client.clone();
    let worker = tokio::spawn(async move {
        let mut sub: Subscriber = worker_client.subscribe(SUBJECT).await?;
        if let Some(msg) = sub.next().await {
            let req: TaskRequest = serde_json::from_slice(&msg.payload)?;
            let reply = TaskReply {
                diff: format!("--- a/foo\n+++ b/bar\n@@ -1 +1 @@\n-{}\n+bar\n", req.prompt),
                model_id: "qwen2.5-coder:32b".into(),
            };
            if let Some(reply_to) = msg.reply {
                worker_client
                    .publish(reply_to, Bytes::from(serde_json::to_vec(&reply)?))
                    .await?;
            }
        }
        Ok::<_, anyhow::Error>(())
    });

    // Let the subscription settle on the broker.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let job = TaskRequest {
        prompt: "rename foo to bar".into(),
    };
    let body = Bytes::from(serde_json::to_vec(&job)?);
    let msg = client.request(SUBJECT, body).await?;
    let reply: TaskReply = serde_json::from_slice(&msg.payload)?;
    println!(
        "worker {}: replied with diff:\n{}",
        reply.model_id, reply.diff
    );

    worker.await??;
    Ok(())
}
