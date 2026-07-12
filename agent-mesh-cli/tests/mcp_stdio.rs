//! End-to-end test of `amesh mcp` as a real subprocess over stdio —
//! the exact loop an MCP client (Claude Code, drake) drives. Recreates
//! the soak-test scenario from issue #23: keygen into a temp home, start
//! the MCP server, bring up a live echo responder, and round-trip a
//! `mesh_request` through the server — no scratch client crates.
//!
//! Two tiers (#52):
//!
//! - [`mcp_server_direct_addr_round_trips_to_live_responder`] names the
//!   responder by explicit `addr`+`pubkey`, so the whole path runs over
//!   **real QUIC on loopback with no multicast** — deterministic, gates
//!   every PR. This is the `amesh mcp` analogue of the bus's
//!   `request_reply_roundtrip_via_direct_dial_no_mdns`.
//! - [`mcp_server_round_trips_request_to_live_responder`] instead resolves
//!   the responder over **mDNS multicast** (`mesh_peers` discovery +
//!   `mesh_request`-by-fingerprint-prefix). Multicast is unreliable on
//!   hosted CI (the resolve never completes and the client's 20s
//!   `STEP_TIMEOUT` fires), so it is `#[ignore]`d — run on a real LAN with
//!   `cargo test -- --ignored`. What it uniquely exercises is the real
//!   multicast-discovery path.

use std::process::Stdio;
use std::time::Duration;

use agent_mesh_bus::{Bus, BusOptions, Topic};
use agent_mesh_protocol::{AgentKey, AgentMetadata, Caveats, UserKey};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

const STEP_TIMEOUT: Duration = Duration::from_secs(20);

struct McpClient {
    child: Child,
    stdin: ChildStdin,
    lines: Lines<BufReader<ChildStdout>>,
    next_id: u64,
}

impl McpClient {
    /// Spawn `amesh --home <home> mcp --quiet` with piped stdio.
    fn spawn(home: &std::path::Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_amesh"))
            .arg("--home")
            .arg(home)
            .arg("mcp")
            .arg("--quiet")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn amesh mcp");
        let stdin = child.stdin.take().expect("child stdin");
        let stdout = child.stdout.take().expect("child stdout");
        Self {
            child,
            stdin,
            lines: BufReader::new(stdout).lines(),
            next_id: 1,
        }
    }

    /// Send one request and await its response line.
    async fn call(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let req = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        let mut line = serde_json::to_string(&req).unwrap();
        line.push('\n');
        self.stdin.write_all(line.as_bytes()).await.unwrap();
        self.stdin.flush().await.unwrap();

        let resp_line = tokio::time::timeout(STEP_TIMEOUT, self.lines.next_line())
            .await
            .unwrap_or_else(|_| panic!("timeout waiting for response to {method}"))
            .expect("read line")
            .unwrap_or_else(|| panic!("server closed stdout during {method}"));
        let resp: Value = serde_json::from_str(&resp_line).expect("response is JSON");
        assert_eq!(resp["id"], id, "response id must match request");
        resp
    }

    /// Send a notification (no id, no response expected).
    async fn notify(&mut self, method: &str) {
        let req = json!({ "jsonrpc": "2.0", "method": method });
        let mut line = serde_json::to_string(&req).unwrap();
        line.push('\n');
        self.stdin.write_all(line.as_bytes()).await.unwrap();
        self.stdin.flush().await.unwrap();
    }

    /// Extract the text payload of a tools/call response.
    fn tool_text(resp: &Value) -> Value {
        let text = resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("no content text in {resp}"));
        serde_json::from_str(text).expect("tool text is JSON")
    }
}

fn echo_agent(user: &UserKey) -> AgentKey {
    AgentKey::issue(
        user,
        AgentMetadata {
            role: "echo-responder".into(),
            host: "test".into(),
            capabilities: vec!["echo".into()],
            issued_at: "2026-06-08T00:00:00Z".into(),
            expires_at: None,
            caveats: Caveats::top(),
        },
    )
}

/// Deterministic `amesh mcp` round-trip: the client names the responder by
/// explicit `addr`+`pubkey`, so the server dials it over **real QUIC on
/// loopback with no mDNS** (#52). No `mesh_peers`, no multicast — gates
/// every PR. The responder binds quiet (it's dialed directly, not
/// discovered).
#[tokio::test(flavor = "multi_thread")]
async fn mcp_server_direct_addr_round_trips_to_live_responder() {
    // 1. keygen into a private home.
    let home = tempfile::tempdir().unwrap();
    let status = Command::new(env!("CARGO_BIN_EXE_amesh"))
        .arg("--home")
        .arg(home.path())
        .arg("keygen")
        .status()
        .await
        .expect("run keygen");
    assert!(status.success(), "keygen must succeed");
    let user = UserKey::load(&home.path().join("user.key")).expect("load generated key");

    // 2. Start the MCP server (quiet bind) and complete the handshake.
    let mut client = McpClient::spawn(home.path());
    let init = client.call("initialize", json!({})).await;
    assert_eq!(init["result"]["serverInfo"]["name"], "amesh-mcp");
    client.notify("notifications/initialized").await;

    // 3. Bring up an echo responder. It never announces — the server
    //    reaches it by explicit (pubkey, addr), so bind quiet.
    let responder_agent = echo_agent(&user);
    let responder_fp = responder_agent.fingerprint();
    let responder_pubkey = responder_agent.public_bytes();
    let responder = Bus::bind_with(&user, responder_agent, 0, BusOptions { announce: false })
        .await
        .expect("bind responder");
    let responder_port = responder.local_port();
    let topic = Topic::new(user.fingerprint(), "echo/v1");
    responder.handle_requests(topic, |body| async move {
        let req: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        Ok(serde_json::to_vec(&json!({ "echo": req["msg"] })).unwrap())
    });
    // Only the handler registration needs a beat — there is no discovery.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 4. Round-trip via explicit addr+pubkey — no mesh_peers, no mDNS.
    let reply = client
        .call(
            "tools/call",
            json!({
                "name": "mesh_request",
                "arguments": {
                    "addr": format!("127.0.0.1:{responder_port}"),
                    "pubkey": hex::encode(responder_pubkey),
                    "topic": "echo/v1",
                    "body": { "msg": "hello direct" },
                    "timeout_secs": 10
                }
            }),
        )
        .await;
    let reply = McpClient::tool_text(&reply);
    assert_eq!(
        reply["reply"]["echo"], "hello direct",
        "echo must round-trip; got {reply}"
    );
    // The reported peer is derived from the pubkey, matching the responder.
    assert_eq!(reply["peer"].as_str().unwrap(), responder_fp.hex());

    // 5. Closing stdin shuts the server down cleanly.
    drop(client.stdin);
    let status = tokio::time::timeout(STEP_TIMEOUT, client.child.wait())
        .await
        .expect("server must exit after stdin closes")
        .expect("wait");
    assert!(status.success(), "clean exit, got {status:?}");
    responder.close().await.expect("close responder");
}

/// Deterministic `mesh_publish` fan-out: `amesh mcp` publishes a body to a
/// quiet-bound in-process subscriber `Bus` by explicit `addr`+`pubkey` over
/// real QUIC on loopback (no mDNS), and the subscriber's topic
/// `broadcast::Receiver` receives it (#56). Fire-and-forget — no reply,
/// unlike the request round-trip above.
#[tokio::test(flavor = "multi_thread")]
async fn mcp_server_direct_addr_publishes_to_subscriber() {
    // 1. keygen + start the MCP server + handshake.
    let home = tempfile::tempdir().unwrap();
    let status = Command::new(env!("CARGO_BIN_EXE_amesh"))
        .arg("--home")
        .arg(home.path())
        .arg("keygen")
        .status()
        .await
        .expect("run keygen");
    assert!(status.success(), "keygen must succeed");
    let user = UserKey::load(&home.path().join("user.key")).expect("load generated key");

    let mut client = McpClient::spawn(home.path());
    let init = client.call("initialize", json!({})).await;
    assert_eq!(init["result"]["serverInfo"]["name"], "amesh-mcp");
    client.notify("notifications/initialized").await;

    // 2. Bring up a quiet-bound subscriber and subscribe BEFORE publishing
    //    so the broadcast channel exists to buffer the message.
    let subscriber_agent = echo_agent(&user);
    let subscriber_pubkey = subscriber_agent.public_bytes();
    let subscriber = Bus::bind_with(&user, subscriber_agent, 0, BusOptions { announce: false })
        .await
        .expect("bind subscriber");
    let subscriber_port = subscriber.local_port();
    let topic = Topic::new(user.fingerprint(), "notes/v1");
    let mut sub_rx = subscriber.subscribe(&topic).await;

    // 3. Publish via explicit addr+pubkey — no mesh_peers, no mDNS.
    let publish = client
        .call(
            "tools/call",
            json!({
                "name": "mesh_publish",
                "arguments": {
                    "addr": format!("127.0.0.1:{subscriber_port}"),
                    "pubkey": hex::encode(subscriber_pubkey),
                    "topic": "notes/v1",
                    "body": { "note": "hello sub" }
                }
            }),
        )
        .await;
    let publish = McpClient::tool_text(&publish);
    assert_eq!(publish["published"], true, "publish ack; got {publish}");
    assert_eq!(publish["topic"], "notes/v1");

    // 4. The subscriber's broadcast receiver gets the published body.
    let got = tokio::time::timeout(STEP_TIMEOUT, sub_rx.recv())
        .await
        .expect("subscriber must receive the publish before timeout")
        .expect("broadcast recv");
    let got: Value = serde_json::from_slice(&got).expect("published body is JSON");
    assert_eq!(got, json!({ "note": "hello sub" }));

    // 5. Clean shutdown.
    drop(client.stdin);
    let status = tokio::time::timeout(STEP_TIMEOUT, client.child.wait())
        .await
        .expect("server must exit after stdin closes")
        .expect("wait");
    assert!(status.success(), "clean exit, got {status:?}");
    subscriber.close().await.expect("close subscriber");
}

// Real mDNS multicast discovery (steps 5–6 resolve the responder by
// fingerprint over multicast); flaky on hosted CI. See the module doc.
// The deterministic per-PR coverage of the same round-trip is
// `mcp_server_direct_addr_round_trips_to_live_responder` above.
#[ignore = "real mDNS multicast discovery (amesh mcp resolves the responder by fingerprint); flaky on hosted CI. Run with --ignored on a real LAN."]
#[tokio::test(flavor = "multi_thread")]
async fn mcp_server_round_trips_request_to_live_responder() {
    // 1. keygen into a private home (the same `--home` flow real
    //    usage takes — no hardcoded key paths anywhere).
    let home = tempfile::tempdir().unwrap();
    let status = Command::new(env!("CARGO_BIN_EXE_amesh"))
        .arg("--home")
        .arg(home.path())
        .arg("keygen")
        .status()
        .await
        .expect("run keygen");
    assert!(status.success(), "keygen must succeed");
    let user = UserKey::load(&home.path().join("user.key")).expect("load generated key");

    // 2. Start the MCP server (quiet bind: replies reach it via the
    //    bus dial-back path only).
    let mut client = McpClient::spawn(home.path());

    // 3. MCP handshake.
    let init = client.call("initialize", json!({})).await;
    assert_eq!(init["result"]["serverInfo"]["name"], "amesh-mcp");
    assert_eq!(init["result"]["protocolVersion"], "2024-11-05");
    client.notify("notifications/initialized").await;

    let tools = client.call("tools/list", json!({})).await;
    let names: Vec<&str> = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        vec!["mesh_whoami", "mesh_peers", "mesh_request", "mesh_publish"]
    );

    let whoami = client
        .call(
            "tools/call",
            json!({ "name": "mesh_whoami", "arguments": {} }),
        )
        .await;
    let whoami = McpClient::tool_text(&whoami);
    assert_eq!(
        whoami["user_fp"].as_str().unwrap(),
        user.fingerprint().hex()
    );
    assert_eq!(whoami["announce"], false);

    // 4. Bring up a live echo responder under the same user key —
    //    it announces, so the server's resolver can discover it.
    let responder_agent = echo_agent(&user);
    let responder_fp = responder_agent.fingerprint();
    let responder = Bus::bind(&user, responder_agent, 0)
        .await
        .expect("bind responder");
    let topic = Topic::new(user.fingerprint(), "echo/v1");
    responder.handle_requests(topic, |body| async move {
        let req: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        Ok(serde_json::to_vec(&json!({ "echo": req["msg"] })).unwrap())
    });

    // 5. The responder must show up in mesh_peers (give mDNS a beat).
    let peers = client
        .call(
            "tools/call",
            json!({ "name": "mesh_peers", "arguments": { "listen_secs": 2, "same_user_only": true } }),
        )
        .await;
    let peers = McpClient::tool_text(&peers);
    let listed: Vec<&str> = peers["peers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["agent_fp"].as_str().unwrap())
        .collect();
    assert!(
        listed.contains(&responder_fp.hex().as_str()),
        "responder {} must be discovered; got {listed:?}",
        responder_fp.short()
    );

    // 6. Round-trip a request through the MCP server using a PREFIX
    //    of the responder's fingerprint (exercises discovery-backed
    //    resolution, not just hex parsing).
    let prefix = &responder_fp.hex()[..12];
    let reply = client
        .call(
            "tools/call",
            json!({
                "name": "mesh_request",
                "arguments": {
                    "peer": prefix,
                    "topic": "echo/v1",
                    "body": { "msg": "hello from mcp" },
                    "timeout_secs": 10
                }
            }),
        )
        .await;
    let reply = McpClient::tool_text(&reply);
    assert_eq!(
        reply["reply"]["echo"], "hello from mcp",
        "echo must round-trip; got {reply}"
    );
    assert_eq!(reply["peer"].as_str().unwrap(), responder_fp.hex());

    // 7. Closing stdin shuts the server down cleanly.
    drop(client.stdin);
    let status = tokio::time::timeout(STEP_TIMEOUT, client.child.wait())
        .await
        .expect("server must exit after stdin closes")
        .expect("wait");
    assert!(status.success(), "clean exit, got {status:?}");

    responder.close().await.expect("close responder");
}
