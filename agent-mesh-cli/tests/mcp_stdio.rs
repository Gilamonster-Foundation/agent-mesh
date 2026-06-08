//! End-to-end test of `amesh mcp` as a real subprocess over stdio —
//! the exact loop an MCP client (Claude Code, drake) drives.
//!
//! Recreates the soak-test scenario from issue #23 deterministically:
//! keygen into a temp home, start the MCP server, discover a live
//! echo responder over mDNS, and round-trip a `mesh_request` through
//! the server — no scratch client crates, no external services.

use std::process::Stdio;
use std::time::Duration;

use agent_mesh_bus::{Bus, Topic};
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
    assert_eq!(names, vec!["mesh_whoami", "mesh_peers", "mesh_request"]);

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
