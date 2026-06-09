//! `amesh mcp` — stdio MCP server exposing the mesh as tool calls.
//!
//! Lets any MCP-capable agent (Claude Code, drake, codex workers) drive
//! the mesh interactively without writing bus client code (issue #23 —
//! born from a soak test where conversing with a newt responder
//! required scaffolding a throwaway Rust crate).
//!
//! One [`Bus`] and one [`PeerResolver`] live for the server's lifetime:
//!
//! * `mesh_whoami`  — local identity, bound port, announce state
//! * `mesh_peers`   — mDNS-discovered peers
//! * `mesh_request` — request/reply to a peer on a topic, body verbatim
//!
//! Protocol-pure: `mesh_request` carries topic + body untouched, so the
//! payload schema (e.g. newt's `InferenceRequest`) stays the client's
//! knowledge. Wire framing is newline-delimited JSON-RPC 2.0 matching
//! the MCP stdio transport; `--quiet` binds without announcing
//! (replies still arrive via the bus's dial-back path).

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use agent_mesh_bus::{Bus, BusOptions, Topic};
use agent_mesh_protocol::{AgentKey, AgentMetadata, Caveats, Fingerprint, UserKey};
use agent_mesh_transport::{PeerResolver, ResolverHandle};
use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::util;

/// Shared state behind every tool handler.
struct McpState {
    bus: Bus,
    resolver: PeerResolver,
    announce: bool,
    /// Keeps the resolver's mDNS browser thread alive.
    _resolver_handle: ResolverHandle,
}

/// Run the `mcp` subcommand: bind the bus, then serve MCP over stdio
/// until the client closes stdin.
pub async fn run(home: PathBuf, quiet: bool) -> Result<()> {
    let key_path = home.join("user.key");
    let user = UserKey::load(&key_path)
        .with_context(|| format!("load {} — run `amesh keygen` first", key_path.display()))?;

    let agent = AgentKey::issue(
        &user,
        AgentMetadata {
            role: "amesh-mcp".into(),
            host: util::current_hostname(),
            capabilities: vec!["amesh-mcp".into()],
            issued_at: util::now_rfc3339(),
            expires_at: None,
            caveats: Caveats::top(),
        },
    );

    let announce = !quiet;
    let bus = Bus::bind_with(&user, agent, 0, BusOptions { announce }).await?;
    let (resolver, resolver_handle) = PeerResolver::start()?;

    // Handshake/progress chatter goes to stderr: stdout is the
    // JSON-RPC channel and must stay pure.
    eprintln!(
        "amesh mcp: bus bound (agent {}, port {}, announce {announce}) — serving stdio",
        bus.agent_fingerprint().short(),
        bus.local_port(),
    );

    let state = Arc::new(McpState {
        bus,
        resolver,
        announce,
        _resolver_handle: resolver_handle,
    });
    serve(state, tokio::io::stdin(), tokio::io::stdout()).await
}

/// Read newline-delimited JSON-RPC from `reader`, dispatch, write
/// responses to `writer`. Notifications (no `id`) get no response,
/// per JSON-RPC 2.0.
async fn serve<R, W>(state: Arc<McpState>, reader: R, mut writer: W) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut lines = BufReader::new(reader).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let request: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let resp = json!({
                    "jsonrpc": "2.0", "id": null,
                    "error": { "code": -32700, "message": format!("Parse error: {e}") }
                });
                write_line(&mut writer, &resp).await?;
                continue;
            }
        };
        let is_notification = request.get("id").is_none();
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = request.get("params").cloned().unwrap_or(Value::Null);

        let outcome = handle_request(&state, method, params).await;
        if is_notification {
            continue;
        }
        let response = match outcome {
            Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
            Err(e) => json!({
                "jsonrpc": "2.0", "id": id,
                "error": { "code": e.code, "message": e.message }
            }),
        };
        write_line(&mut writer, &response).await?;
    }
    Ok(())
}

async fn write_line<W: tokio::io::AsyncWrite + Unpin>(writer: &mut W, value: &Value) -> Result<()> {
    let mut out = serde_json::to_string(value)?;
    out.push('\n');
    writer.write_all(out.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

/// JSON-RPC error with a protocol code.
#[derive(Debug)]
struct RpcError {
    code: i64,
    message: String,
}

impl RpcError {
    fn method_not_found(method: &str) -> Self {
        Self {
            code: -32601,
            message: format!("Method not found: {method}"),
        }
    }
    fn invalid_params(message: impl Into<String>) -> Self {
        Self {
            code: -32602,
            message: message.into(),
        }
    }
    fn internal(err: anyhow::Error) -> Self {
        Self {
            code: -32603,
            message: err.to_string(),
        }
    }
}

/// Dispatch one JSON-RPC method. Factored out of the stdio loop so
/// tests can drive it directly.
async fn handle_request(
    state: &McpState,
    method: &str,
    params: Value,
) -> std::result::Result<Value, RpcError> {
    match method {
        "initialize" => Ok(json!({
            "protocolVersion": "2024-11-05",
            "capabilities": { "tools": {} },
            "serverInfo": {
                "name": "amesh-mcp",
                "version": env!("CARGO_PKG_VERSION"),
            }
        })),
        // Sent by clients after `initialize`; nothing to do.
        "notifications/initialized" => Ok(Value::Null),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tool_definitions() })),
        "tools/call" => {
            let name = params
                .get("name")
                .and_then(|n| n.as_str())
                .ok_or_else(|| RpcError::invalid_params("tools/call needs a `name`"))?;
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let text = match name {
                "mesh_whoami" => tool_whoami(state),
                "mesh_peers" => tool_peers(state, &args).await,
                "mesh_request" => tool_request(state, &args).await,
                other => Err(anyhow!("unknown tool: {other}")),
            }
            .map_err(RpcError::internal)?;
            Ok(json!({ "content": [{ "type": "text", "text": text }] }))
        }
        other => Err(RpcError::method_not_found(other)),
    }
}

/// The MCP tool catalogue (shared by `tools/list`).
fn tool_definitions() -> Value {
    json!([
        {
            "name": "mesh_whoami",
            "description": "Local agent-mesh identity: user/agent fingerprints, bound UDP port, announce state.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "mesh_peers",
            "description": "List peers discovered on the LAN via mDNS. Peers under the same user fingerprint are the ones requests can reach.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "listen_secs": {
                        "type": "number",
                        "description": "Extra seconds to let discovery settle before listing (default 2)."
                    },
                    "same_user_only": {
                        "type": "boolean",
                        "description": "Only list peers under our own user fingerprint (default false)."
                    }
                }
            }
        },
        {
            "name": "mesh_request",
            "description": "Send a request to a peer on a topic and wait for the reply. The body is forwarded verbatim — e.g. for a newt responder use topic `newt/inference/v1` with body {\"prompt\": ..., \"tier\": null, \"model\": null, \"max_tokens\": ...}.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "peer": {
                        "type": "string",
                        "description": "Peer agent fingerprint — 64-char hex, or a unique prefix of a discovered peer."
                    },
                    "topic": {
                        "type": "string",
                        "description": "Topic name (namespaced under our user fingerprint), e.g. `newt/inference/v1`."
                    },
                    "body": {
                        "description": "Request payload — JSON object (sent as-is) or string (sent as UTF-8)."
                    },
                    "timeout_secs": {
                        "type": "number",
                        "description": "How long to wait for the reply (default 30)."
                    }
                },
                "required": ["peer", "topic", "body"]
            }
        }
    ])
}

fn tool_whoami(state: &McpState) -> Result<String> {
    let user_fp = state.bus.user_fingerprint();
    let agent_fp = state.bus.agent_fingerprint();
    let out = json!({
        "user_fp": user_fp.hex(),
        "user_short": user_fp.short(),
        "agent_fp": agent_fp.hex(),
        "agent_short": agent_fp.short(),
        "port": state.bus.local_port(),
        "announce": state.announce,
    });
    Ok(serde_json::to_string_pretty(&out)?)
}

async fn tool_peers(state: &McpState, args: &Value) -> Result<String> {
    let listen_secs = args
        .get("listen_secs")
        .and_then(Value::as_f64)
        .unwrap_or(2.0);
    let same_user_only = args
        .get("same_user_only")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    // The resolver accumulates from server start; this wait only
    // matters for the first call after startup.
    tokio::time::sleep(Duration::from_secs_f64(listen_secs.clamp(0.0, 30.0))).await;

    let our_user = state.bus.user_fingerprint();
    let our_agent = state.bus.agent_fingerprint();
    let peers: Vec<Value> = state
        .resolver
        .known()
        .await
        .into_iter()
        .filter(|p| p.agent_fp != our_agent)
        .filter(|p| !same_user_only || p.user_fp == our_user)
        .map(|p| {
            json!({
                "agent_fp": p.agent_fp.hex(),
                "short": p.agent_fp.short(),
                "same_user": p.user_fp == our_user,
                "role": p.role,
                "host": p.host,
                "capabilities": p.capabilities,
                "addrs": p.addrs.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "port": p.port,
            })
        })
        .collect();
    Ok(serde_json::to_string_pretty(&json!({ "peers": peers }))?)
}

async fn tool_request(state: &McpState, args: &Value) -> Result<String> {
    let peer_arg = args
        .get("peer")
        .and_then(|p| p.as_str())
        .ok_or_else(|| anyhow!("mesh_request needs `peer`"))?;
    let topic_name = args
        .get("topic")
        .and_then(|t| t.as_str())
        .ok_or_else(|| anyhow!("mesh_request needs `topic`"))?;
    let body_val = args
        .get("body")
        .ok_or_else(|| anyhow!("mesh_request needs `body`"))?;
    let timeout_secs = args
        .get("timeout_secs")
        .and_then(Value::as_f64)
        .unwrap_or(30.0)
        .clamp(0.1, 600.0);

    let body = match body_val {
        Value::String(s) => s.clone().into_bytes(),
        other => serde_json::to_vec(other)?,
    };

    let peer_fp = resolve_peer(state, peer_arg).await?;
    let topic = Topic::new(state.bus.user_fingerprint(), topic_name);

    let started = std::time::Instant::now();
    let reply_bytes = state
        .bus
        .request(peer_fp, &topic, body, Duration::from_secs_f64(timeout_secs))
        .await?;
    let elapsed_ms = started.elapsed().as_millis() as u64;

    // Surface JSON replies as JSON; anything else as lossy UTF-8.
    let reply: Value = serde_json::from_slice(&reply_bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&reply_bytes).into_owned()));
    Ok(serde_json::to_string_pretty(&json!({
        "peer": peer_fp.hex(),
        "elapsed_ms": elapsed_ms,
        "reply": reply,
    }))?)
}

/// Resolve a peer argument: full 64-char hex parses directly; anything
/// shorter must be a unique prefix of a discovered peer's fingerprint.
async fn resolve_peer(state: &McpState, arg: &str) -> Result<Fingerprint> {
    if let Ok(fp) = Fingerprint::from_str(arg) {
        return Ok(fp);
    }
    let known = state.resolver.known().await;
    let candidates: Vec<Fingerprint> = known
        .iter()
        .map(|p| p.agent_fp)
        .filter(|fp| fp.hex().starts_with(arg))
        .collect();
    match candidates.as_slice() {
        [fp] => Ok(*fp),
        [] => Err(anyhow!(
            "peer `{arg}` is not a full fingerprint and matches no discovered peer \
             ({} known) — try `mesh_peers` first",
            known.len()
        )),
        many => Err(anyhow!(
            "peer prefix `{arg}` is ambiguous: {}",
            many.iter()
                .map(|fp| fp.short())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn quiet_state() -> McpState {
        let user = UserKey::generate();
        let agent = AgentKey::issue(
            &user,
            AgentMetadata {
                role: "amesh-mcp-test".into(),
                host: "test".into(),
                capabilities: vec!["amesh-mcp".into()],
                issued_at: "2026-06-08T00:00:00Z".into(),
                expires_at: None,
                caveats: Caveats::top(),
            },
        );
        let bus = Bus::bind_with(&user, agent, 0, BusOptions { announce: false })
            .await
            .expect("bind");
        let (resolver, resolver_handle) = PeerResolver::start().expect("resolver");
        McpState {
            bus,
            resolver,
            announce: false,
            _resolver_handle: resolver_handle,
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn initialize_reports_server_info() {
        let state = quiet_state().await;
        let out = handle_request(&state, "initialize", Value::Null)
            .await
            .unwrap();
        assert_eq!(out["protocolVersion"], "2024-11-05");
        assert_eq!(out["serverInfo"]["name"], "amesh-mcp");
        assert!(out["capabilities"]["tools"].is_object());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn tools_list_names_all_three_tools() {
        let state = quiet_state().await;
        let out = handle_request(&state, "tools/list", Value::Null)
            .await
            .unwrap();
        let names: Vec<&str> = out["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["mesh_whoami", "mesh_peers", "mesh_request"]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unknown_method_is_32601_and_unknown_tool_is_32603() {
        let state = quiet_state().await;
        let err = handle_request(&state, "no/such/method", Value::Null)
            .await
            .err()
            .unwrap();
        assert_eq!(err.code, -32601);

        let err = handle_request(
            &state,
            "tools/call",
            json!({ "name": "no_such_tool", "arguments": {} }),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(err.code, -32603);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn tools_call_without_name_is_invalid_params() {
        let state = quiet_state().await;
        let err = handle_request(&state, "tools/call", json!({}))
            .await
            .err()
            .unwrap();
        assert_eq!(err.code, -32602);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn whoami_reports_identity_and_quiet_bind() {
        let state = quiet_state().await;
        let out = handle_request(
            &state,
            "tools/call",
            json!({ "name": "mesh_whoami", "arguments": {} }),
        )
        .await
        .unwrap();
        let text = out["content"][0]["text"].as_str().unwrap();
        let parsed: Value = serde_json::from_str(text).unwrap();
        assert_eq!(parsed["agent_fp"], state.bus.agent_fingerprint().hex());
        assert_eq!(parsed["announce"], false);
        assert!(parsed["port"].as_u64().unwrap() > 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn peers_listen_secs_is_clamped_and_returns_array() {
        let state = quiet_state().await;
        let out = handle_request(
            &state,
            "tools/call",
            json!({ "name": "mesh_peers", "arguments": { "listen_secs": 0.0 } }),
        )
        .await
        .unwrap();
        let text = out["content"][0]["text"].as_str().unwrap();
        let parsed: Value = serde_json::from_str(text).unwrap();
        assert!(parsed["peers"].is_array());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn request_to_unknown_prefix_suggests_mesh_peers() {
        let state = quiet_state().await;
        let err = handle_request(
            &state,
            "tools/call",
            json!({
                "name": "mesh_request",
                "arguments": { "peer": "deadbeef", "topic": "t", "body": "x" }
            }),
        )
        .await
        .err()
        .unwrap();
        assert!(err.message.contains("mesh_peers"), "got: {}", err.message);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn notifications_get_no_response_and_requests_do() {
        let state = Arc::new(quiet_state().await);
        let input = concat!(
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":7,"method":"ping"}"#,
            "\n",
        );
        let mut output: Vec<u8> = Vec::new();
        serve(state, input.as_bytes(), &mut output).await.unwrap();
        let lines: Vec<&str> = std::str::from_utf8(&output).unwrap().lines().collect();
        // Exactly one response: the ping. The notification was silent.
        assert_eq!(lines.len(), 1, "got: {lines:?}");
        let resp: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(resp["id"], 7);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn malformed_json_line_yields_parse_error() {
        let state = Arc::new(quiet_state().await);
        let mut output: Vec<u8> = Vec::new();
        serve(state, "{{{nope\n".as_bytes(), &mut output)
            .await
            .unwrap();
        let resp: Value =
            serde_json::from_str(std::str::from_utf8(&output).unwrap().trim()).unwrap();
        assert_eq!(resp["error"]["code"], -32700);
    }
}
