//! `flock_*` MCP tools: the same session, the same reads and the same single
//! `Emit` the `amesh flock` commands use. The session socket is fixed when the
//! server starts and is never a tool argument; the tools hold no key and make
//! no policy check, so a refusal is admission's, returned as the tool error.

use super::discover::Where;
use super::{emit, read};
use agent_mesh_flock::{Body, Kind};
use anyhow::{anyhow, Context, Result};
use content_addressable::ContentId;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The flock tools of one `amesh mcp` process.
pub struct FlockTools {
    home: PathBuf,
    at: Where,
}

impl FlockTools {
    /// Bind to `socket`. The flock is the one whose directory holds the
    /// socket (`<dir>/run/session-*.sock`) and the session must belong to it,
    /// so this is 7a's destination binding, checked now and on every call.
    pub fn new(home: PathBuf, socket: &Path) -> Result<Self> {
        let dir = socket
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| anyhow!("{} is not <flock>/run/<socket>", socket.display()))?;
        let at = Where {
            dir: Some(dir.to_owned()),
            name: None,
            session: Some(socket.to_owned()),
        };
        at.session(&home)
            .with_context(|| format!("flock session {}", socket.display()))?;

        Ok(Self { home, at })
    }

    pub fn definitions() -> Vec<Value> {
        vec![
            json!({
                "name": "flock_whoami",
                "description": "Who this flock session is: flock id, roster member, session id and its state in the log.",
                "inputSchema": { "type": "object", "properties": {} }
            }),
            json!({
                "name": "flock_inbox",
                "description": "Briefs and reviews addressed to this session's member that are still open.",
                "inputSchema": { "type": "object", "properties": {} }
            }),
            json!({
                "name": "flock_status",
                "description": "Every lane in the flock and where it stands.",
                "inputSchema": { "type": "object", "properties": {} }
            }),
            json!({
                "name": "flock_emit",
                "description": "Send one event as this session's member. The session signs it; the server's admission decides, and a refusal comes back as the error. `kind` is the kebab-case event kind (e.g. `ack`, `result`), `refs` maps a role to a content id (e.g. {\"of\": \"bafy...\"}), `body` is the event body as JSON (e.g. \"ack\" for an ack, or {\"result\": {\"outcome\": \"completed\"}}).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "kind": { "type": "string" },
                        "refs": { "type": "object", "additionalProperties": { "type": "string" } },
                        "body": { "type": ["string", "object"] }
                    },
                    "required": ["kind", "body"]
                }
            }),
        ]
    }

    /// `None` when `name` is not a flock tool.
    pub fn call(&self, name: &str, args: &Value) -> Option<Result<String>> {
        if !matches!(
            name,
            "flock_whoami" | "flock_inbox" | "flock_status" | "flock_emit"
        ) {
            return None;
        }
        // The one guard every flock tool passes: the bound socket must still be
        // a live session of the flock it was started for, on every call.
        if let Err(e) = self.at.session(&self.home) {
            return Some(Err(e));
        }
        Some(match name {
            "flock_whoami" => emit::whoami(&self.home, &self.at).map(|(_, t)| t),
            "flock_inbox" => read::inbox_text(&self.home, &self.at),
            "flock_status" => read::status_text(&self.home, &self.at),
            "flock_emit" => self.emit(args),
            _ => return None,
        })
    }

    fn emit(&self, args: &Value) -> Result<String> {
        let kind: Kind = serde_json::from_value(args.get("kind").cloned().unwrap_or(Value::Null))
            .context("`kind` is not an event kind")?;
        let refs: BTreeMap<String, ContentId> = match args.get("refs") {
            // optional means absent (or {}): the schema says object, so null is not "none"
            None => BTreeMap::new(),
            Some(r) => serde_json::from_value(r.clone()).context("`refs` is not role -> cid")?,
        };
        let body: Body = serde_json::from_value(args.get("body").cloned().unwrap_or(Value::Null))
            .context("`body` is not an event body")?;
        emit::send(&self.home, &self.at, kind, refs, body)
    }
}
