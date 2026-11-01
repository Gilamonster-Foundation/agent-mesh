//! The `flock_*` MCP tools through `amesh mcp` over stdio, against a live
//! `serve` and live sessions. The tools sign nothing and check nothing: the
//! session signs, admission decides, and a refusal is the tool's error.
#![cfg(unix)]

mod revocation_log;

use agent_mesh_flock::{Body, EndReason, HandoffApproval};
use agent_mesh_protocol::{AgentKey, AgentMetadata, Assertion, Caveats, UserKey};
use assert_cmd::cargo::cargo_bin;
use content_addressable::{ContentAddressable as _, ContentId, MerkleNode, RawContentId};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Output, Stdio};
use tempfile::TempDir;

struct Proc(Child);
impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn amesh(home: &Path) -> Command {
    let mut c = Command::new(cargo_bin("amesh"));
    c.arg("--home").arg(home).env_remove("AMESH_FLOCK_SESSION");
    c
}

struct Flock {
    home: TempDir,
    dir: PathBuf,
    _serve: Proc,
}

fn flock() -> Flock {
    let home = TempDir::new().unwrap();
    assert!(amesh(home.path()).arg("keygen").status().unwrap().success());
    revocation_log::ensure_log(home.path());
    let mut init = amesh(home.path());
    init.args(["flock", "init", "--name", "f"]);
    for m in ["shep:shepherd", "h1:helper", "h2:helper"] {
        init.args(["--member", m]);
    }
    assert!(init.stdout(Stdio::null()).status().unwrap().success());
    let dir = home.path().join("flocks").join("f");
    let mut serve = amesh(home.path())
        .args(["flock", "serve", "--dir"])
        .arg(&dir)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(serve.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert!(line.starts_with("serving"), "{line}");
    Flock {
        home,
        dir,
        _serve: Proc(serve),
    }
}

struct Sess {
    _proc: Proc,
    sock: PathBuf,
}

impl Flock {
    fn session(&self, member: &str) -> Sess {
        let inv = amesh(self.home.path())
            .args(["flock", "invite", "--dir"])
            .arg(&self.dir)
            .arg(member)
            .output()
            .unwrap();
        assert!(inv.status.success());
        let token = String::from_utf8(inv.stdout).unwrap().trim().to_owned();
        let mut child = amesh(self.home.path())
            .args(["flock", "session", "--dir"])
            .arg(&self.dir)
            .args(["--member", member])
            .env("AMESH_FLOCK_TOKEN", token)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut out = BufReader::new(child.stdout.take().unwrap());
        let (mut id, mut sock) = (String::new(), String::new());
        out.read_line(&mut id).unwrap();
        out.read_line(&mut sock).unwrap();
        Sess {
            _proc: Proc(child),
            sock: sock.trim().strip_prefix("socket: ").unwrap().into(),
        }
    }

    /// `amesh flock <args>` as the given session.
    fn cli(&self, s: &Sess, args: &[&str]) -> Output {
        let mut c = amesh(self.home.path());
        c.arg("flock").arg(args[0]);
        c.arg("--dir").arg(&self.dir).arg("--session").arg(&s.sock);
        c.args(&args[1..]).output().unwrap()
    }

    fn log(&self, s: &Sess) -> String {
        let o = self.cli(s, &["log"]);
        assert!(o.status.success());
        String::from_utf8(o.stdout).unwrap()
    }

    /// An `amesh mcp` process for `s` (or none).
    fn mcp(&self, s: Option<&Sess>) -> Mcp {
        let mut c = amesh(self.home.path());
        c.args(["mcp", "--quiet"]);
        if let Some(s) = s {
            c.arg("--flock-session").arg(&s.sock);
        }
        let mut child = c
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        Mcp {
            stdin: child.stdin.take().unwrap(),
            out: BufReader::new(child.stdout.take().unwrap()),
            _proc: Proc(child),
            id: 0,
        }
    }
}

struct Mcp {
    _proc: Proc,
    stdin: ChildStdin,
    out: BufReader<ChildStdout>,
    id: u64,
}

impl Mcp {
    fn rpc(&mut self, method: &str, params: Value) -> Value {
        self.id += 1;
        let req = json!({"jsonrpc": "2.0", "id": self.id, "method": method, "params": params});
        writeln!(self.stdin, "{req}").unwrap();
        self.stdin.flush().unwrap();
        let mut line = String::new();
        self.out.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("{e}: {line:?}"))
    }

    /// `tools/call`: the text of a success, or the error message.
    fn tool(&mut self, name: &str, args: Value) -> Result<String, String> {
        let r = self.rpc("tools/call", json!({"name": name, "arguments": args}));
        match r.get("error") {
            Some(e) => Err(e["message"].as_str().unwrap().to_owned()),
            None => Ok(r["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .to_owned()),
        }
    }

    /// The `inputSchema` a client would honour for `name`.
    fn schema(&mut self, name: &str) -> Value {
        let r = self.rpc("tools/list", json!({}));
        r["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == name)
            .unwrap_or_else(|| panic!("{name} not listed"))["inputSchema"]
            .clone()
    }

    fn tool_names(&mut self) -> Vec<String> {
        let r = self.rpc("tools/list", json!({}));
        r["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_owned())
            .collect()
    }
}

fn admitted_cid(text: &str) -> String {
    text.split_whitespace().nth(1).unwrap().to_owned()
}

#[test]
fn the_flock_tools_exist_only_when_started_with_a_session() {
    let f = flock();
    let mut bare = f.mcp(None);
    let names = bare.tool_names();
    assert!(names.iter().all(|n| !n.starts_with("flock_")), "{names:?}");
    let err = bare.tool("flock_emit", json!({"kind": "ack", "body": "ack"}));
    assert!(err.unwrap_err().contains("unknown tool"));

    let h1 = f.session("h1");
    let mut with = f.mcp(Some(&h1));
    let names = with.tool_names();
    for t in ["flock_whoami", "flock_inbox", "flock_status", "flock_emit"] {
        assert!(names.iter().any(|n| n == t), "{t} in {names:?}");
    }
    assert!(
        names.iter().any(|n| n == "mesh_whoami"),
        "the mesh tools stay"
    );
}

#[test]
fn a_socket_that_is_not_a_live_session_stops_the_server_at_startup() {
    let f = flock();
    let bogus = f.dir.join("run").join("session-nope.sock");
    let o = amesh(f.home.path())
        .args(["mcp", "--quiet", "--flock-session"])
        .arg(&bogus)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!o.status.success());
}

#[test]
fn the_addressee_acks_through_the_tool_and_a_non_addressee_is_refused() {
    let f = flock();
    let (shep, h1, h2) = (f.session("shep"), f.session("h1"), f.session("h2"));
    let o = f.cli(&shep, &["brief", "--to", "h1", "--lane", "l1"]);
    assert!(o.status.success());
    let brief = admitted_cid(&String::from_utf8(o.stdout).unwrap());

    let mut m1 = f.mcp(Some(&h1));
    let who = m1.tool("flock_whoami", json!({})).unwrap();
    assert!(who.contains("member:  h1"), "{who}");
    let inbox = m1.tool("flock_inbox", json!({})).unwrap();
    assert!(
        inbox.contains(&brief) && !inbox.contains("epoch"),
        "{inbox}"
    );
    let status = m1.tool("flock_status", json!({})).unwrap();
    assert!(
        status.contains("epoch") && status.contains("l1"),
        "{status}"
    );

    // the forger first: h2 was not addressed
    let before = f.log(&shep);
    let mut m2 = f.mcp(Some(&h2));
    let why = m2
        .tool(
            "flock_emit",
            json!({"kind": "ack", "refs": {"of": brief}, "body": "ack"}),
        )
        .unwrap_err();
    assert!(why.contains("NotAddressee"), "{why}");
    assert_eq!(f.log(&shep), before, "the log is unchanged");

    // the addressee
    let ok = m1
        .tool(
            "flock_emit",
            json!({"kind": "ack", "refs": {"of": brief}, "body": "ack"}),
        )
        .unwrap();
    assert!(ok.starts_with("admitted "), "{ok}");
    assert!(m1
        .tool("flock_status", json!({}))
        .unwrap()
        .contains("working"));
    assert_ne!(f.log(&shep), before);
}

/// Real bodies of every kind the server alone signs, so each one parses and
/// the only thing that can stop it is admission.
fn server_signed_bodies(flock: ContentId) -> Vec<(&'static str, Body)> {
    let user = UserKey::generate();
    let key = AgentKey::issue(
        &user,
        AgentMetadata {
            role: "x".into(),
            host: "x".into(),
            capabilities: vec![],
            issued_at: "2026-10-18T00:00:00Z".into(),
            expires_at: None,
            caveats: Caveats::top(),
        },
    );
    let approval = MerkleNode::genesis(HandoffApproval {
        flock,
        member: "h1".into(),
        from: "a".into(),
        to: "b".into(),
        resume: flock,
        context: None,
    });
    let approval_sig = Assertion::sign(&key, &approval.content_id().unwrap());
    vec![
        ("epoch", Body::Epoch { epoch: 99 }),
        (
            "invite",
            Body::Invite {
                member: "h1".into(),
                verifier: RawContentId::from_content(b"v"),
            },
        ),
        (
            "session-start",
            Body::SessionStart {
                member: "h1".into(),
                session: "x".into(),
                cert: key.cert().clone(),
            },
        ),
        (
            "session-end",
            Body::SessionEnd {
                session: "x".into(),
                reason: EndReason::Closed,
            },
        ),
        (
            "handoff",
            Body::Handoff {
                from: "a".into(),
                to: "b".into(),
                resume: flock,
                context: None,
                approval: Box::new(approval),
                approval_sig: Box::new(approval_sig),
            },
        ),
        (
            "renewal",
            Body::Renewal {
                session: "x".into(),
                epoch: 1,
                cert: key.cert().clone(),
            },
        ),
    ]
}

#[test]
fn server_signed_kinds_are_refused_by_admission_not_by_the_tool() {
    let f = flock();
    let shep = f.session("shep");
    let before = f.log(&shep);
    let mut m = f.mcp(Some(&shep));
    let who = m.tool("flock_whoami", json!({})).unwrap();
    let flock_id: ContentId = who
        .lines()
        .find_map(|l| l.strip_prefix("flock:"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    for (kind, body) in server_signed_bodies(flock_id) {
        let why = m
            .tool(
                "flock_emit",
                json!({"kind": kind, "body": serde_json::to_value(&body).unwrap()}),
            )
            .unwrap_err();
        assert!(why.contains("refused"), "{kind}: {why}");
        assert!(
            !why.contains("not an event"),
            "{kind} must reach admission: {why}"
        );
    }
    assert_eq!(f.log(&shep), before, "none of them reached the log");
}

/// A small JSON Schema check, enough for the schemas the flock tools publish:
/// `type` (one name or several), `properties`, `required` and an
/// `additionalProperties` schema.
fn conforms(schema: &Value, v: &Value) -> bool {
    let is = |t: &str| match t {
        "object" => v.is_object(),
        "string" => v.is_string(),
        "array" => v.is_array(),
        "integer" | "number" => v.is_number(),
        "boolean" => v.is_boolean(),
        "null" => v.is_null(),
        _ => false,
    };
    let typed = match &schema["type"] {
        Value::String(t) => is(t),
        Value::Array(ts) => ts.iter().any(|t| is(t.as_str().unwrap_or(""))),
        _ => true,
    };
    if !typed {
        return false;
    }
    let Some(obj) = v.as_object() else {
        return true;
    };
    let required = schema["required"].as_array().cloned().unwrap_or_default();
    if required
        .iter()
        .any(|k| !obj.contains_key(k.as_str().unwrap()))
    {
        return false;
    }
    obj.iter().all(|(k, x)| match schema["properties"].get(k) {
        Some(sub) => conforms(sub, x),
        None => schema
            .get("additionalProperties")
            .filter(|a| a.is_object())
            .is_none_or(|a| conforms(a, x)),
    })
}

#[test]
fn the_published_schema_accepts_every_body_shape_the_tool_takes() {
    let f = flock();
    let (shep, h1) = (f.session("shep"), f.session("h1"));
    let o = f.cli(&shep, &["brief", "--to", "h1", "--lane", "l1"]);
    let brief = admitted_cid(&String::from_utf8(o.stdout).unwrap());
    let mut m = f.mcp(Some(&h1));
    let schema = m.schema("flock_emit");

    // the documented ack: a unit variant is a string
    let ack = json!({"kind": "ack", "refs": {"of": brief}, "body": "ack"});
    assert!(
        conforms(&schema, &ack),
        "schema rejects the documented ack: {schema}"
    );
    // and a struct variant is an object
    let result = json!({"kind": "result", "refs": {"brief": brief},
        "body": {"result": {"outcome": "completed"}}});
    assert!(conforms(&schema, &result));
    // the check itself can fail
    assert!(!conforms(&schema, &json!({"kind": "ack", "body": 7})));
    assert!(!conforms(&schema, &json!({"body": "ack"})));

    // a client that honoured the schema sends it, and it is admitted
    assert!(m.tool("flock_emit", ack).unwrap().starts_with("admitted "));
}

#[test]
fn refs_is_optional_but_never_null_in_the_schema_and_in_the_parser_alike() {
    let f = flock();
    let h1 = f.session("h1");
    let mut m = f.mcp(Some(&h1));
    let schema = m.schema("flock_emit");
    let job = |refs: Option<Value>| {
        let mut a = json!({"kind": "job", "body": {"job": {"lane": "l1", "label": "x"}}});
        if let Some(r) = refs {
            a["refs"] = r;
        }
        a
    };
    // omitted and {} both conform, and both are taken
    for refs in [None, Some(json!({}))] {
        let args = job(refs);
        assert!(conforms(&schema, &args), "{args}");
        assert!(m.tool("flock_emit", args).unwrap().starts_with("admitted "));
    }
    // null does not conform, and the parser agrees: it is refused, nothing is sent
    let before = f.log(&h1);
    let null = job(Some(Value::Null));
    assert!(
        !conforms(&schema, &null),
        "the schema must not allow null refs"
    );
    let err = m.tool("flock_emit", null).unwrap_err();
    assert!(err.contains("refs"), "{err}");
    assert_eq!(f.log(&h1), before);
}

#[test]
fn every_flock_tool_fails_once_the_bound_socket_stops_being_its_session() {
    let f = flock();
    let h1 = f.session("h1");
    // the socket the server is started with is a link under the flock's run/
    let link = f.dir.join("run").join("session-bound.sock");
    std::os::unix::fs::symlink(&h1.sock, &link).unwrap();
    let bound = Sess {
        _proc: Proc(Command::new("true").spawn().unwrap()),
        sock: link.clone(),
    };
    let mut m = f.mcp(Some(&bound));
    let args = [
        ("flock_whoami", json!({})),
        ("flock_inbox", json!({})),
        ("flock_status", json!({})),
        (
            "flock_emit",
            json!({"kind": "job", "body": {"job": {"lane": "l", "label": "x"}}}),
        ),
    ];
    for (t, a) in &args {
        assert!(m.tool(t, a.clone()).is_ok(), "{t} works while bound");
    }

    // swapped for another flock's live session
    let other = flock();
    let theirs = other.session("h1");
    let before = other.log(&theirs);
    std::fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(&theirs.sock, &link).unwrap();
    for (t, a) in &args {
        assert!(
            m.tool(t, a.clone()).is_err(),
            "{t} must fail on another flock's socket"
        );
    }
    assert_eq!(
        other.log(&theirs),
        before,
        "nothing was written to the other flock"
    );

    // removed
    std::fs::remove_file(&link).unwrap();
    for (t, a) in &args {
        assert!(
            m.tool(t, a.clone()).is_err(),
            "{t} must fail with no socket"
        );
    }
}

/// A session socket that is not a session: it vouches for itself on the first
/// two `Whoami`s (the server's startup check, then the tool's per-call guard)
/// and answers everything after with a refusal carrying `payload`.
fn mock_session(f: &Flock, payload: &str) -> PathBuf {
    use agent_mesh_flock_server::wire::{read_msg, write_msg};
    use agent_mesh_flock_session::{CtlReq, CtlResp};
    let sock = f.dir.join("run").join("session-mock.sock");
    let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    let flock = agent_mesh_flock_server::load_genesis(&f.dir)
        .unwrap()
        .node
        .content_id()
        .unwrap();
    let payload = payload.to_owned();
    std::thread::spawn(move || {
        for (n, conn) in listener.incoming().enumerate() {
            let Ok(mut c) = conn else { return };
            if read_msg::<CtlReq>(&mut c).ok().flatten().is_none() {
                continue;
            }
            let resp = if n < 2 {
                CtlResp::Who {
                    flock,
                    member: "m".into(),
                    session: "00".into(),
                    pending: false,
                }
            } else {
                CtlResp::Err(payload.clone())
            };
            let _ = write_msg(&mut c, &resp);
        }
    });
    sock
}

#[test]
fn a_refusal_after_startup_reaches_the_mcp_client_inert() {
    let payload = "\u{1b}]52;c;aGk=\u{7}\u{9b}31m\u{202e}rtl\u{61c}\nFORGED";
    let f = flock();
    let sock = mock_session(&f, payload);
    let mut child = amesh(f.home.path())
        .args(["mcp", "--quiet", "--flock-session"])
        .arg(&sock)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let _guard = Proc(child);
    let req = json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
        "params":{"name":"flock_whoami","arguments":{}}});
    writeln!(stdin, "{req}").unwrap();
    stdin.flush().unwrap();
    let mut line = String::new();
    out.read_line(&mut line).unwrap();

    let r: Value = serde_json::from_str(&line).unwrap_or_else(|e| panic!("{e}: {line:?}"));
    assert_eq!(r["id"], 1, "framing and id survive: {line}");
    let msg = r["error"]["message"]
        .as_str()
        .unwrap_or_else(|| panic!("an error response: {line:?}"));
    for (what, s) in [("message", msg), ("wire", line.as_str())] {
        let bad = s.chars().find(|c| {
            c.is_control() && *c != '\n'
                || matches!(c, '\u{061c}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}'
                    | '\u{2060}'..='\u{206f}' | '\u{feff}')
        });
        // the one newline the wire may carry is the framing terminator
        assert!(bad.is_none(), "{what}: {bad:?} in {s:?}");
    }
    assert!(!msg.contains('\n'), "a newline in {msg:?}");
    assert!(
        msg.contains("\\x1b]52"),
        "the text is still readable: {msg:?}"
    );
}
