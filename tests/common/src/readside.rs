//! Proof that a consumer of the flock crates has no writer: shared by the
//! session crate's tests (the crates themselves) and the TUI's (a crate built
//! on them). Two independent checks, because neither is enough alone:
//!
//! - **resolution**: `cargo tree -p P --format "{p}|{f}"` lists the features
//!   cargo resolves for one package (per-package; `cargo metadata` unifies
//!   across the workspace and would always see the CLI's writer);
//! - **API**: a scratch crate that depends on the flock crates with
//!   `default-features = false` (and, optionally, on the crate under test) must
//!   fail to resolve every writer API while the same lines compile with the
//!   writer on, and the read API must compile. If the crate under test turned a
//!   writer feature on, cargo would unify it into the scratch crate and the
//!   writer lines would compile: the check goes red.
//!
//! Needs only cargo and the crates already in the lockfile.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn cargo() -> String {
    std::env::var("CARGO").unwrap_or_else(|_| "cargo".into())
}

/// `package -> enabled features`, one entry per node of `cargo tree`'s normal
/// (non-dev) closure for the selected package.
///
/// # Panics
/// If cargo cannot resolve the selection.
#[must_use]
pub fn features(root: &Path, selection: &[&str]) -> Vec<(String, Vec<String>)> {
    let out = Command::new(cargo())
        .current_dir(root)
        .args(["tree", "--locked", "-e", "normal", "--prefix", "none"])
        .args(["--format", "{p}|{f}"])
        .args(selection)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .filter_map(|l| {
            let (pkg, feats) = l.split_once('|')?;
            let feats = feats.trim_end_matches(" (*)");
            Some((
                pkg.split_whitespace().next()?.to_owned(),
                feats
                    .split(',')
                    .filter(|f| !f.is_empty())
                    .map(str::to_owned)
                    .collect(),
            ))
        })
        .collect()
}

/// Whether `package` appears in the closure with `feature` enabled.
#[must_use]
pub fn has(tree: &[(String, Vec<String>)], package: &str, feature: &str) -> bool {
    tree.iter()
        .any(|(p, f)| p == package && f.iter().any(|x| x == feature))
}

/// Just the flock crates, for messages a person can read.
#[must_use]
pub fn ours(tree: &[(String, Vec<String>)]) -> Vec<&(String, Vec<String>)> {
    tree.iter()
        .filter(|(p, _)| p.starts_with("agent-mesh-flock"))
        .collect()
}

/// Whether `package` appears in the closure at all.
#[must_use]
pub fn present(tree: &[(String, Vec<String>)], package: &str) -> bool {
    tree.iter().any(|(p, _)| p == package)
}

/// (name, snippet, text the compiler must say when the writer is off)
pub const WRITER_ONLY: &[(&str, &str, &str)] = &[
    (
        "seal",
        "let _ = agent_mesh_flock_server::seal;",
        "cannot find value `seal` in crate",
    ),
    (
        "refusal_sign",
        "let _ = agent_mesh_flock_server::RefusalEntry::sign;",
        "named `sign` found for struct `RefusalEntry`",
    ),
    (
        "server",
        "let _ = agent_mesh_flock_server::Server::open;",
        "cannot find `Server` in `agent_mesh_flock_server`",
    ),
    (
        "init",
        "let _ = agent_mesh_flock_server::init;",
        "cannot find value `init` in crate",
    ),
    (
        "req_invite",
        "let _ = agent_mesh_flock_server::wire::Req::Invite { member: String::new() };",
        "no variant named `Invite`",
    ),
    (
        "req_enroll",
        "let _ = agent_mesh_flock_server::wire::Req::EnrollBegin { token: String::new(), member: String::new(), pubkey: [0; 32] };",
        "no variant named `EnrollBegin`",
    ),
    (
        "req_head",
        "let _ = |s: String| agent_mesh_flock_server::wire::Req::Head { session: s };",
        "no variant named `Head`",
    ),
    (
        "req_end",
        "let _ = agent_mesh_flock_server::wire::Req::End;",
        "named `End` found for enum `Req`",
    ),
    (
        "ctl_end",
        "let _ = agent_mesh_flock_session::CtlReq::End;",
        "named `End` found for enum `CtlReq`",
    ),
    (
        "ctl_emit",
        "let _ = agent_mesh_flock_session::CtlReq::Announce;",
        "named `Announce` found for enum `CtlReq`",
    ),
    (
        "session",
        "let _ = agent_mesh_flock_session::Session::enroll;",
        "cannot find `Session` in `agent_mesh_flock_session`",
    ),
];

/// Held-key signing was moved out of the library into test code: gone
/// whatever the features, so there is no writer-on control for it.
pub const GONE: &[(&str, &str, &str)] = &[(
    "key_prover",
    "let _ = agent_mesh_flock_session::key_prover;",
    "cannot find value `key_prover` in crate",
)];

/// The read side, which must keep compiling with the writer off.
pub const READ_API: &str = r#"
    use agent_mesh_flock_server::wire::{read_msg, write_msg, Req, Resp, StreamChallenge};
    use agent_mesh_flock_server::{load_genesis, verify_record, Follower, Head, Snapshot};
    use agent_mesh_flock_session::{
        call, save_atomic, session_prover, CtlReq, CtlResp, Prover, Reader, RealFs, Seen, Watch,
        WatchEvent,
    };
    let _ = |c: &mut std::os::unix::net::UnixStream| {
        let _: Result<Option<Resp>, _> = read_msg(c);
        write_msg(c, &Req::Hello)
    };
    let _ = (load_genesis, Snapshot::read, Follower::new);
    let _ = (call, session_prover, save_atomic, Watch::open, WatchEvent::Caught(0));
    let _: Option<(Head, StreamChallenge, Seen<'_>, Prover<'_>, CtlResp)> = None;
    let _ = (Req::Hello, Req::WatchBegin, CtlReq::Whoami);
    let _ = (verify_record, std::marker::PhantomData::<Reader<RealFs>>);
    let _ = |c: StreamChallenge| CtlReq::ProveStream { challenge: c };
"#;

/// A scratch crate that depends on the two flock crates (no default
/// features) and on whatever `extra` names.
pub struct Probe {
    dir: tempfile::TempDir,
    target: PathBuf,
}

impl Probe {
    /// `extra` is `(crate name, path)` pairs the scratch crate also depends on.
    ///
    /// # Panics
    /// On a filesystem error.
    #[must_use]
    pub fn new(root: &Path, extra: &[(&str, &Path)]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let p = |c: &str| root.join(c).display().to_string();
        let extra: String = extra
            .iter()
            .map(|(n, path)| format!("{n} = {{ path = \"{}\" }}\n", path.display()))
            .collect();
        fs::write(
            dir.path().join("Cargo.toml"),
            format!(
                r#"[package]
name = "probe"
version = "0.0.0"
edition = "2021"

[features]
writer = ["agent-mesh-flock-server/serve", "agent-mesh-flock-session/emit"]

[dependencies]
agent-mesh-flock-server = {{ path = "{}", default-features = false }}
agent-mesh-flock-session = {{ path = "{}", default-features = false }}
{extra}
[workspace]
"#,
                p("agent-mesh-flock-server"),
                p("agent-mesh-flock-session"),
            ),
        )
        .unwrap();
        // the same dependency versions as the workspace, resolved offline
        fs::copy(root.join("Cargo.lock"), dir.path().join("Cargo.lock")).unwrap();
        fs::create_dir_all(dir.path().join("src/bin")).unwrap();
        fs::write(dir.path().join("src/main.rs"), "fn main() {}\n").unwrap();
        Self {
            dir,
            target: root.join("target").join("read_side_probe"),
        }
    }

    /// Compile `snippet` as `fn main`; `Ok` or the compiler's complaint.
    ///
    /// # Errors
    /// The compiler's stderr.
    ///
    /// # Panics
    /// On a filesystem error.
    pub fn check(&self, name: &str, snippet: &str, writer: bool) -> Result<(), String> {
        fs::write(
            self.dir.path().join(format!("src/bin/{name}.rs")),
            format!("#![allow(unused)]\nfn main() {{\n{snippet}\n}}\n"),
        )
        .unwrap();
        let mut c = Command::new(cargo());
        c.current_dir(self.dir.path())
            .env("CARGO_TARGET_DIR", &self.target)
            .args(["check", "--offline", "--quiet", "--bin", name]);
        if writer {
            c.args(["--features", "writer"]);
        }
        let out = c.output().unwrap();
        if out.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).into_owned())
        }
    }
}

/// Assert the whole API claim for a scratch consumer that also depends on
/// `extra`: the read API compiles with the writer off, every writer API fails
/// to resolve (and compiles with the writer on), the gone ones are gone.
///
/// # Panics
/// With the compiler's message, on any violation.
pub fn assert_no_writer_apis(root: &Path, extra: &[(&str, &Path)]) {
    let probe = Probe::new(root, extra);
    if let Err(e) = probe.check("read_api", READ_API, false) {
        panic!("the read API must compile with both writer features off:\n{e}");
    }
    for (name, snippet, said) in WRITER_ONLY {
        // control: with the writer on, the same line compiles, so the failure
        // below is the gate and not a typo in the snippet
        if let Err(e) = probe.check(name, snippet, true) {
            panic!("{name}: should compile with the writer on:\n{e}");
        }
        match probe.check(name, snippet, false) {
            Ok(()) => panic!("{name}: resolves with both writer features off: {snippet}"),
            Err(e) => assert!(e.contains(said), "{name}: expected `{said}` in:\n{e}"),
        }
    }
    for (name, snippet, said) in GONE {
        for writer in [false, true] {
            match probe.check(name, snippet, writer) {
                Ok(()) => panic!("{name}: should not exist (writer={writer})"),
                Err(e) => assert!(e.contains(said), "{name}: expected `{said}` in:\n{e}"),
            }
        }
    }
}
