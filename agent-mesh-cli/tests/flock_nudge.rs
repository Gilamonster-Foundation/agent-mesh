//! `amesh flock nudge` as a real process against a real server and sessions,
//! with a fake `herdr` script first on PATH that logs every argv: the real
//! herdr is never reached.
#![cfg(unix)]

mod harness;
use agent_mesh_flock::{Body, Kind, Role};
use agent_mesh_flock_server::Snapshot;
use agent_mesh_flock_session::{call, CtlReq, CtlResp};
use harness::*;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Output;
use tempfile::TempDir;

/// panes: p0 = the adapter (`ad`), p1 = `h1`, p2 = `shep`. `agent get` answers
/// per pane; with `swap_on_prompt` present, the prompt changes who p1 is.
const HERDR: &str = r#"#!/bin/sh
S="$FAKE_HERDR_STATE"
echo "$*" >> "$S/calls"
kind=newt; [ -e "$S/swapped" ] && kind=claude
case "$1 $2" in
"pane list") cat <<EOF2
{"result":{"panes":[
{"pane_id":"w1:p0","tab_id":"w1:t1","workspace_id":"w1","label":"ad","agent":"newt","agent_status":"idle"},
{"pane_id":"w1:p1","tab_id":"w1:t1","workspace_id":"w1","label":"h1","agent":"$kind","agent_status":"idle"},
{"pane_id":"w1:p2","tab_id":"w1:t1","workspace_id":"w1","label":"shep","agent":"newt","agent_status":"idle"},
{"pane_id":"w1:p3","tab_id":"w1:t1","workspace_id":"w1","agent":"newt","agent_status":"idle"}]}}
EOF2
;;
"agent get") echo "{\"result\":{\"agent\":{\"terminal_id\":\"t-$3\",\"name\":\"n-$3\",\"agent\":\"$kind\",\"agent_status\":\"idle\",\"pane_id\":\"$3\",\"tab_id\":\"w1:t1\"}}}";;
"agent wait") echo '{}';;
"agent prompt") if [ -e "$S/swap_on_prompt" ]; then touch "$S/swapped"; fi; echo '{}';;
*) echo "$*" >> "$S/unexpected"; exit 3;;
esac
"#;

struct Fake {
    bin: TempDir,
    state: TempDir,
}

fn fake() -> Fake {
    let f = Fake {
        bin: TempDir::new().unwrap(),
        state: TempDir::new().unwrap(),
    };
    let path = f.bin.path().join("herdr");
    std::fs::write(&path, HERDR).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    f
}

impl Fake {
    fn calls(&self) -> Vec<String> {
        std::fs::read_to_string(self.state.path().join("calls"))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }
    fn prompts(&self) -> Vec<String> {
        self.calls()
            .into_iter()
            .filter(|c| c.starts_with("agent prompt"))
            .collect()
    }
    /// Only the four verbs were ever issued.
    fn audit(&self) {
        assert!(!self.state.path().join("unexpected").exists());
        for c in self.calls() {
            let w: Vec<&str> = c.split(' ').collect();
            assert!(
                matches!(
                    w[..2],
                    ["pane", "list"] | ["agent", "get"] | ["agent", "wait"] | ["agent", "prompt"]
                ),
                "{c}"
            );
        }
    }
}

fn nudge(f: &Flock, fake: &Fake, s: &Sess, extra: &[&str]) -> Output {
    amesh(f.home.path())
        .args(["flock", "nudge", "--dir"])
        .arg(&f.dir)
        .arg("--session")
        .arg(&s.sock)
        .arg("--once")
        .args(extra)
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", fake.bin.path().display()),
        )
        .env("FAKE_HERDR_STATE", fake.state.path())
        .env("HERDR_PANE_ID", "w1:p0")
        .output()
        .unwrap()
}

fn ok(o: &Output) -> String {
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8(o.stdout.clone()).unwrap()
}

fn log(dir: &Path) -> Snapshot {
    Snapshot::read(dir).unwrap()
}

/// Events of `kind` citing `of`.
fn citing(dir: &Path, kind: Kind, of: &str) -> usize {
    log(dir)
        .board()
        .entries()
        .filter(|e| {
            e.event.kind == kind
                && e.event.refs.get("of").map(ToString::to_string).as_deref() == Some(of)
        })
        .count()
}

fn flock4() -> Flock {
    flock_with(&[
        "shep:shepherd",
        "h1:helper",
        "h2:helper",
        "ad:adapter",
        "op:operator",
    ])
}

#[test]
fn a_brief_is_nudged_once_the_nudge_cites_it_and_a_restart_or_an_ack_stops_more() {
    let f = flock4();
    let (fake, shep, h1, ad) = (fake(), f.session("shep"), f.session("h1"), f.session("ad"));
    let brief = f.emit(&shep, &["brief", "--to", "h1", "--lane", "l1"]);
    let out = ok(&nudge(&f, &fake, &ad, &[]));
    assert!(out.contains("Nudged") && out.contains("admitted"), "{out}");

    // by pane id, after waiting for idle, with exactly the fixed text
    assert_eq!(
        fake.prompts(),
        [format!("agent prompt w1:p1 amesh flock take {brief}")]
    );
    assert!(fake
        .calls()
        .iter()
        .any(|c| c == "agent wait w1:p1 --timeout 120000"));
    fake.audit();
    // the nudge is in the log, signed by the adapter, citing the brief
    assert_eq!(citing(&f.dir, Kind::Nudged, &brief), 1);
    let snap = log(&f.dir);
    let n = snap
        .board()
        .entries()
        .find(|e| e.event.kind == Kind::Nudged)
        .unwrap();
    assert_eq!(n.member.as_deref(), Some("ad"));
    assert!(matches!(&n.event.body, Body::Nudged { target } if target == "h1"));

    // a restart re-derives from the log: nothing more is prompted
    ok(&nudge(&f, &fake, &ad, &[]));
    assert_eq!(fake.prompts().len(), 1, "nudged twice across a restart");

    // an event the addressee already took is never nudged
    let second = f.emit(&shep, &["brief", "--to", "h1", "--lane", "l2"]);
    f.emit(&h1, &["take", &second]);
    ok(&nudge(&f, &fake, &ad, &[]));
    assert_eq!(fake.prompts().len(), 1, "an acked brief was nudged");
    assert_eq!(citing(&f.dir, Kind::Nudged, &second), 0);
    fake.audit();
}

#[test]
fn an_addressee_with_no_pane_gets_a_status_and_no_prompt() {
    let f = flock4();
    let (fake, shep, ad) = (fake(), f.session("shep"), f.session("ad"));
    let brief = f.emit(&shep, &["brief", "--to", "h2", "--lane", "l1"]); // h2 has no pane
    ok(&nudge(&f, &fake, &ad, &[]));
    assert!(fake.prompts().is_empty());
    assert!(!fake.calls().iter().any(|c| c.starts_with("agent wait")));
    let snap = log(&f.dir);
    let st = snap
        .board()
        .entries()
        .find_map(|e| match &e.event.body {
            Body::Status { text } => Some(text.clone()),
            _ => None,
        })
        .expect("a status");
    assert!(
        st.contains("not nudged: h2") && st.contains("no pane") && st.contains(&brief),
        "{st}"
    );
    assert_eq!(citing(&f.dir, Kind::Nudged, &brief), 0);
}

#[test]
fn a_pane_that_changes_under_the_prompt_is_recorded_as_a_misfire_not_a_nudge() {
    let f = flock4();
    let (fake, shep, ad) = (fake(), f.session("shep"), f.session("ad"));
    std::fs::write(fake.state.path().join("swap_on_prompt"), "").unwrap();
    let brief = f.emit(&shep, &["brief", "--to", "h1", "--lane", "l1"]);
    let out = ok(&nudge(&f, &fake, &ad, &[]));
    assert!(out.contains("NudgeMisfire"), "{out}");
    assert_eq!(fake.prompts().len(), 1);
    assert_eq!(citing(&f.dir, Kind::NudgeMisfire, &brief), 1);
    assert_eq!(citing(&f.dir, Kind::Nudged, &brief), 0);
    // a misfire is a record too: it is not nudged again
    ok(&nudge(&f, &fake, &ad, &[]));
    assert_eq!(fake.prompts().len(), 1);
}

#[test]
fn a_deny_list_keeps_the_prompt_away() {
    let f = flock4();
    let (fake, shep, ad) = (fake(), f.session("shep"), f.session("ad"));
    f.emit(&shep, &["brief", "--to", "h1", "--lane", "l1"]);
    ok(&nudge(&f, &fake, &ad, &["--deny", "tab:w1:t1"]));
    assert!(fake.prompts().is_empty());
    // and so does a deny file in the home
    std::fs::write(f.home.path().join("herdr-nudge.deny"), "pane:w1:p1\n").unwrap();
    ok(&nudge(&f, &fake, &ad, &[]));
    assert!(fake.prompts().is_empty());
    fake.audit();
}

#[test]
fn only_the_adapters_session_may_run_it() {
    let f = flock4();
    let (fake, shep) = (fake(), f.session("shep"));
    f.emit(&shep, &["brief", "--to", "h1", "--lane", "l1"]);
    let o = nudge(&f, &fake, &shep, &[]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("not the adapter"));
    assert!(fake.calls().is_empty(), "herdr was reached");
}

#[test]
fn outside_herdr_nothing_is_prompted() {
    let f = flock4();
    let (fake, shep, ad) = (fake(), f.session("shep"), f.session("ad"));
    f.emit(&shep, &["brief", "--to", "h1", "--lane", "l1"]);
    let o = amesh(f.home.path())
        .args(["flock", "nudge", "--once", "--dir"])
        .arg(&f.dir)
        .arg("--session")
        .arg(&ad.sock)
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", fake.bin.path().display()),
        )
        .env("FAKE_HERDR_STATE", fake.state.path())
        .env_remove("HERDR_PANE_ID")
        .output()
        .unwrap();
    ok(&o);
    assert!(fake.prompts().is_empty());
}

#[test]
fn the_log_alone_decides_even_when_the_readers_saved_state_is_lost() {
    let f = flock4();
    let (fake, shep, ad) = (fake(), f.session("shep"), f.session("ad"));
    f.emit(&shep, &["brief", "--to", "h1", "--lane", "l1"]);
    ok(&nudge(&f, &fake, &ad, &[]));
    assert_eq!(fake.prompts().len(), 1);
    // replay everything from scratch: the nudge is in the replayed log, and
    // nothing is decided until the replay is over
    std::fs::remove_dir_all(f.dir.join("nudge")).unwrap();
    ok(&nudge(&f, &fake, &ad, &[]));
    assert_eq!(fake.prompts().len(), 1, "a replay nudged again");
}

#[test]
fn the_operator_is_never_nudged() {
    let f = flock4();
    let (fake, shep, ad) = (fake(), f.session("shep"), f.session("ad"));
    f.emit(&shep, &["brief", "--to", "op", "--lane", "l1"]);
    ok(&nudge(&f, &fake, &ad, &[]));
    assert!(
        fake.calls().is_empty(),
        "herdr was reached for the operator"
    );
    assert!(!log(&f.dir)
        .board()
        .entries()
        .any(|e| e.event.kind == Kind::Status));
}

#[test]
fn a_running_nudge_takes_live_events_and_tries_each_once() {
    use std::io::{BufRead as _, BufReader};
    use std::process::Stdio;
    let f = flock4();
    let (fake, shep, ad) = (fake(), f.session("shep"), f.session("ad"));
    let mut child = amesh(f.home.path())
        .args(["flock", "nudge", "--dir"])
        .arg(&f.dir)
        .arg("--session")
        .arg(&ad.sock)
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", fake.bin.path().display()),
        )
        .env("FAKE_HERDR_STATE", fake.state.path())
        .env("HERDR_PANE_ID", "w1:p0")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let proc = Proc(child);
    let mut next = || {
        let mut l = String::new();
        out.read_line(&mut l).unwrap();
        l
    };
    // live: each line arrives only after its event did
    let live = f.emit(&shep, &["brief", "--to", "h1", "--lane", "l1"]);
    let l = next();
    assert!(l.starts_with("Nudged") && l.contains(&live), "{l}");
    // a refused one is recorded once; its own status frame must not retry it
    let a = f.emit(&shep, &["brief", "--to", "h2", "--lane", "l2"]);
    let l = next();
    assert!(l.starts_with("Status") && l.contains(&a), "{l}");
    let b = f.emit(&shep, &["brief", "--to", "h2", "--lane", "l3"]);
    let l = next();
    assert!(
        l.starts_with("Status") && l.contains(&b),
        "retried the first: {l}"
    );
    drop(proc);
    assert_eq!(fake.prompts().len(), 1);
}

#[test]
fn a_map_and_a_sessions_own_pane_claim_choose_the_pane_when_no_label_does() {
    let f = flock4();
    let (fake, shep, ad) = (fake(), f.session("shep"), f.session("ad"));
    // h2 has no label anywhere: only --map can reach p3
    let a = f.emit(&shep, &["brief", "--to", "h2", "--lane", "l1"]);
    ok(&nudge(&f, &fake, &ad, &["--map", "h2=w1:p3"]));
    assert_eq!(
        fake.prompts(),
        [format!("agent prompt w1:p3 amesh flock take {a}")]
    );

    // h1's session announces p3 (signed); a claim beats the label p1
    let fake = self::fake();
    let _h1 = f.session_in("h1", Some(("w1:p3", "w1:t1")));
    let b = f.emit(&shep, &["brief", "--to", "h1", "--lane", "l2"]);
    ok(&nudge(&f, &fake, &ad, &[]));
    assert_eq!(
        fake.prompts(),
        [format!("agent prompt w1:p3 amesh flock take {b}")]
    );
    fake.audit();
}

#[test]
fn a_brief_that_already_has_a_result_is_not_nudged() {
    let f = flock4();
    let (fake, shep, h1, ad) = (fake(), f.session("shep"), f.session("h1"), f.session("ad"));
    let brief = f.emit(&shep, &["brief", "--to", "h1", "--lane", "l1"]);
    f.emit(&h1, &["result", &brief, "--outcome", "completed"]);
    ok(&nudge(&f, &fake, &ad, &[]));
    assert!(fake.calls().is_empty(), "a closed brief was nudged");
}

/// The shepherd's session signs a roster that gives `who` a new role.
fn set_role(f: &Flock, shep: &Sess, who: &str, role: Role) {
    let snap = log(&f.dir);
    let mut members = snap.board().members().to_vec();
    members.iter_mut().find(|m| m.name == who).unwrap().role = role;
    let refs =
        std::collections::BTreeMap::from([("replaces".to_owned(), snap.board().roster_id())]);
    let body = Body::Roster {
        members,
        roots: snap.board().roots().to_vec(),
    };
    let r = call(
        &shep.sock,
        &CtlReq::Emit {
            kind: Kind::Roster,
            refs,
            body,
        },
    )
    .unwrap();
    assert!(
        matches!(r, CtlResp::Admitted { .. }),
        "the roster change was not admitted"
    );
}

#[test]
fn an_adapter_demoted_in_the_replayed_log_touches_herdr_not_at_all() {
    let f = flock4();
    let (fake, shep, ad) = (fake(), f.session("shep"), f.session("ad"));
    // the genesis roster says adapter; the log, once replayed, says helper
    set_role(&f, &shep, "ad", Role::Helper);
    f.emit(&shep, &["brief", "--to", "h1", "--lane", "l1"]);
    let o = nudge(&f, &fake, &ad, &[]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("not the adapter"));
    assert!(
        fake.calls().is_empty(),
        "herdr was reached by a demoted adapter"
    );
}

#[test]
fn a_member_promoted_to_adapter_after_genesis_is_accepted_once_caught_up() {
    let f = flock_with(&["shep:shepherd", "h1:helper", "ad:helper"]);
    let (fake, shep, ad) = (fake(), f.session("shep"), f.session("ad"));
    set_role(&f, &shep, "ad", Role::Adapter);
    let brief = f.emit(&shep, &["brief", "--to", "h1", "--lane", "l1"]);
    let out = ok(&nudge(&f, &fake, &ad, &[]));
    assert!(out.contains("Nudged"), "{out}");
    assert_eq!(citing(&f.dir, Kind::Nudged, &brief), 1);
}

#[test]
fn an_adapter_demoted_while_running_stops_before_the_next_herdr_command() {
    use std::io::{BufRead as _, BufReader};
    use std::process::Stdio;
    let f = flock4();
    let (fake, shep, ad) = (fake(), f.session("shep"), f.session("ad"));
    let mut child = amesh(f.home.path())
        .args(["flock", "nudge", "--dir"])
        .arg(&f.dir)
        .arg("--session")
        .arg(&ad.sock)
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", fake.bin.path().display()),
        )
        .env("FAKE_HERDR_STATE", fake.state.path())
        .env("HERDR_PANE_ID", "w1:p0")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let first = f.emit(&shep, &["brief", "--to", "h1", "--lane", "l1"]);
    let mut line = String::new();
    out.read_line(&mut line).unwrap();
    assert!(
        line.starts_with("Nudged") && line.contains(&first),
        "{line}"
    );
    let before = fake.calls().len();
    // the demoting frame arrives live: the process ends on it, then a brief follows
    set_role(&f, &shep, "ad", Role::Helper);
    let status = child.wait().unwrap();
    assert!(!status.success(), "a demoted adapter kept running");
    f.emit(&shep, &["brief", "--to", "h1", "--lane", "l2"]);
    assert_eq!(
        fake.calls().len(),
        before,
        "herdr was reached after the demotion"
    );
}
