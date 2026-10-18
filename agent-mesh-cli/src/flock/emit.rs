//! Commands that write: each is one `Emit` to the session, which holds the
//! key, fills `prev`, signs and sends it. The CLI signs nothing, and checks
//! nothing the server's admission decides.

use super::discover::{Where, Who};
use agent_mesh_flock::{Body, Kind, Outcome};
use agent_mesh_flock_server::{Snapshot, Status};
use agent_mesh_flock_session::{call, CtlReq, CtlResp};
use anyhow::{anyhow, bail, Context, Result};
use content_addressable::ContentId;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Send one event through the session and print what the server admitted.
pub fn emit(home: &Path, w: &Where, kind: Kind, refs: &[(&str, &str)], body: Body) -> Result<()> {
    let refs = refs
        .iter()
        .map(|(role, cid)| {
            cid.parse::<ContentId>()
                .map(|c| ((*role).to_owned(), c))
                .map_err(|e| anyhow!("'{cid}' is not a content id: {e}"))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    println!("{}", send(home, w, kind, refs, body)?);
    Ok(())
}

/// One `Emit` to the session; the line that says what was admitted. The MCP
/// `flock_emit` tool goes through here too, so both carry the same rules.
pub fn send(
    home: &Path,
    w: &Where,
    kind: Kind,
    refs: BTreeMap<String, ContentId>,
    body: Body,
) -> Result<String> {
    let (socket, _) = w.session(home)?;
    let (event, index) = send_via(&socket, kind, refs, body)?;
    Ok(format!("admitted {event} at {index}"))
}

/// One `Emit` to a session already chosen; the event id and index the server
/// admitted. `run` uses it twice so both events go to the same session.
pub fn send_via(
    socket: &Path,
    kind: Kind,
    refs: BTreeMap<String, ContentId>,
    body: Body,
) -> Result<(ContentId, u64)> {
    match call(socket, &CtlReq::Emit { kind, refs, body })? {
        CtlResp::Admitted { event, index } => Ok((event, index)),
        _ => bail!("the session answered something else"),
    }
}

/// `join`: who is this session, and optionally tell the log its pane.
pub fn join(home: &Path, w: &Where, announce: bool) -> Result<()> {
    let (socket, text) = whoami(home, w)?;
    print!("{text}");
    if announce {
        match call(&socket, &CtlReq::Announce)? {
            CtlResp::Admitted { event, index } => println!("announced {event} at {index}"),
            _ => bail!("the session answered something else"),
        }
    }
    Ok(())
}

/// The session's socket and what `join` prints about it.
pub fn whoami(home: &Path, w: &Where) -> Result<(PathBuf, String)> {
    let (socket, me) = w.session(home)?;
    let snap = match w.dir(home) {
        Ok(dir) => Some(
            Snapshot::read(&dir).with_context(|| format!("read the log in {}", dir.display()))?,
        ),
        Err(_) => None,
    };
    Ok((socket, describe(&me, snap.as_ref())))
}

pub fn parse_outcome(s: &str) -> Result<Outcome> {
    match s {
        "completed" => Ok(Outcome::Completed),
        "failed" => Ok(Outcome::Failed),
        _ => bail!("outcome must be completed or failed"),
    }
}

/// What `join` prints. The session's `pending` is the flag it was handed at
/// enrollment, so it is labelled so; the current state comes from the log.
fn describe(me: &Who, snap: Option<&Snapshot>) -> String {
    let state = snap.map_or_else(
        || "unknown (name the flock with --dir or --name to read it from the log)".to_owned(),
        |s| format!("{} (in the log)", state_in_log(s, &me.session)),
    );
    format!(
        "flock:   {}\nmember:  {}\nsession: {}\nenrolled: {} (at enrollment; a hand-off may have changed it)\nstate:   {state}\n",
        me.flock,
        me.member,
        me.session,
        if me.pending { "pending" } else { "active" },
    )
}

/// A session's status in the verified log: the authority, unlike the
/// `pending` flag the session was handed when it enrolled.
fn state_in_log(snap: &Snapshot, session: &str) -> &'static str {
    match snap.sessions().get(session).map(|i| i.status) {
        Some(Status::Active) => "active",
        Some(Status::Pending) => "pending",
        Some(Status::Ended) => "ended",
        None => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_mesh_flock::{FileRef, HandoffApproval, Member};
    use agent_mesh_flock_server::{init, InitSpec, Server};
    use agent_mesh_protocol::{AgentKey, Assertion, UserKey};
    use content_addressable::{ContentAddressable as _, MerkleNode, RawContentId};
    use ed25519_dalek::{Signer as _, SigningKey};
    use rand::rngs::OsRng;

    fn enroll(server: &mut Server, member: &str) -> (AgentKey, String, bool) {
        let invite = server.invite(member).unwrap();
        let sk = SigningKey::generate(&mut OsRng);
        let ch = server
            .enroll_begin(&invite.token, member, sk.verifying_key().to_bytes())
            .unwrap();
        let done = server
            .enroll_finish(&ch, &sk.sign(&ch.signing_bytes()))
            .unwrap();
        let key = AgentKey::from_seed_and_cert(&sk.to_bytes(), done.cert).unwrap();
        (key, done.session, done.pending)
    }

    #[test]
    fn the_state_shown_is_the_logs_after_a_handoff_not_the_enrollment_flag() {
        let dir = tempfile::tempdir().unwrap();
        let spec = InitSpec {
            name: "f".into(),
            roster: ["shep:shepherd", "h1:helper"]
                .iter()
                .map(|m| {
                    let (n, r) = m.split_once(':').unwrap();
                    Member {
                        name: n.into(),
                        role: serde_json::from_value(r.into()).unwrap(),
                        devices: vec![],
                    }
                })
                .collect(),
            salt: "00".into(),
            host: "h".into(),
            issued_at: "t".into(),
        };
        init(dir.path(), &UserKey::generate(), spec).unwrap();
        let mut server = Server::open(dir.path()).unwrap();
        let (shep, _, _) = enroll(&mut server, "shep");
        let (_, old, _) = enroll(&mut server, "h1");
        let (_, new, enrolled_pending) = enroll(&mut server, "h1");
        assert!(enrolled_pending, "the flag the session is handed");
        let snap = || Snapshot::read(dir.path()).unwrap();
        assert_eq!(state_in_log(&snap(), &new), "pending");
        let approval = MerkleNode::genesis(HandoffApproval {
            flock: server.flock(),
            member: "h1".into(),
            from: old.clone(),
            to: new.clone(),
            resume: server.sessions().get(&old).unwrap().start,
            context: Some(FileRef {
                root: "r".into(),
                path: "HANDOFF.md".into(),
                id: RawContentId::from_content(b"h"),
            }),
        });
        let sig = Assertion::sign(&shep, &approval.content_id().unwrap());
        server.handoff(approval, sig).unwrap();
        // the session still believes it enrolled pending; the log says active
        assert_eq!(state_in_log(&snap(), &new), "active");
        let me = Who {
            flock: server.flock(),
            member: "h1".into(),
            session: new.clone(),
            pending: true, // what the session was told when it enrolled
        };
        let shown = describe(&me, Some(&snap()));
        assert!(shown.contains("enrolled: pending"), "{shown}");
        assert!(shown.contains("state:   active (in the log)"), "{shown}");
        assert_eq!(state_in_log(&snap(), &old), "ended");
        assert_eq!(state_in_log(&snap(), "nope"), "unknown");
    }
}
