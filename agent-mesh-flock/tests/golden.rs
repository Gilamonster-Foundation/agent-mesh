//! Golden ids: each kind's node id is pinned, like content-addressable's
//! vectors. A change here is a change to the wire identity of the flock.

use agent_mesh_flock::{Body, EndReason, Event, FileRef, HandoffApproval, Kind, Outcome};
use agent_mesh_protocol::{AgentKey, AgentMetadata, Caveats, UserKey};
use content_addressable::{ContentAddressable, ContentId, MerkleNode, RawContentId};
use std::collections::BTreeMap;

fn cid(label: &str) -> ContentId {
    MerkleNode::genesis(label.to_owned()).content_id().unwrap()
}

fn event(kind: Kind, body: Body, refs: &[(&str, &str)]) -> MerkleNode<Event> {
    Event {
        flock: cid("flock"),
        kind,
        author: "aa".repeat(32),
        prev: Some(cid("prev")),
        refs: refs
            .iter()
            .map(|(r, l)| ((*r).to_owned(), cid(l)))
            .collect::<BTreeMap<_, _>>(),
        files: vec![FileRef {
            root: "lane".into(),
            path: "BRIEF.md".into(),
            id: RawContentId::from_content(b"brief bytes"),
        }],
        at: 1,
        body,
    }
    .node()
}

fn vectors() -> Vec<(&'static str, MerkleNode<Event>)> {
    let s = |t: &str| t.to_owned();
    vec![
        (
            "roster",
            event(
                Kind::Roster,
                Body::Roster { members: vec![] },
                &[("replaces", "roster")],
            ),
        ),
        (
            "brief",
            event(
                Kind::Brief,
                Body::Brief {
                    to: s("h1"),
                    lane: s("a"),
                },
                &[],
            ),
        ),
        (
            "review",
            event(
                Kind::Review,
                Body::Review {
                    to: s("rev"),
                    lane: s("a"),
                    head: s("abc"),
                },
                &[],
            ),
        ),
        ("ack", event(Kind::Ack, Body::Ack, &[("of", "brief")])),
        (
            "result",
            event(
                Kind::Result,
                Body::Result {
                    outcome: Outcome::Completed,
                },
                &[("brief", "brief")],
            ),
        ),
        (
            "verdict",
            event(
                Kind::Verdict,
                Body::Verdict {
                    head: s("abc"),
                    approved: true,
                },
                &[("review", "review")],
            ),
        ),
        (
            "job",
            event(
                Kind::Job,
                Body::Job {
                    lane: s("a"),
                    label: s("push"),
                },
                &[],
            ),
        ),
        (
            "job-end",
            event(
                Kind::JobEnd,
                Body::JobEnd {
                    code: Some(0),
                    signal: None,
                },
                &[("job", "job")],
            ),
        ),
        (
            "job-end-signal",
            event(
                Kind::JobEnd,
                Body::JobEnd {
                    code: None,
                    signal: Some(9),
                },
                &[("job", "job")],
            ),
        ),
        (
            "ask",
            event(
                Kind::Ask,
                Body::Ask {
                    lane: None,
                    text: s("?"),
                },
                &[("about", "brief")],
            ),
        ),
        (
            "answer",
            event(
                Kind::Answer,
                Body::Answer { text: s("y") },
                &[("ask", "ask")],
            ),
        ),
        (
            "relayed-answer",
            event(
                Kind::RelayedAnswer,
                Body::RelayedAnswer { text: s("y") },
                &[("ask", "ask")],
            ),
        ),
        (
            "status",
            event(Kind::Status, Body::Status { text: s("idle") }, &[]),
        ),
        (
            "nudged",
            event(Kind::Nudged, Body::Nudged { target: s("h1") }, &[]),
        ),
        (
            "nudged-of",
            event(
                Kind::Nudged,
                Body::Nudged { target: s("h1") },
                &[("of", "brief")],
            ),
        ),
        (
            "nudge-misfire",
            event(
                Kind::NudgeMisfire,
                Body::NudgeMisfire {
                    target: s("h1"),
                    expected: s("pane w1:p2 claude"),
                    found: s("pane w1:p2 shell"),
                },
                &[("of", "brief")],
            ),
        ),
        (
            "pane",
            event(
                Kind::Pane,
                Body::Pane {
                    pane: s("w1:p2"),
                    tab: s("w1:t1"),
                },
                &[],
            ),
        ),
        ("epoch", event(Kind::Epoch, Body::Epoch { epoch: 1 }, &[])),
        (
            "session-end",
            event(
                Kind::SessionEnd,
                Body::SessionEnd {
                    session: s("bb"),
                    reason: EndReason::Lost,
                },
                &[("session", "start")],
            ),
        ),
        (
            "invite",
            event(
                Kind::Invite,
                Body::Invite {
                    member: s("h1"),
                    verifier: RawContentId::from_content(b"token"),
                },
                &[],
            ),
        ),
    ]
}

const GOLDEN: &[(&str, &str)] = &[
    (
        "roster",
        "bafyr4igcgxd5zewv23avoi62l26625jtpibvrwufusuaa3x7olq7wgixam",
    ),
    (
        "brief",
        "bafyr4idrcczcf5mfcurz6bxeoyafrk7bst7zmyhiydg2vnab3dinmhjyte",
    ),
    (
        "review",
        "bafyr4ibstcfrlxji53rycg6plgcyvlumumpzdwr34u2ylfwwo2cxdrliaa",
    ),
    (
        "ack",
        "bafyr4idfiiu2byyzbwn7v6h2kjmglq2p3turh6vm5nulofgfsaahxvnbwa",
    ),
    (
        "result",
        "bafyr4iakrgw4v7p6nmf3z75tmt24irnbze5aiqirr4kifyqgeg4advv5xa",
    ),
    (
        "verdict",
        "bafyr4iati4l46rab537scm56iat43lgy36eglsiyudqiqju54zhukau4am",
    ),
    (
        "job",
        "bafyr4icwtbvfotgpkkzhj7irhchvu2vdapgdexvxfizmhhdfoasvzomtue",
    ),
    (
        "job-end",
        "bafyr4iaklrse2apiz4rm5o4lwzlkbx6vybt73vuejchwdnsvqrm2p63u7e",
    ),
    (
        "job-end-signal",
        "bafyr4ig5jdajgo5anbhqymngwvmmzplcotvhvx6a46tf7jmvokulqmkibe",
    ),
    (
        "ask",
        "bafyr4iagsgt2eolddr4ff2ojillis2bkcno4nvidnkw5acmu2vdwtet644",
    ),
    (
        "answer",
        "bafyr4ih5zlko2xx4il3b2lrklks3bjkz77osz6sxzhcyaqiwkjlxi2yngy",
    ),
    (
        "relayed-answer",
        "bafyr4iecbu3gw6sa6qghppwyxvtvv3vmieg3j7ydi3qlbgeqqccnphfmwy",
    ),
    (
        "status",
        "bafyr4igijsnolsquosf76cqo7awchhqzooeewjsjidrwziyoua3adxbhx4",
    ),
    (
        "nudged",
        "bafyr4idxdvmjklou4mzm2k2chzp3mjogqhklk6xibru7kzhphk2hcpuv3q",
    ),
    (
        "nudged-of",
        "bafyr4ig3o2lhyncz4lld6xovv54lrlwxvmy6tnavwcfceum5un3hh5xeei",
    ),
    (
        "nudge-misfire",
        "bafyr4ibvz3rvoxknidxd6m2dyztfdfnzzuimvmw65yipa4lqq6o4h4z3ki",
    ),
    (
        "pane",
        "bafyr4igmazngln4psjhurlt62av6biwgn6notplsvacwt4viwjwafcep5q",
    ),
    (
        "epoch",
        "bafyr4iapi4lxjb44425yr3blpzgmwxtfcpdusv7izooi7iknjppllkskta",
    ),
    (
        "session-end",
        "bafyr4ifj6aarj76aigbro5eq2xapkxq7ofzkeom7ihlhezzrvjfg6mf2am",
    ),
    (
        "invite",
        "bafyr4igvh2rrluj5m7ljyen74vu3vo4rhatc2jbh7cqqeafhy27ppds4ue",
    ),
];

#[test]
fn every_kind_has_its_pinned_id() {
    let actual: Vec<(&str, String)> = vectors()
        .into_iter()
        .map(|(k, n)| (k, n.content_id().unwrap().to_string()))
        .collect();
    let expected: Vec<(&str, &str)> = GOLDEN.to_vec();
    let got: Vec<(&str, &str)> = actual.iter().map(|(k, v)| (*k, v.as_str())).collect();
    assert_eq!(got, expected, "pin these:\n{got:#?}");
}

#[test]
fn parents_are_prev_and_refs_and_never_files() {
    let (_, node) = vectors().into_iter().find(|(k, _)| *k == "ack").unwrap();
    let want: std::collections::BTreeSet<_> = [cid("prev"), cid("brief")].into_iter().collect();
    assert_eq!(node.parents, want);
}

#[test]
fn two_signers_of_an_identical_body_get_different_ids() {
    let mut a = event(Kind::Ack, Body::Ack, &[("of", "brief")]);
    let b = a.clone();
    a.payload.author = "bb".repeat(32);
    assert_ne!(a.content_id().unwrap(), b.content_id().unwrap());
}

/// Bodies that carry a certificate cannot be pinned (keys are generated at
/// runtime); pin what can be: the id follows the certificate, and the kind.
#[test]
fn certificate_bearing_bodies_bind_the_certificate() {
    let user = UserKey::generate();
    let meta = |r: &str| AgentMetadata {
        role: r.into(),
        host: "h".into(),
        capabilities: vec![],
        issued_at: "2026-10-15T00:00:00Z".into(),
        expires_at: None,
        caveats: Caveats::top(),
    };
    let (a, b) = (
        AgentKey::issue(&user, meta("a")),
        AgentKey::issue(&user, meta("b")),
    );
    let start = |k: &AgentKey| {
        event(
            Kind::SessionStart,
            Body::SessionStart {
                member: "h1".into(),
                session: "bb".into(),
                cert: k.cert().clone(),
            },
            &[("invite", "invite")],
        )
        .content_id()
        .unwrap()
    };
    assert_eq!(start(&a), start(&a));
    assert_ne!(start(&a), start(&b));
    let renew = |k: &AgentKey, epoch| {
        event(
            Kind::Renewal,
            Body::Renewal {
                session: "bb".into(),
                epoch,
                cert: k.cert().clone(),
            },
            &[("session", "start")],
        )
        .content_id()
        .unwrap()
    };
    assert_ne!(renew(&a, 1), renew(&a, 2));
    assert_ne!(renew(&a, 1), renew(&b, 1));
}

fn approval() -> MerkleNode<HandoffApproval> {
    MerkleNode::genesis(HandoffApproval {
        flock: cid("flock"),
        member: "h1".into(),
        from: "aa".repeat(32),
        to: "bb".repeat(32),
        resume: cid("resume"),
        context: Some(FileRef {
            root: "lane".into(),
            path: "HANDOFF.md".into(),
            id: RawContentId::from_content(b"handoff bytes"),
        }),
    })
}

/// What the approver signs is key-independent, so it is pinned.
#[test]
fn the_handoff_approval_has_its_pinned_id() {
    assert_eq!(
        approval().content_id().unwrap().to_string(),
        "bafyr4ig26nyfneq4catmnr5zzzpuj2hbwafzyfzmb7hfzledzgc4maiv2e"
    );
}

/// The `handoff` event carries an assertion (a certificate), so like
/// session-start it is pinned by what it binds: the approval and every field.
#[test]
fn a_handoff_binds_its_approval_and_fields() {
    let user = UserKey::generate();
    let key = AgentKey::issue(
        &user,
        AgentMetadata {
            role: "op".into(),
            host: "h".into(),
            capabilities: vec![],
            issued_at: "2026-10-15T00:00:00Z".into(),
            expires_at: None,
            caveats: Caveats::top(),
        },
    );
    let handoff = |ap: MerkleNode<HandoffApproval>, to: &str| {
        let sig = agent_mesh_protocol::Assertion::sign(&key, &ap.content_id().unwrap());
        event(
            Kind::Handoff,
            Body::Handoff {
                from: "aa".repeat(32),
                to: to.into(),
                resume: cid("resume"),
                context: None,
                approval: Box::new(ap),
                approval_sig: Box::new(sig),
            },
            &[("from", "f"), ("to", "t"), ("resume", "resume")],
        )
        .content_id()
        .unwrap()
    };
    let base = handoff(approval(), "bb");
    assert_eq!(base, handoff(approval(), "bb"));
    assert_ne!(base, handoff(approval(), "cc"));
    let mut other = approval();
    other.payload.member = "h2".into();
    assert_ne!(base, handoff(other, "bb"));
}

/// Roster members as they were encoded before `devices` existed.
#[derive(serde::Serialize)]
struct MemberBefore {
    name: String,
    role: agent_mesh_flock::Role,
}

fn roster_node(devices: Vec<agent_mesh_protocol::Fingerprint>) -> MerkleNode<Event> {
    use agent_mesh_flock::{Member, Role};
    let members = vec![
        Member {
            name: "shep".into(),
            role: Role::Shepherd,
            devices: vec![],
        },
        Member {
            name: "op".into(),
            role: Role::Operator,
            devices,
        },
    ];
    event(
        Kind::Roster,
        Body::Roster { members },
        &[("replaces", "roster")],
    )
}

#[test]
fn a_member_without_devices_encodes_as_it_did_before_devices_existed() {
    use content_addressable::canonical::to_canonical_dagcbor;
    let m = agent_mesh_flock::Member {
        name: "shep".into(),
        role: agent_mesh_flock::Role::Shepherd,
        devices: vec![],
    };
    let before = MemberBefore {
        name: "shep".into(),
        role: agent_mesh_flock::Role::Shepherd,
    };
    assert_eq!(
        to_canonical_dagcbor(&m).unwrap(),
        to_canonical_dagcbor(&before).unwrap()
    );
}

#[test]
fn a_roster_with_devices_has_its_pinned_id_and_differs_from_one_without() {
    let none = roster_node(vec![]).content_id().unwrap().to_string();
    let one = roster_node(vec![agent_mesh_protocol::Fingerprint([7; 32])])
        .content_id()
        .unwrap()
        .to_string();
    assert_ne!(none, one);
    assert_eq!(
        // Re-pinned when keys and fingerprints became CBOR byte strings (was
        // bafyr4iatidh7yrc3nsinfuyh6iry7cioxd5pwis5cd6gwi2wcwp4xb2cou, with
        // the fingerprint as an array of 32 integers).
        one,
        "bafyr4ig43nudonwg2wiifkv33lu5xpj3uxiol4dwpiakhy6uv2pbe2xrwa",
        "pin this"
    );
}
