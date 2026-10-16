//! Golden ids: each kind's node id is pinned, like content-addressable's
//! vectors. A change here is a change to the wire identity of the flock.

use agent_mesh_flock::{Body, Event, FileRef, Kind, Outcome};
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
            event(Kind::JobEnd, Body::JobEnd { code: 0 }, &[("job", "job")]),
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
            "epoch",
            event(Kind::Epoch, Body::Server { note: s("1") }, &[]),
        ),
        (
            "renewal",
            event(Kind::Renewal, Body::Server { note: s("1") }, &[]),
        ),
        (
            "session-start",
            event(Kind::SessionStart, Body::Server { note: s("h1") }, &[]),
        ),
        (
            "session-end",
            event(Kind::SessionEnd, Body::Server { note: s("h1") }, &[]),
        ),
        (
            "handoff",
            event(Kind::Handoff, Body::Server { note: s("h1") }, &[]),
        ),
        (
            "invite",
            event(Kind::Invite, Body::Server { note: s("h1") }, &[]),
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
        "epoch",
        "bafyr4icnupwrdyk33dypkeymaytqvkykxpt5gspegqdrfsyo7drjc2yib4",
    ),
    (
        "renewal",
        "bafyr4igazvtvs4jnhzx53d3shb4iumhr3g7a7o3qpxlnn6uaww75ycbgje",
    ),
    (
        "session-start",
        "bafyr4ibi5grrrg6z47gczbkjflrpdjjr57n4dqxi5csdb7vtmxu5yuhmre",
    ),
    (
        "session-end",
        "bafyr4ievv7abhebosq7irznmmsi4nkhnjm3lgoxodagc65u6xosist5gae",
    ),
    (
        "handoff",
        "bafyr4ihvomhnpo2xavrtrpbafrmq6d65uyalrd7afv3mxuiopgwym4gl74",
    ),
    (
        "invite",
        "bafyr4ickt72krfsi5mhepnizqny7mp5bdnkifzfqhjdqh5pcwwqsob37si",
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
