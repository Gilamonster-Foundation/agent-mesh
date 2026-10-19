//! The Stream view and the raw-event panel, over a real flock on disk: every
//! admitted event, filters, follow, the raw view with jumpable parents, and
//! golden screens. The model is only ever read.
#![cfg(unix)]

mod support;

use agent_mesh_tui::events::EventRow;
use agent_mesh_tui::model::{fold, fold_onto, Link, Model};
use agent_mesh_tui::ui::{render, App, Tab};
use newtui::{Component as _, Key};
use std::sync::Arc;
use support::{assert_snapshot, busy_model, mask_hashes, mask_id};

fn app() -> (support::Fixture, App) {
    let (f, m) = busy_model(Link::Live);
    let mut app = App::new(m);
    app.handle(Key::Char('2'));
    assert_eq!(app.tab(), Tab::Stream);
    (f, app)
}

fn screen(app: &App, height: u16) -> String {
    mask_hashes(&mask_id(&render::to_text(app, 110, height)))
}

fn press(app: &mut App, keys: &str) {
    for c in keys.chars() {
        app.handle(Key::Char(c));
    }
}

fn shown(app: &App) -> Vec<&EventRow> {
    app.stream_rows()
        .into_iter()
        .map(|i| &app.model().events[i])
        .collect()
}

#[test]
fn every_admitted_event_is_on_the_stream_in_order_with_its_lane() {
    let (f, m) = busy_model(Link::Live);
    let snap = agent_mesh_flock_server::Snapshot::read(f.path()).unwrap();
    assert_eq!(m.events.len() as u64, snap.admitted());
    for (i, e) in m.events.iter().enumerate() {
        assert_eq!(e.index, i as u64 + 1, "admission order");
    }
    let find = |kind: &str, member: &str| {
        m.events
            .iter()
            .find(|e| e.kind == kind && e.member == member)
            .unwrap()
    };
    // the lane of an answer is the lane of what it answers
    assert_eq!(find("ack", "h1").lane.as_deref(), Some("l1"));
    assert_eq!(find("job-end", "shep").lane.as_deref(), Some("l9"));
    assert_eq!(find("brief", "shep").lane.as_deref(), Some("l1"));
    assert_eq!(find("status", "herdr").lane, None);
    // server-signed events are the server's
    assert!(m
        .events
        .iter()
        .any(|e| e.kind == "session-start" && e.member == "server"));
    // an exit is a code or a signal, in words
    assert_eq!(find("job-end", "shep").summary, "exit 0");
}

#[test]
fn the_stream_follows_the_newest_event_until_the_reader_moves_off_it() {
    let (_f, m) = busy_model(Link::Live);
    let grow = |m: &Model, n: usize| {
        let mut m = m.clone();
        let events = Arc::make_mut(&mut m.events);
        for _ in 0..n {
            let mut e = events.last().unwrap().clone();
            e.index += 1;
            e.id = format!("{}x", e.id);
            events.push(e);
        }
        m
    };
    let mut app = App::new(m.clone());
    app.handle(Key::Char('2'));
    assert!(app.following());
    assert_eq!(app.stream_selected(), Some(m.events.len() - 1));
    // following: the newest event is selected as it arrives
    app.set_model(grow(&m, 3));
    assert_eq!(app.stream_selected(), Some(m.events.len() + 2));
    // moving up leaves follow, and new events no longer move the selection
    app.handle(Key::Up);
    assert!(!app.following());
    let stayed = app.stream_selected();
    app.set_model(grow(&m, 6));
    assert_eq!(app.stream_selected(), stayed);
    // `f` turns follow back on and jumps to the newest; so does End
    app.handle(Key::Char('f'));
    assert!(app.following());
    assert_eq!(app.stream_selected(), Some(m.events.len() + 5));
    app.handle(Key::Up);
    app.handle(Key::End);
    assert!(app.following());
}

#[test]
fn kind_lane_and_member_filters_cycle_through_what_the_log_has_and_clear() {
    let (_f, mut app) = app();
    let all = shown(&app).len();
    // k: each kind in turn, then back to all
    let mut kinds = vec![];
    for _ in 0..40 {
        press(&mut app, "k");
        match app.filters().kind.clone() {
            Some(k) => {
                assert!(shown(&app).iter().all(|e| e.kind == k), "{k}");
                assert!(!shown(&app).is_empty());
                kinds.push(k);
            }
            None => break,
        }
    }
    assert!(kinds.contains(&"ack".to_owned()) && kinds.contains(&"job-end".to_owned()));
    assert!(kinds.windows(2).all(|w| w[0] < w[1]), "sorted: {kinds:?}");
    assert_eq!(shown(&app).len(), all, "one more press is back to all");

    // lane and member narrow together with kind
    press(&mut app, "l");
    let lane = app.filters().lane.clone().unwrap();
    assert!(shown(&app).iter().all(|e| e.lane.as_deref() == Some(&lane)));
    press(&mut app, "m");
    let who = app.filters().member.clone().unwrap();
    assert!(shown(&app)
        .iter()
        .all(|e| e.lane.as_deref() == Some(&lane) && e.member == who));
    press(&mut app, "k");
    assert!(shown(&app)
        .iter()
        .all(|e| Some(&e.kind) == app.filters().kind.as_ref()));
    // c clears all three
    press(&mut app, "c");
    assert!(!app.filters().any());
    assert_eq!(shown(&app).len(), all);
}

#[test]
fn the_raw_panel_shows_the_verified_event_and_its_parents_can_be_followed() {
    let (_f, mut app) = app();
    // an ack: kind filter to it, select it, open the panel
    while app.filters().kind.as_deref() != Some("ack") {
        press(&mut app, "k");
    }
    app.handle(Key::Enter);
    let ack = app.raw().expect("panel open").clone();
    let text = render::raw_lines(&app).join("\n");
    assert!(text.contains(&ack.id) && text.contains("✓"), "{text}");
    assert!(text.contains("signed by h1; session "), "{text}");
    // h1's first event has no prev: its only parent is what it answers
    assert!(text.contains("1 of "), "the reference is listed:\n{text}");
    assert!(text.contains("→ #"), "{text}");
    assert!(text.contains("\"ack\""), "the body:\n{text}");

    // 1 jumps to the parent: another event, with the panel still open
    let before = app.stream_selected();
    app.handle(Key::Char('1'));
    let parent = app.raw().expect("still open").clone();
    assert_ne!(parent.id, ack.id);
    assert_eq!(ack.parents[0].id, parent.id);
    assert_eq!(parent.index, ack.index.min(parent.index));
    // a parent the filter hides is shown anyway: the filters were cleared
    assert!(!app.filters().any() || parent.kind == "ack");
    // Backspace goes back to where we were
    app.handle(Key::Backspace);
    assert_eq!(app.stream_selected(), before);
    // a number with no parent does nothing
    app.handle(Key::Char('9'));
    assert_eq!(app.stream_selected(), before);
    // Esc closes the panel and does not leave the program
    assert!(!matches!(app.handle(Key::Esc), newtui::Flow::Close(_)));
    assert!(app.raw().is_none());
}

#[test]
fn keys_never_change_what_the_model_says() {
    let (_f, m) = busy_model(Link::Live);
    let mut app = App::new(m.clone());
    let keys = [
        Key::Up,
        Key::Down,
        Key::Home,
        Key::End,
        Key::PageUp,
        Key::PageDown,
        Key::Enter,
        Key::Esc,
        Key::Tab,
        Key::BackTab,
        Key::Backspace,
    ];
    let chars: Vec<Key> = "fklmc123456789x".chars().map(Key::Char).collect();
    for round in 0..4 {
        for k in keys.iter().chain(&chars) {
            // q would end the session; the rest must leave the model alone
            app.handle(*k);
            assert_eq!(app.model(), &m, "round {round}, key {k}");
        }
    }
}

#[test]
fn a_newer_fold_reuses_the_rows_it_already_has_and_rebuilds_when_they_are_not_its_log() {
    let (_f, full) = busy_model(Link::Live);
    let rebuilt = |prev: &Model| {
        let src_events = prev.events.len();
        let _ = src_events;
        prev.clone()
    };
    let _ = rebuilt;
    let (f, _) = busy_model(Link::Live);
    let snap = agent_mesh_flock_server::Snapshot::read(f.path()).unwrap();
    let genesis = agent_mesh_flock_server::load_genesis(f.path())
        .unwrap()
        .node;
    let id = content_addressable::ContentAddressable::content_id(&genesis).unwrap();
    let src = agent_mesh_tui::model::Source::of_snapshot("fx", id, &snap);
    let want = fold(&src, Link::Live);
    assert_eq!(want.events.len(), full.events.len());

    // a prefix of the same log: the rows are reused and the rest added
    let mut prefix = want.clone();
    Arc::make_mut(&mut prefix.events).truncate(5);
    let onto = fold_onto(Some(&prefix), &src, Link::Live);
    assert_eq!(onto, want);
    assert!(
        !Arc::ptr_eq(&onto.events, &prefix.events),
        "grew into a new list"
    );

    // rows that are not this log's (the last one differs): rebuilt, not trusted
    let other_cid = |i: usize| {
        content_addressable::ContentAddressable::content_id(
            &content_addressable::MerkleNode::genesis(format!("other{i}")),
        )
        .unwrap()
    };
    let mut other = want.clone();
    Arc::make_mut(&mut other.events)[4].cid = other_cid(4);
    Arc::make_mut(&mut other.events).truncate(5);
    assert_eq!(fold_onto(Some(&other), &src, Link::Live), want);

    // the same length and the same LAST event, but another history before it:
    // an event id commits to its own author's chain, not to everything the
    // flock admitted earlier, so matching the last id proves nothing
    let mut forked = want.clone();
    let n = forked.events.len();
    {
        let rows = Arc::make_mut(&mut forked.events);
        rows[2].cid = other_cid(2);
        rows[2].summary = "another history".into();
    }
    assert_eq!(forked.events.len(), n);
    assert_eq!(forked.events.last(), want.events.last());
    let healed = fold_onto(Some(&forked), &src, Link::Live);
    assert_eq!(healed, want, "the forked rows were kept");
}

#[test]
fn golden_screens_of_the_stream_and_the_raw_panel() {
    let (_f, mut app) = app();
    assert_snapshot("stream", &screen(&app, 30));

    // only acks, then the raw view of the newest one
    while app.filters().kind.as_deref() != Some("ack") {
        press(&mut app, "k");
    }
    assert_snapshot("stream_acks", &screen(&app, 12));
    app.handle(Key::Enter);
    assert_snapshot("stream_raw", &screen(&app, 24));
    app.handle(Key::Char('1'));
    assert_snapshot("stream_raw_parent", &screen(&app, 24));
}

#[test]
fn the_stream_keeps_the_selection_on_screen_through_a_resize_with_the_header_fixed() {
    let (_f, m) = busy_model(Link::Live);
    let mut big = m.clone();
    let events = Arc::make_mut(&mut big.events);
    while events.len() < 60 {
        let mut e = events.last().unwrap().clone();
        e.index += 1;
        e.id = format!("{}x", e.id);
        events.push(e);
    }
    let mut app = App::new(big.clone());
    app.handle(Key::Char('2'));
    let newest = big.events.last().unwrap().index.to_string();
    for height in [24, 9, 7, 40, 14] {
        let text = render::to_text(&app, 110, height);
        assert!(
            text.contains("[Stream]") && text.contains("amesh-tui · flock"),
            "{text}"
        );
        assert!(
            text.lines()
                .any(|l| l.starts_with('▸') && l.contains(&format!(" {newest} "))),
            "height {height}:\n{text}"
        );
    }
    // walk to the top: the first event comes into view, the newest leaves it
    app.handle(Key::Home);
    let top = render::to_text(&app, 110, 12);
    assert!(
        top.lines()
            .any(|l| l.starts_with('▸') && l.contains("     1 ")),
        "{top}"
    );
    assert!(
        !top.lines().any(|l| l
            .trim_start_matches(['▸', ' '])
            .starts_with(&format!("{newest} "))),
        "{top}"
    );
}

fn fold_disk(f: &support::Fixture, prev: Option<&Model>) -> Model {
    let snap = agent_mesh_flock_server::Snapshot::read(f.path()).unwrap();
    let genesis = agent_mesh_flock_server::load_genesis(f.path())
        .unwrap()
        .node;
    let id = content_addressable::ContentAddressable::content_id(&genesis).unwrap();
    let src = agent_mesh_tui::model::Source::of_snapshot("fx", id, &snap);
    fold_onto(prev, &src, Link::Live)
}

#[test]
fn a_lane_comes_from_the_event_answered_never_from_the_authors_previous_event() {
    use agent_mesh_flock::{Body, Kind};
    let mut f = support::Fixture::new();
    let (shep, h1, herdr) = (f.enroll("shep"), f.enroll("h1"), f.enroll("herdr"));
    // h1 works in alpha, is then briefed in beta and acknowledges the brief:
    // the ack's prev is the alpha job, what it answers is the beta brief
    f.emit(
        &h1,
        Kind::Job,
        &[],
        Body::Job {
            lane: "alpha".into(),
            label: "j".into(),
        },
    );
    let brief = f.emit(
        &shep,
        Kind::Brief,
        &[],
        Body::Brief {
            to: "h1".into(),
            lane: "beta".into(),
        },
    );
    f.emit(&h1, Kind::Ack, &[("of", brief)], Body::Ack);
    // a status after a job names no lane and answers nothing
    f.emit(
        &herdr,
        Kind::Job,
        &[],
        Body::Job {
            lane: "gamma".into(),
            label: "k".into(),
        },
    );
    f.emit(
        &herdr,
        Kind::Status,
        &[],
        Body::Status {
            text: "idle".into(),
        },
    );
    let m = fold_disk(&f, None);
    let lane = |kind: &str, who: &str| {
        m.events
            .iter()
            .find(|e| e.kind == kind && e.member == who)
            .unwrap()
            .lane
            .clone()
    };
    assert_eq!(lane("ack", "h1").as_deref(), Some("beta"));
    assert_eq!(
        lane("status", "herdr"),
        None,
        "no lane is invented from prev"
    );
    // and filtering by beta finds the ack
    let mut app = App::new(m);
    app.handle(Key::Char('2'));
    while app.filters().lane.as_deref() != Some("beta") {
        app.handle(Key::Char('l'));
    }
    assert!(shown(&app).iter().any(|e| e.kind == "ack"));
}

#[test]
fn the_signer_label_does_not_rewrite_a_role_after_a_roster_change() {
    use agent_mesh_flock::{Body, Kind, Role};
    let mut f = support::Fixture::new();
    let herdr = f.enroll("herdr");
    f.emit(
        &herdr,
        Kind::Status,
        &[],
        Body::Status {
            text: "idle".into(),
        },
    );
    let before = fold_disk(&f, None);
    // the roster now makes herdr a helper; the old status was signed as an adapter
    let mut roster = f.server.board().members().to_vec();
    roster.iter_mut().find(|m| m.name == "herdr").unwrap().role = Role::Helper;
    f.server.replace_roster(roster).unwrap();
    let fresh = fold_disk(&f, None);
    let grown = fold_disk(&f, Some(&before));
    assert_eq!(fresh, grown, "fresh and incremental folds agree");
    let status = fresh.events.iter().find(|e| e.kind == "status").unwrap();
    assert!(
        !status.signer.contains("helper") && !status.signer.contains("adapter"),
        "a role as of today is not the role the event was signed under: {}",
        status.signer
    );
    assert!(status.signer.starts_with("herdr"), "{}", status.signer);
}
