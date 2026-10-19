//! The Lane view over a real flock on disk and real files: attempts, reviews
//! and `changed since cited`, as golden screens, and the properties that must
//! hold in every state. Files are only ever read.
#![cfg(unix)]

mod support;

use agent_mesh_flock::{Body, FileRef, Kind, Outcome};
use agent_mesh_flock_server::Snapshot;
use agent_mesh_tui::drift::{check_all, Drift, FileState, Roots};
use agent_mesh_tui::model::{fold, Link, Model, Source};
use agent_mesh_tui::ui::{render, App, Tab};
use content_addressable::{ContentAddressable as _, RawContentId};
use newtui::{Component as _, Explorer, Key, Named, Observation, PropertyOutcome};
use std::os::unix::fs::symlink;
use support::{assert_snapshot, mask_hashes, mask_id, Fixture};

struct World {
    f: Fixture,
    tmp: tempfile::TempDir,
    roots: Roots,
}

fn id(bytes: &[u8]) -> RawContentId {
    RawContentId::from_content(bytes)
}

fn file(root: &str, path: &str, bytes: &[u8]) -> FileRef {
    FileRef {
        root: root.into(),
        path: path.into(),
        id: id(bytes),
    }
}

/// Lane `l1`: attempt one (brief, ack, review, verdict, a result citing files,
/// a second result that is a conflict), then attempt two (brief, a job open).
/// Lane `l2`: a brief nobody took. Files: `a.rs` unchanged, `b.rs` edited after
/// it was cited, `gone.rs` missing, `escape.txt` a link out of the root, `..`
/// and an unmapped root.
fn world() -> World {
    let tmp = tempfile::tempdir().unwrap();
    let work = tmp.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::write(work.join("a.rs"), b"fn a() {}").unwrap();
    std::fs::write(work.join("b.rs"), b"fn b() { /* edited */ }").unwrap();
    std::fs::write(tmp.path().join("secret.txt"), b"secret").unwrap();
    symlink(tmp.path().join("secret.txt"), work.join("escape.txt")).unwrap();
    let mut roots = Roots::default();
    roots.insert("work", work);

    let mut f = Fixture::new();
    let shep = f.enroll("shep");
    let h1 = f.enroll("h1");
    let rev = f.enroll("rev");
    let brief = f.emit(
        &shep,
        Kind::Brief,
        &[],
        Body::Brief {
            to: "h1".into(),
            lane: "l1".into(),
        },
    );
    f.emit(&h1, Kind::Ack, &[("of", brief)], Body::Ack);
    let review = f.emit(
        &shep,
        Kind::Review,
        &[],
        Body::Review {
            to: "rev".into(),
            lane: "l1".into(),
            head: "c0ffee".into(),
        },
    );
    f.emit(
        &rev,
        Kind::Verdict,
        &[("review", review)],
        Body::Verdict {
            head: "c0ffee".into(),
            approved: true,
        },
    );
    // the result comes after the reviewed head: the review may be stale
    f.emit_files(
        &h1,
        Kind::Result,
        &[("brief", brief)],
        Body::Result {
            outcome: Outcome::Completed,
        },
        vec![
            file("work", "a.rs", b"fn a() {}"),
            file("work", "b.rs", b"fn b() {}"),
            file("work", "gone.rs", b"gone"),
            file("work", "escape.txt", b"secret"),
            file("work", "../secret.txt", b"secret"),
            file("elsewhere", "x.rs", b"x"),
        ],
    );
    // a second closer: admitted, but as a conflict
    f.emit(
        &h1,
        Kind::Result,
        &[("brief", brief)],
        Body::Result {
            outcome: Outcome::Failed,
        },
    );
    f.emit(
        &shep,
        Kind::Brief,
        &[],
        Body::Brief {
            to: "h1".into(),
            lane: "l1".into(),
        },
    );
    f.emit(
        &h1,
        Kind::Job,
        &[],
        Body::Job {
            lane: "l1".into(),
            label: "build".into(),
        },
    );
    f.emit(
        &shep,
        Kind::Brief,
        &[],
        Body::Brief {
            to: "h2".into(),
            lane: "l2".into(),
        },
    );
    World { f, tmp, roots }
}

fn model_of(f: &Fixture) -> Model {
    let snap = Snapshot::read(f.path()).unwrap();
    let genesis = agent_mesh_flock_server::load_genesis(f.path())
        .unwrap()
        .node;
    let id = genesis.content_id().unwrap();
    fold(&Source::of_snapshot("fx", id, &snap), Link::Live)
}

fn app_of(w: &World, checked: bool) -> App {
    let mut app = App::new(model_of(&w.f));
    app.handle(Key::Char('3'));
    assert_eq!(app.tab(), Tab::Lane);
    if checked {
        app.set_drift(check_all(&w.roots, &app.cited_files()));
    }
    app
}

fn screen(app: &App, height: u16) -> String {
    mask_hashes(&mask_id(&render::to_text(app, 110, height)))
}

#[test]
fn a_lane_has_its_latest_attempt_older_ones_conflicts_and_reviews() {
    let w = world();
    let m = model_of(&w.f);
    assert_eq!(
        m.lanes.iter().map(|l| l.lane.as_str()).collect::<Vec<_>>(),
        ["l1", "l2"]
    );
    let l1 = &m.lanes[0];
    // the latest attempt is the second brief, with its job still open
    assert_eq!(l1.latest.label, "submitted, job open");
    // the first completed, and the second closer is a conflict aimed at it
    assert_eq!(l1.older.len(), 1);
    assert!(l1.older[0].label.starts_with("completed"), "{:?}", l1.older);
    assert_eq!(l1.older[0].conflicts.len(), 1);
    // a review and its verdict, both older than the lane's first result
    let kinds: Vec<_> = l1.reviews.iter().map(|r| r.kind.as_str()).collect();
    assert_eq!(kinds, ["review", "verdict"]);
    let result = m
        .events
        .iter()
        .find(|e| e.kind == "result" && !e.conflict)
        .unwrap()
        .index;
    for r in &l1.reviews {
        assert_eq!(r.head, "c0ffee");
        assert_eq!(r.newer_result, Some(result), "{r:?}");
    }
    // the conflicting result is not "newer": it closes nothing
    // and a file is listed once, in the order it was cited
    assert_eq!(l1.files.len(), 6);
    assert_eq!(l1.files[0].path, "a.rs");
    assert!(m.lanes[1].files.is_empty());
}

#[test]
fn a_review_with_no_later_result_is_not_marked_stale() {
    let mut f = Fixture::new();
    let shep = f.enroll("shep");
    f.emit(
        &shep,
        Kind::Brief,
        &[],
        Body::Brief {
            to: "h1".into(),
            lane: "l1".into(),
        },
    );
    f.emit(
        &shep,
        Kind::Review,
        &[],
        Body::Review {
            to: "rev".into(),
            lane: "l1".into(),
            head: "abc".into(),
        },
    );
    let m = model_of(&f);
    assert_eq!(m.lanes[0].reviews.len(), 1);
    assert_eq!(m.lanes[0].reviews[0].newer_result, None);
}

#[test]
fn drift_is_same_changed_or_unavailable_per_file() {
    let w = world();
    let app = app_of(&w, true);
    let d: &Drift = app.drift();
    let state = |path: &str| {
        let f = &app.model().lanes[0]
            .files
            .iter()
            .find(|f| f.path == path)
            .unwrap();
        d[&agent_mesh_tui::drift::key(f)].clone()
    };
    assert_eq!(state("a.rs"), FileState::Same);
    assert_eq!(
        state("b.rs"),
        FileState::Changed {
            current: id(b"fn b() { /* edited */ }")
        }
    );
    for (p, why) in [
        ("gone.rs", "file missing"),
        ("escape.txt", "path leaves its root or crosses a link"),
        ("../secret.txt", "path leaves its root"),
        ("x.rs", "root not mapped"),
    ] {
        assert_eq!(state(p), FileState::Unavailable(why.into()), "{p}");
    }
}

#[test]
fn the_lane_screen_shows_marks_and_the_detail_of_the_selected_lane() {
    let w = world();
    assert_snapshot("lane", &screen(&app_of(&w, true), 22));
}

#[test]
fn before_any_check_the_files_say_so() {
    let w = world();
    assert_snapshot("lane_unchecked", &screen(&app_of(&w, false), 22));
}

#[test]
fn the_second_lane_has_nothing_cited() {
    let w = world();
    let mut app = app_of(&w, true);
    app.handle(Key::Down);
    assert_snapshot("lane_two", &screen(&app, 14));
}

#[test]
fn an_edit_after_the_check_shows_only_when_asked_again() {
    let w = world();
    let mut app = app_of(&w, true);
    std::fs::write(w.tmp.path().join("work/a.rs"), b"fn a() { 2 }").unwrap();
    // nothing re-reads the file by itself
    assert!(screen(&app, 22).contains("✓ work/a.rs"));
    assert!(!app.take_recheck());
    app.handle(Key::Char('r'));
    assert!(app.take_recheck());
    assert!(!app.take_recheck(), "the ask is spent");
    app.set_drift(check_all(&w.roots, &app.cited_files()));
    let s = screen(&app, 22);
    assert!(s.contains("⚠ work/a.rs changed since cited"), "{s}");
    assert!(
        s.contains("cited <cid>") && s.contains("now   <cid>"),
        "{s}"
    );
}

#[test]
fn a_lane_the_log_grows_keeps_its_selection_and_its_known_files() {
    let w = world();
    let mut app = app_of(&w, true);
    app.handle(Key::Down);
    let drift = app.drift().clone();
    app.set_model(model_of(&w.f));
    assert_eq!(app.lane_selected(), Some(1));
    assert_eq!(app.drift(), &drift);
}

#[test]
fn tabs_cycle_through_the_lane_view_both_ways() {
    let w = world();
    let mut app = App::new(model_of(&w.f));
    for want in [Tab::Stream, Tab::Lane, Tab::Waiting, Tab::Board] {
        app.handle(Key::Tab);
        assert_eq!(app.tab(), want);
    }
    app.handle(Key::BackTab);
    assert_eq!(app.tab(), Tab::Waiting);
}

fn alphabet() -> Vec<Key> {
    vec![
        Key::Up,
        Key::Down,
        Key::Home,
        Key::End,
        Key::PageUp,
        Key::PageDown,
        Key::Char('r'),
        Key::Tab,
        Key::BackTab,
        Key::Char('3'),
    ]
}

/// Within the Lane tab a key moves the selection and nothing else: the lanes
/// and what they say stay as they were.
fn keys_never_change_the_lanes() -> Named<impl Fn(&Observation<'_>) -> PropertyOutcome> {
    Named::new("a key never changes the displayed lanes", |o| match o {
        Observation::Transition { from, to, .. } => {
            let data = |v: &newtui::View| {
                v.rows
                    .iter()
                    .map(|r| (r.label.clone(), r.value.clone(), r.note.clone()))
                    .collect::<Vec<_>>()
            };
            if from.title != "Lane" || to.title != "Lane" {
                PropertyOutcome::NotApplicable
            } else if data(from) == data(to) && from.footer == to.footer {
                PropertyOutcome::Held
            } else {
                PropertyOutcome::Violated("a key changed the lane rows".into())
            }
        }
        Observation::State { .. } => PropertyOutcome::NotApplicable,
    })
}

#[test]
fn every_reachable_state_keeps_the_selection_in_range_and_the_lanes_untouched() {
    let w = world();
    let model = model_of(&w.f);
    let report = Explorer::new(alphabet()).explore(
        || {
            let mut app = App::new(model.clone());
            app.handle(Key::Char('3'));
            app
        },
        &[
            &newtui::properties::selection_is_always_in_range(),
            &keys_never_change_the_lanes(),
        ],
    );
    assert!(report.is_clean(), "{report}");
    assert!(report.exhausted, "the search was capped");
    assert!(
        report.never_applied().is_empty(),
        "{:?}",
        report.never_applied()
    );
}

#[test]
fn keys_never_touch_the_model_or_the_drift_it_holds() {
    let w = world();
    let mut app = app_of(&w, true);
    let (model, drift) = (app.model().clone(), app.drift().clone());
    for k in alphabet().into_iter().cycle().take(60) {
        app.handle(k);
    }
    assert_eq!(app.model(), &model);
    assert_eq!(app.drift(), &drift);
}

#[test]
fn a_smaller_model_clamps_the_lane_selection() {
    let w = world();
    let mut app = app_of(&w, true);
    app.handle(Key::Down);
    assert_eq!(app.lane_selected(), Some(1));
    let mut fewer = app.model().clone();
    fewer.lanes.truncate(1);
    app.set_model(fewer);
    assert_eq!(app.lane_selected(), Some(0));
    let mut none = app.model().clone();
    none.lanes.clear();
    app.set_model(none);
    assert_eq!(app.lane_selected(), None);
}

#[test]
fn only_a_result_that_closed_something_is_newer_and_a_file_is_listed_once() {
    let mut f = Fixture::new();
    let shep = f.enroll("shep");
    let h1 = f.enroll("h1");
    let brief = f.emit(
        &shep,
        Kind::Brief,
        &[],
        Body::Brief {
            to: "h1".into(),
            lane: "l1".into(),
        },
    );
    let cite = || vec![file("work", "a.rs", b"x")];
    let done = || Body::Result {
        outcome: Outcome::Completed,
    };
    f.emit_files(&h1, Kind::Result, &[("brief", brief)], done(), cite());
    f.emit(
        &shep,
        Kind::Review,
        &[],
        Body::Review {
            to: "rev".into(),
            lane: "l1".into(),
            head: "abc".into(),
        },
    );
    // admitted after the review, but as a second closer: it closes nothing,
    // so it does not make the review stale; it cites the same file again
    f.emit_files(&h1, Kind::Result, &[("brief", brief)], done(), cite());
    let m = model_of(&f);
    assert!(m.events.last().unwrap().conflict);
    assert_eq!(m.lanes[0].reviews[0].newer_result, None);
    assert_eq!(m.lanes[0].files.len(), 1, "{:?}", m.lanes[0].files);
}
