//! The Waiting view over a real flock on disk: unanswered asks, reviews with
//! no verdict and briefs nobody has taken, each with its age in events and
//! the member it waits on. The view answers nothing.
#![cfg(unix)]

mod support;

use agent_mesh_flock::{Body, FileRef, Kind, Outcome};
use agent_mesh_flock_server::Snapshot;
use agent_mesh_tui::model::{fold, Link, Model, Source};
use agent_mesh_tui::ui::{render, App, Tab};
use content_addressable::{ContentAddressable as _, RawContentId};
use newtui::{Component as _, Explorer, Key, Named, Observation, PropertyOutcome};
use support::{assert_snapshot, mask_hashes, mask_id, Fixture};

fn model_of(f: &Fixture) -> Model {
    let snap = Snapshot::read(f.path()).unwrap();
    let genesis = agent_mesh_flock_server::load_genesis(f.path())
        .unwrap()
        .node;
    let id = genesis.content_id().unwrap();
    fold(&Source::of_snapshot("fx", id, &snap), Link::Live)
}

fn brief(
    f: &mut Fixture,
    who: &support::Who,
    to: &str,
    lane: &str,
) -> content_addressable::ContentId {
    f.emit(
        who,
        Kind::Brief,
        &[],
        Body::Brief {
            to: to.into(),
            lane: lane.into(),
        },
    )
}

/// l1: taken (acked), with an ask carrying a draft file, an ask without one,
/// a review nobody ruled on and a review that has its verdict. l2: a brief
/// nobody took. l3: a brief superseded by a newer untaken one. l4: completed.
fn world() -> Fixture {
    let mut f = Fixture::new();
    let shep = f.enroll("shep");
    let h1 = f.enroll("h1");
    let rev = f.enroll("rev");
    // the oldest thing in the log is a brief nobody has taken
    brief(&mut f, &shep, "h2", "l0");
    let b1 = brief(&mut f, &shep, "h1", "l1");
    f.emit(&h1, Kind::Ack, &[("of", b1)], Body::Ack);
    f.emit_files(
        &h1,
        Kind::Ask,
        &[("about", b1)],
        Body::Ask {
            lane: Some("l1".into()),
            text: "which branch?".into(),
        },
        vec![FileRef {
            root: "work".into(),
            path: "notes/draft.md".into(),
            id: RawContentId::from_content(b"draft"),
        }],
    );
    f.emit(
        &h1,
        Kind::Ask,
        &[("about", b1)],
        Body::Ask {
            lane: Some("l1".into()),
            text: "ok to rebase?".into(),
        },
    );
    let open = f.emit(
        &shep,
        Kind::Review,
        &[],
        Body::Review {
            to: "rev".into(),
            lane: "l1".into(),
            head: "c0ffee".into(),
        },
    );
    let ruled = f.emit(
        &shep,
        Kind::Review,
        &[],
        Body::Review {
            to: "rev".into(),
            lane: "l1".into(),
            head: "beef".into(),
        },
    );
    f.emit(
        &rev,
        Kind::Verdict,
        &[("review", ruled)],
        Body::Verdict {
            head: "beef".into(),
            approved: true,
        },
    );
    let _ = open;
    brief(&mut f, &shep, "h2", "l2");
    brief(&mut f, &shep, "h2", "l3");
    brief(&mut f, &shep, "h1", "l3");
    let b4 = brief(&mut f, &shep, "h1", "l4");
    f.emit(&h1, Kind::Ack, &[("of", b4)], Body::Ack);
    f.emit(
        &h1,
        Kind::Result,
        &[("brief", b4)],
        Body::Result {
            outcome: Outcome::Completed,
        },
    );
    f
}

fn app_of(f: &Fixture) -> App {
    let mut app = App::new(model_of(f));
    app.handle(Key::Char('4'));
    assert_eq!(app.tab(), Tab::Waiting);
    app
}

fn screen(app: &App, height: u16) -> String {
    mask_hashes(&mask_id(&render::to_text(app, 110, height)))
}

#[test]
fn what_waits_is_open_asks_unruled_reviews_and_untaken_latest_briefs() {
    let f = world();
    let m = model_of(&f);
    let seen: Vec<(&str, &str, &str)> = m
        .waiting
        .iter()
        .map(|w| (w.kind.as_str(), w.on.as_str(), w.what.as_str()))
        .collect();
    assert_eq!(
        seen,
        [
            ("brief", "h2", "to h2"),
            ("ask", "shep", "which branch?"),
            ("ask", "shep", "ok to rebase?"),
            ("review", "rev", "head c0ffee"),
            ("brief", "h2", "to h2"),
            ("brief", "h1", "to h1"),
        ]
    );
    // oldest first, age counted in events since
    let admitted = m.header.verified;
    for w in &m.waiting {
        assert_eq!(w.age, admitted - w.index);
    }
    assert!(m.waiting.windows(2).all(|p| p[0].index < p[1].index));
    // a draft is named only on the ask that cites one
    assert_eq!(m.waiting[1].draft.as_deref(), Some("work/notes/draft.md"));
    assert_eq!(m.waiting.iter().filter(|w| w.draft.is_some()).count(), 1);
    // the superseded brief of l3 and the finished l4 wait for no one
    let lanes: Vec<_> = m
        .waiting
        .iter()
        .filter(|w| w.kind == "brief")
        .map(|w| w.lane.clone().unwrap())
        .collect();
    assert_eq!(lanes, ["l0", "l2", "l3"]);
}

#[test]
fn nothing_waiting_says_so() {
    let mut f = Fixture::new();
    let shep = f.enroll("shep");
    let _ = shep;
    let app = app_of(&f);
    assert!(app.model().waiting.is_empty());
    assert_eq!(app.wait_selected(), None);
    assert!(screen(&app, 10).contains("nothing is waiting"));
}

#[test]
fn the_waiting_screen() {
    let f = world();
    assert_snapshot("waiting", &screen(&app_of(&f), 12));
}

#[test]
fn the_selection_moves_and_clamps() {
    let f = world();
    let mut app = app_of(&f);
    app.handle(Key::Down);
    app.handle(Key::Down);
    assert_snapshot("waiting_selected", &screen(&app, 12));
    let mut fewer = app.model().clone();
    fewer.waiting.truncate(1);
    app.set_model(fewer);
    assert_eq!(app.wait_selected(), Some(0));
}

#[test]
fn the_tabs_cycle_through_four_views_both_ways() {
    let f = world();
    let mut app = App::new(model_of(&f));
    for want in [Tab::Stream, Tab::Lane, Tab::Waiting, Tab::Board] {
        app.handle(Key::Tab);
        assert_eq!(app.tab(), want);
    }
    for want in [Tab::Waiting, Tab::Lane, Tab::Stream, Tab::Board] {
        app.handle(Key::BackTab);
        assert_eq!(app.tab(), want);
    }
}

fn keys_never_change_the_waiting_rows() -> Named<impl Fn(&Observation<'_>) -> PropertyOutcome> {
    Named::new("a key never changes what waits", |o| match o {
        Observation::Transition { from, to, .. } => {
            let data = |v: &newtui::View| {
                v.rows
                    .iter()
                    .map(|r| (r.label.clone(), r.value.clone(), r.note.clone()))
                    .collect::<Vec<_>>()
            };
            if from.title != "Waiting" || to.title != "Waiting" {
                PropertyOutcome::NotApplicable
            } else if data(from) == data(to) && from.footer == to.footer {
                PropertyOutcome::Held
            } else {
                PropertyOutcome::Violated("a key changed the waiting rows".into())
            }
        }
        Observation::State { .. } => PropertyOutcome::NotApplicable,
    })
}

#[test]
fn every_reachable_state_keeps_the_selection_in_range_and_the_rows_untouched() {
    let f = world();
    let model = model_of(&f);
    let keys = vec![
        Key::Up,
        Key::Down,
        Key::Home,
        Key::End,
        Key::PageUp,
        Key::PageDown,
        Key::Char('r'),
        Key::Char('a'),
        Key::Enter,
        Key::Tab,
        Key::BackTab,
        Key::Char('4'),
    ];
    let report = Explorer::new(keys).explore(
        || {
            let mut app = App::new(model.clone());
            app.handle(Key::Char('4'));
            app
        },
        &[
            &newtui::properties::selection_is_always_in_range(),
            &keys_never_change_the_waiting_rows(),
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
fn no_key_changes_the_log_or_emits_anything() {
    // read-only: the view holds no way to write, and keys leave the model alone
    let f = world();
    let mut app = app_of(&f);
    let before = app.model().clone();
    let admitted = Snapshot::read(f.path()).unwrap().admitted();
    for k in "abcdefghijklmnopqrstuvwxyz0123456789".chars() {
        app.handle(Key::Char(k));
        app.handle(Key::Enter);
    }
    assert_eq!(app.model(), &before);
    assert_eq!(Snapshot::read(f.path()).unwrap().admitted(), admitted);
}
