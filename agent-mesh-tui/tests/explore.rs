//! newtui's explorer walks every state the Board can reach by keys and checks
//! what must always hold. The properties that matter for a read-only view: the
//! selection stays in range, and no key changes what the model says (only
//! which row is selected).
#![cfg(unix)]

use agent_mesh_tui::model::{Header, Link, MemberRow, Model, Open};
use agent_mesh_tui::ui::App;
use newtui::properties::selection_is_always_in_range;
use newtui::{Explorer, Key, Named, Observation, PropertyOutcome};

fn model(n: usize) -> Model {
    Model {
        header: Header {
            flock: "fx".into(),
            short_id: "bafy".into(),
            members: n,
            verified: 7,
            epoch: 0,
            link: Link::Live,
        },
        members: (0..n)
            .map(|i| MemberRow {
                name: format!("m{i}"),
                role: "helper".into(),
                session: "active".into(),
                says: "-".into(),
                open: Open::default(),
                quiet_for: Some(i as u64),
            })
            .collect(),
        events: std::sync::Arc::default(),
        lanes: vec![],
        waiting: vec![],
    }
}

/// Every key the Board might be sent, not only the navigation set, but none
/// that leaves it (Tab and the view numbers are explored with the Stream).
fn alphabet() -> Vec<Key> {
    let mut keys = vec![Key::Up, Key::Down, Key::Left, Key::Right, Key::Enter];
    keys.extend([
        Key::Home,
        Key::End,
        Key::PageUp,
        Key::PageDown,
        Key::Backspace,
        Key::Char('x'),
        Key::Other,
    ]);
    keys
}

/// Between any two states, every row says the same thing; only the selection
/// may differ.
fn keys_never_change_what_the_model_says() -> Named<impl Fn(&Observation<'_>) -> PropertyOutcome> {
    Named::new("a key never changes the displayed data", |o| match o {
        Observation::Transition { from, to, .. } => {
            let data = |v: &newtui::View| {
                v.rows
                    .iter()
                    .map(|r| (r.label.clone(), r.value.clone(), r.note.clone()))
                    .collect::<Vec<_>>()
            };
            if from.title != "Board" || to.title != "Board" {
                PropertyOutcome::NotApplicable
            } else if data(from) == data(to) && from.footer == to.footer {
                PropertyOutcome::Held
            } else {
                PropertyOutcome::Violated("a key changed the rows".into())
            }
        }
        Observation::State { .. } => PropertyOutcome::NotApplicable,
    })
}

#[test]
fn every_reachable_state_keeps_the_selection_in_range_and_the_data_untouched() {
    for n in [1, 3, 25] {
        let report = Explorer::new(alphabet()).explore(
            || App::new(model(n)),
            &[
                &selection_is_always_in_range(),
                &keys_never_change_what_the_model_says(),
            ],
        );
        assert!(report.is_clean(), "{n} members:\n{report}");
        assert!(report.exhausted, "{n} members: the search was capped");
        assert!(
            report.never_applied().is_empty(),
            "{n} members: {:?}",
            report.never_applied()
        );
    }
}

#[test]
fn an_empty_roster_selects_nothing_and_no_key_changes_that() {
    // the range property has nothing to say with no rows (the explorer says so:
    // a property that never applies is reported, not trusted), so check it here
    let report = Explorer::new(alphabet()).explore(
        || App::new(model(0)),
        &[&keys_never_change_what_the_model_says()],
    );
    assert!(report.is_clean() && report.exhausted, "{report}");
    let mut app = App::new(model(0));
    for k in alphabet() {
        newtui::Component::handle(&mut app, k);
        assert_eq!(app.selected(), None);
    }
}

#[test]
fn the_properties_can_fail() {
    // a component that rewrites its rows on a key must be caught
    struct Bad(App, u8);
    impl newtui::Component for Bad {
        fn handle(&mut self, key: Key) -> newtui::Flow {
            self.1 = self.1.wrapping_add(1);
            self.0.handle(key)
        }
        fn view(&self) -> newtui::View {
            let mut v = self.0.view();
            if let Some(r) = v.rows.first_mut() {
                r.value = format!("{}-{}", r.value, self.1);
            }
            v
        }
    }
    let report = Explorer::new(alphabet()).max_states(200).explore(
        || Bad(App::new(model(3)), 0),
        &[&keys_never_change_what_the_model_says()],
    );
    assert!(!report.is_clean(), "the property did not notice");
}

#[test]
fn a_new_model_clamps_the_selection_to_the_roster() {
    use newtui::Component as _;
    let mut app = App::new(model(5));
    for _ in 0..4 {
        app.handle(Key::Down);
    }
    assert_eq!(app.selected(), Some(4));
    app.set_model(model(2));
    assert_eq!(app.selected(), Some(1));
    app.set_model(model(0));
    assert_eq!(app.selected(), None);
}

/// A roster taller than the screen: the selected member must be on it, with
/// the header fixed, however the selection got there and however the screen is
/// resized afterwards.
mod viewport {
    use super::model;
    use agent_mesh_tui::ui::{render, App};
    use newtui::{Component as _, Key};

    fn rows_with(text: &str, name: &str) -> usize {
        text.lines().filter(|l| l.contains(name)).count()
    }

    #[test]
    fn the_selected_member_is_always_on_screen_and_the_header_never_scrolls() {
        let mut app = App::new(model(25));
        // 24 lines: 2 header + 1 column header + 20 rows + 1 footer
        let top = render::to_text(&app, 110, 24);
        assert!(top.contains("m0 ") && !top.contains("m24 "), "{top}");

        app.handle(Key::End);
        let end = render::to_text(&app, 110, 24);
        assert!(
            end.contains("amesh-tui · flock fx"),
            "header scrolled away:\n{end}"
        );
        assert!(end.contains("MEMBER"), "{end}");
        let selected: Vec<&str> = end.lines().filter(|l| l.starts_with('▸')).collect();
        assert_eq!(selected.len(), 1, "{end}");
        assert!(selected[0].contains("m24"), "{end}");
        assert!(!end.contains("m0 "), "the top scrolled off:\n{end}");

        // walking back up keeps the selection visible, and does not move the
        // window until the selection leaves it
        for _ in 0..3 {
            app.handle(Key::Up);
        }
        let up = render::to_text(&app, 110, 24);
        assert!(
            up.lines().any(|l| l.starts_with('▸') && l.contains("m21")),
            "{up}"
        );
        assert!(
            up.contains("m24 "),
            "the window moved with the selection:\n{up}"
        );
    }

    #[test]
    fn a_resize_keeps_the_selection_visible() {
        let mut app = App::new(model(25));
        app.handle(Key::End);
        for height in [24, 9, 7, 40, 12] {
            let text = render::to_text(&app, 110, height);
            assert!(
                text.lines()
                    .any(|l| l.starts_with('▸') && l.contains("m24")),
                "height {height}:\n{text}"
            );
            assert!(text.contains("amesh-tui"), "height {height}");
        }
        // tall enough for everyone: the whole roster is back, from the top
        let all = render::to_text(&app, 110, 40);
        assert_eq!(rows_with(&all, "m0 "), 1);
        assert_eq!(rows_with(&all, "m24 "), 1);
    }
}

// ---- the Stream ----

use agent_mesh_tui::events::{EventRow, Parent};
use newtui::properties::selection_is_always_in_range as in_range;

fn event(i: usize, kind: &str, member: &str, lane: Option<&str>, parents: &[usize]) -> EventRow {
    EventRow {
        index: i as u64 + 1,
        id: format!("bafy{i}"),
        cid: content_addressable::ContentAddressable::content_id(
            &content_addressable::MerkleNode::genesis(format!("e{i}")),
        )
        .unwrap(),
        kind: kind.into(),
        member: member.into(),
        lane: lane.map(str::to_owned),
        summary: format!("s{i}"),
        conflict: false,
        signer: format!("{member}, helper; session ab{i}"),
        at: i as u64,
        parents: parents
            .iter()
            .enumerate()
            .map(|(n, p)| Parent {
                role: if n == 0 { "prev".into() } else { "of".into() },
                id: format!("bafy{p}"),
                row: Some(*p),
            })
            .collect(),
        files: vec![],
        body: vec!["\"ack\"".into()],
        verified: "✓ checked".into(),
    }
}

/// A small log with two kinds, two lanes, two signers and parent links.
fn with_events() -> Model {
    let mut m = model(3);
    m.events = std::sync::Arc::new(vec![
        event(0, "brief", "m0", Some("l1"), &[]),
        event(1, "ack", "m1", Some("l1"), &[0]),
        event(2, "brief", "m0", Some("l2"), &[0]),
        event(3, "ack", "m1", Some("l2"), &[1, 2]),
    ]);
    m
}

/// Whatever the Stream shows is an event the log has: a row for `#n` says the
/// kind and signer that event really has, and a raw panel's parents are the
/// event's own.
fn the_stream_shows_only_what_the_log_holds(
    m: Model,
) -> Named<impl Fn(&Observation<'_>) -> PropertyOutcome> {
    Named::new("the Stream shows only events the log holds", move |o| {
        let view = o.view();
        if view.title != "Stream" {
            return PropertyOutcome::NotApplicable;
        }
        for row in &view.rows {
            let Some(n) = row.label.strip_prefix('#') else {
                continue; // a parent line of the raw panel
            };
            let Some(e) = n
                .parse::<u64>()
                .ok()
                .and_then(|n| m.events.iter().find(|e| e.index == n))
            else {
                return PropertyOutcome::Violated(format!("no event {}", row.label));
            };
            if row.value != e.id && row.value != format!("{} {}", e.kind, e.member) {
                return PropertyOutcome::Violated(format!("{} says {}", row.label, row.value));
            }
        }
        PropertyOutcome::Held
    })
}

fn stream_alphabet() -> Vec<Key> {
    let mut keys = vec![
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
    keys.extend("fklmc1239x".chars().map(Key::Char));
    keys
}

#[test]
fn every_state_the_stream_can_reach_holds_to_the_log() {
    let m = with_events();
    let report = Explorer::new(stream_alphabet())
        .max_states(200_000)
        .max_depth(64)
        .explore(
            || App::new(with_events()),
            &[&in_range(), &the_stream_shows_only_what_the_log_holds(m)],
        );
    assert!(report.is_clean(), "{report}");
    assert!(report.exhausted, "the search was capped: {report}");
    assert!(
        report.never_applied().is_empty(),
        "{:?}",
        report.never_applied()
    );
}
