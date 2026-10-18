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
    }
}

/// Every key the Board might be sent, not only the navigation set.
fn alphabet() -> Vec<Key> {
    let mut keys = Key::navigation();
    keys.extend([
        Key::Home,
        Key::End,
        Key::PageUp,
        Key::PageDown,
        Key::Tab,
        Key::BackTab,
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
            if data(from) == data(to) && from.title == to.title && from.footer == to.footer {
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
