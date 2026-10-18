//! Golden screens: a real flock on disk, folded, drawn to a text buffer and
//! compared with `tests/snapshots/<name>.txt` (`UPDATE_SNAPSHOTS=1` rewrites).
#![cfg(unix)]

mod support;

use agent_mesh_flock_server::Snapshot;
use agent_mesh_tui::model::{fold, Link, Source};
use agent_mesh_tui::ui::{render, App};
use content_addressable::ContentAddressable as _;
use newtui::{Component as _, Key};
use support::{assert_snapshot, busy, mask_id};

fn screen(app: &App) -> String {
    mask_id(&render::to_text(app, 100, 12))
}

fn busy_app(link: Link) -> App {
    let (f, _) = busy();
    let snap = Snapshot::read(f.path()).unwrap();
    let genesis = agent_mesh_flock_server::load_genesis(f.path())
        .unwrap()
        .node;
    let id = genesis.content_id().unwrap();
    let name = genesis.payload.name.clone();
    App::new(fold(&Source::of_snapshot(&name, id, &snap), link))
}

#[test]
fn the_board_of_a_busy_flock() {
    assert_snapshot("board", &screen(&busy_app(Link::Live)));
}

#[test]
fn the_selection_moves_and_shows() {
    let mut app = busy_app(Link::Live);
    app.handle(Key::Down);
    app.handle(Key::Down);
    assert_snapshot("board_selected", &screen(&app));
}

#[test]
fn a_stale_feed_says_since_when() {
    let app = busy_app(Link::Stale { since: 9 });
    assert_snapshot("board_stale", &screen(&app));
}

#[test]
fn a_failed_verification_is_marked_and_says_why() {
    let app = busy_app(Link::Failed(
        "history does not extend the saved head".into(),
    ));
    assert_snapshot("board_failed", &screen(&app));
}
