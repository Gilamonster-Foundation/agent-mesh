//! A signature says who spoke, not that what they said is safe to print. Any
//! member can put anything in a status, a lane, a job label, a file path or
//! its own name; the screen must show it as inert text and never hand it to
//! the terminal as a command.
#![cfg(unix)]

mod support;

use agent_mesh_flock::{Body, FileRef, Kind};
use agent_mesh_flock_server::Snapshot;
use agent_mesh_tui::model::{fold, Link, Model, Source};
use agent_mesh_tui::ui::{render, App};
use content_addressable::{ContentAddressable as _, RawContentId};
use newtui::{Component as _, Key};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::Rect;
use ratatui::{Terminal, TerminalOptions, Viewport};
use support::Fixture;

/// The reviewer's payload: OSC 52 (set the clipboard) and BEL, a carriage
/// return, a tab, and U+009B (CSI as a single C1 character).
const PAYLOAD: &str = "A\x1b]52;c;Y2xpcGJvYXJk\x07B\rC\tD\u{9b}31mE";

/// What a hostile member carries in every place it can put text.
fn hostile(payload: &str) -> (Fixture, Model) {
    let name = format!("evil{payload}");
    let mut f = Fixture::with_members(&[&name]);
    let shep = f.enroll("shep");
    let h1 = f.enroll("h1");
    let evil = f.enroll(&name);
    let brief = f.emit(
        &shep,
        Kind::Brief,
        &[],
        Body::Brief {
            to: "h1".into(),
            lane: format!("lane{payload}"),
        },
    );
    f.emit(&h1, Kind::Ack, &[("of", brief)], Body::Ack);
    f.emit(
        &h1,
        Kind::Ask,
        &[("about", brief)],
        Body::Ask {
            lane: Some(format!("lane{payload}")),
            text: format!("ask{payload}"),
        },
    );
    // a lane's result cites a file with a hostile path (a root is a plain name, which admission enforces), and a review's
    // head is whatever the shepherd wrote
    f.emit_files(
        &h1,
        Kind::Result,
        &[("brief", brief)],
        Body::Result {
            outcome: agent_mesh_flock::Outcome::Completed,
        },
        vec![FileRef {
            root: "root".into(),
            path: format!("path{payload}"),
            id: RawContentId::from_content(b"x"),
        }],
    );
    f.emit(
        &shep,
        Kind::Review,
        &[],
        Body::Review {
            to: "rev".into(),
            lane: format!("lane{payload}"),
            head: format!("head{payload}"),
        },
    );
    f.emit(
        &evil,
        Kind::Job,
        &[],
        Body::Job {
            lane: "l".into(),
            label: format!("label{payload}"),
        },
    );
    f.emit_files(
        &evil,
        Kind::Status,
        &[],
        Body::Status {
            text: format!("status{payload}"),
        },
        vec![FileRef {
            root: "root".into(),
            path: format!("path{payload}"),
            id: RawContentId::from_content(b"x"),
        }],
    );
    let snap = Snapshot::read(f.path()).unwrap();
    let genesis = agent_mesh_flock_server::load_genesis(f.path())
        .unwrap()
        .node;
    let id = genesis.content_id().unwrap();
    let model = fold(
        &Source::of_snapshot(&format!("flock{payload}"), id, &snap),
        Link::Failed(format!("why{payload}")),
    );
    (f, model)
}

/// Every screen a reader can reach in this flock.
fn screens(model: &Model) -> Vec<(String, String)> {
    let mut out = vec![];
    let mut app = App::new(model.clone());
    let mut shot = |label: &str, app: &App| {
        out.push((label.to_owned(), render::to_text(app, 140, 30)));
    };
    shot("board", &app);
    app.handle(Key::Char('2'));
    shot("stream", &app);
    // each filter set to a hostile value, so the footer shows it
    for key in ['k', 'l', 'm'] {
        for _ in 0..40 {
            app.handle(Key::Char(key));
            let f = app.filters();
            let value = match key {
                'k' => &f.kind,
                'l' => &f.lane,
                _ => &f.member,
            };
            if value.as_deref().is_some_and(|v| v.contains('\u{1b}')) {
                shot(&format!("filter {key}"), &app);
                break;
            }
        }
        app.handle(Key::Char('c'));
    }
    // the raw panel of every event
    app.handle(Key::Home);
    for _ in 0..model.events.len() {
        app.handle(Key::Enter);
        shot("raw", &app);
        app.handle(Key::Esc);
        app.handle(Key::Down);
    }
    // the Lane tab, with the files unchecked and then checked against a root
    // whose name and directory are hostile too
    app.handle(Key::Char('3'));
    shot("lane unchecked", &app);
    let dir = tempfile::tempdir().unwrap();
    let mut roots = agent_mesh_tui::drift::Roots::default();
    roots.insert(&format!("root{PAYLOAD}"), dir.path().to_path_buf());
    app.set_drift(agent_mesh_tui::drift::check_all(&roots, &app.cited_files()));
    shot("lane checked", &app);
    app.handle(Key::Char('4'));
    shot("waiting", &app);
    // a Link that carries text, on both tabs
    let mut unsaved = model.clone();
    unsaved.header.link = Link::Unsaved(format!("cannot save{PAYLOAD}"));
    shot("unsaved", &App::new(unsaved));
    out
}

#[test]
fn no_screen_carries_a_control_character_and_the_escaped_text_is_visible() {
    let (_f, model) = hostile(PAYLOAD);
    for (label, text) in screens(&model) {
        for (n, line) in text.lines().enumerate() {
            assert!(
                !line.chars().any(char::is_control),
                "{label} line {n} carries a control character: {line:?}"
            );
        }
    }
    // and the payload is there, spelled out, where a person can read it
    let all: String = screens(&model).into_iter().map(|(_, t)| t).collect();
    for want in ["\\x1b]52;c;Y2xpcGJvYXJk\\x07", "\\r", "\\t", "\\x9b"] {
        assert!(all.contains(want), "{want} not visible on any screen");
    }
}

/// What the terminal is sent for these screens: the renderer's own escape
/// codes (colours, cursor moves) are the same whatever the text is, so a
/// hostile run must equal a benign run of the same shape, byte for byte in
/// the count of every control byte, and carry no C1 (U+009B is C2 9B).
/// A writer the test can read back after the terminal has taken it.
#[derive(Clone, Default)]
struct Capture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn terminal_bytes(model: &Model) -> Vec<u8> {
    let mut bytes = vec![];
    for tab in ['1', '2', '3', '4'] {
        let mut app = App::new(model.clone());
        app.handle(Key::Char(tab));
        let sink = Capture::default();
        let backend = CrosstermBackend::new(sink.clone());
        let mut term = Terminal::with_options(
            backend,
            TerminalOptions {
                viewport: Viewport::Fixed(Rect::new(0, 0, 140, 30)),
            },
        )
        .unwrap();
        term.draw(|f| render::draw(f, &app)).unwrap();
        drop(term);
        bytes.extend(sink.0.lock().unwrap().iter());
    }
    bytes
}

fn count(bytes: &[u8], b: u8) -> usize {
    bytes.iter().filter(|x| **x == b).count()
}

#[test]
fn the_bytes_sent_to_the_terminal_carry_no_injected_control_sequence() {
    let (_a, hostile_model) = hostile(PAYLOAD);
    // the same shape with harmless text of the same length
    let benign = "x".repeat(PAYLOAD.chars().count());
    let (_b, benign_model) = hostile(&benign);
    let (bad, good) = (
        terminal_bytes(&hostile_model),
        terminal_bytes(&benign_model),
    );
    assert!(
        !bad.is_empty() && count(&good, 0x1b) > 0,
        "the renderer's own escapes exist"
    );
    for b in [0x1b, 0x07, 0x0d, 0x09] {
        // note: the hostile run is *longer* once escaped; the control bytes it
        // contains are the renderer's, exactly as many as the benign run's
        assert_eq!(count(&bad, b), count(&good, b), "control byte {b:#x}");
    }
    assert!(
        !bad.windows(2).any(|w| w == [0xc2, 0x9b]),
        "a C1 CSI reached the terminal"
    );
    // the escaped text spells "]52;" out, but no ESC byte introduces it
    assert!(
        !bad.windows(4).any(|w| w == [0x1b, b']', b'5', b'2']),
        "the OSC 52 introducer reached the terminal as an escape"
    );
}
