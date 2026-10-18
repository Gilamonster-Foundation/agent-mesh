//! crossterm key events -> newtui keys.

use newtui::Key;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

/// The newtui key for a terminal key event; releases are ignored.
#[must_use]
pub fn decode(e: &KeyEvent) -> Option<Key> {
    if e.kind == KeyEventKind::Release {
        return None;
    }
    let ctrl = e.modifiers.contains(KeyModifiers::CONTROL);
    Some(match e.code {
        KeyCode::Up => Key::Up,
        KeyCode::Down => Key::Down,
        KeyCode::Left => Key::Left,
        KeyCode::Right => Key::Right,
        KeyCode::Enter => Key::Enter,
        KeyCode::Esc => Key::Esc,
        KeyCode::Backspace => Key::Backspace,
        KeyCode::Tab => Key::Tab,
        KeyCode::BackTab => Key::BackTab,
        KeyCode::Home => Key::Home,
        KeyCode::End => Key::End,
        KeyCode::PageUp => Key::PageUp,
        KeyCode::PageDown => Key::PageDown,
        KeyCode::Char(c) if ctrl => Key::Ctrl(c),
        KeyCode::Char(c) => Key::Char(c),
        _ => Key::Other,
    })
}
