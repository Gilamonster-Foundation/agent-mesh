//! The one place untrusted text becomes safe to print.
//!
//! A valid signature says who spoke, not that their words are harmless: any
//! member can put anything in a status, a lane, a label, a file path or its
//! own name. A terminal acts on control characters (an OSC 52 sets the
//! clipboard, a CSI moves the cursor and recolours), so every string drawn on
//! the screen passes through [`inert`], which spells such characters out. The
//! canonical data is never changed; only what is drawn.

use std::borrow::Cow;
use std::fmt::Write as _;

/// Characters a terminal or a reader could mistake for something other than
/// text: C0 and DEL (including newline, carriage return, tab, ESC, BEL), C1
/// (including U+009B, CSI as one character), line and paragraph separators,
/// zero-width and bidirectional controls, and the byte-order mark.
fn needs_escape(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2060}'..='\u{2069}'
                | '\u{feff}'
        )
}

/// `s` with every such character written out (`\x1b`, `\r`, `\x9b`; beyond U+00FF `\u{2028}`);
/// borrowed unchanged when there is nothing to escape.
#[must_use]
pub fn inert(s: &str) -> Cow<'_, str> {
    if !s.chars().any(needs_escape) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if needs_escape(c) && u32::from(c) < 0x100 => {
                let _ = write!(out, "\\x{:02x}", u32::from(c));
            }
            c if needs_escape(c) => {
                let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    Cow::Owned(out)
}
