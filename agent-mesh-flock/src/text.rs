//! The one place untrusted text becomes safe to print.
//!
//! A valid signature says who spoke, not that their words are harmless: any
//! member can put anything in a status, a lane, a label, a file path or its
//! own name. A terminal acts on control characters (an OSC 52 sets the
//! clipboard, a CSI moves the cursor and recolours), so every string drawn on
//! a screen passes through [`inert`], which spells such characters out. The
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

fn spell(out: &mut String, c: char) {
    match c {
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' => out.push_str("\\t"),
        c if u32::from(c) < 0x100 => {
            let _ = write!(out, "\\x{:02x}", u32::from(c));
        }
        c => {
            let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
        }
    }
}

/// `s` with every such character written out (`\x1b`, `\r`, `\x9b`; beyond
/// U+00FF `\u{2028}`); borrowed unchanged when there is nothing to escape.
#[must_use]
pub fn inert(s: &str) -> Cow<'_, str> {
    if !s.chars().any(needs_escape) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if needs_escape(c) {
            spell(&mut out, c);
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

/// [`inert`] for a block of lines the program itself composed: newlines stay
/// as line breaks. A last line of defence for whole outputs; a field that can
/// hold a newline of its own must already have passed through [`inert`], or the
/// writer could forge a line.
#[must_use]
pub fn inert_lines(s: &str) -> Cow<'_, str> {
    if !s.chars().any(|c| c != '\n' && needs_escape(c)) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if c != '\n' && needs_escape(c) {
            spell(&mut out, c);
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_is_borrowed_unchanged() {
        assert!(matches!(inert("lane-1 · ünïcode ✓"), Cow::Borrowed(_)));
        assert!(matches!(inert_lines("a\nb ✓\n"), Cow::Borrowed(_)));
    }

    #[test]
    fn every_c0_control_and_del_is_spelled_out() {
        for b in (0u8..0x20).chain([0x7f]) {
            let s = format!("a{}b", char::from(b));
            let out = inert(&s);
            assert!(out.chars().all(|c| !c.is_control()), "{b:#x}: {out:?}");
            assert!(out.starts_with('a') && out.ends_with('b'));
        }
        assert_eq!(inert("\x1b]52;c;aGk=\x07"), "\\x1b]52;c;aGk=\\x07");
        assert_eq!(inert("a\nb\rc\td"), "a\\nb\\rc\\td");
    }

    #[test]
    fn c1_controls_including_the_one_character_csi_are_spelled_out() {
        for c in '\u{80}'..='\u{9f}' {
            let one = c.to_string();
            assert_eq!(inert(&one), format!("\\x{:02x}", u32::from(c)));
        }
        assert_eq!(inert("\u{9b}31m"), "\\x9b31m");
    }

    #[test]
    fn separators_zero_width_bidi_and_bom_are_spelled_out() {
        for (c, want) in [
            ('\u{2028}', "\\u{2028}"),
            ('\u{2029}', "\\u{2029}"),
            ('\u{200b}', "\\u{200b}"),
            ('\u{200f}', "\\u{200f}"),
            ('\u{202e}', "\\u{202e}"),
            ('\u{2066}', "\\u{2066}"),
            ('\u{2069}', "\\u{2069}"),
            ('\u{2060}', "\\u{2060}"),
            ('\u{feff}', "\\u{feff}"),
        ] {
            assert_eq!(inert(&format!("x{c}y")), format!("x{want}y"));
        }
    }

    #[test]
    fn nothing_that_needs_escaping_survives() {
        let hostile: String = ('\0'..='\u{ffff}')
            .filter(|c| needs_escape(*c))
            .chain("normal".chars())
            .collect();
        let out = inert(&hostile);
        assert!(!out.chars().any(needs_escape), "{out:?}");
    }

    #[test]
    fn inert_lines_keeps_the_newline_and_nothing_else() {
        assert_eq!(inert_lines("one\n\x1b[2Jtwo\r\n"), "one\n\\x1b[2Jtwo\\r\n");
    }
}
