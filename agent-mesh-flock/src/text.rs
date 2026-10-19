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
/// text: every control (Cc: C0, DEL, C1 including U+009B, CSI as one
/// character), every format character (Cf: zero-width and bidirectional
/// controls, the Arabic letter mark, annotation controls, tag characters, the
/// byte-order mark), and the line and paragraph separators. Variation
/// selectors shape text and are kept.
fn needs_escape(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{00ad}'
                | '\u{0600}'..='\u{0605}'
                | '\u{061c}'
                | '\u{06dd}'
                | '\u{070f}'
                | '\u{0890}'..='\u{0891}'
                | '\u{08e2}'
                | '\u{180e}'
                | '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{206f}'
                | '\u{feff}'
                | '\u{fff9}'..='\u{fffb}'
                | '\u{110bd}'
                | '\u{110cd}'
                | '\u{13430}'..='\u{1343f}'
                | '\u{1bca0}'..='\u{1bca3}'
                | '\u{1d173}'..='\u{1d17a}'
                | '\u{e0001}'
                | '\u{e0020}'..='\u{e007f}'
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

    /// The policy, written out on its own (from the Unicode General_Category
    /// lists for Cc, Cf, Zl and Zp), not derived from `needs_escape`: a class
    /// the implementation forgets is still in this table and fails the sweep.
    /// Variation selectors (Mn) are deliberately absent: they shape text and
    /// do not command a terminal.
    const MUST_ESCAPE: &[(u32, u32)] = &[
        (0x0000, 0x001f), // Cc C0
        (0x007f, 0x009f), // Cc DEL, C1
        (0x00ad, 0x00ad), // Cf soft hyphen
        (0x0600, 0x0605), // Cf Arabic number signs
        (0x061c, 0x061c), // Cf Arabic letter mark
        (0x06dd, 0x06dd), // Cf Arabic end of ayah
        (0x070f, 0x070f), // Cf Syriac abbreviation mark
        (0x0890, 0x0891), // Cf Arabic pound/piastre marks above
        (0x08e2, 0x08e2), // Cf Arabic disputed end of ayah
        (0x180e, 0x180e), // Cf Mongolian vowel separator
        (0x200b, 0x200f), // Cf zero width, LRM, RLM
        (0x2028, 0x2029), // Zl, Zp
        (0x202a, 0x202e), // Cf bidi embeddings and overrides
        (0x2060, 0x2064), // Cf word joiner, invisible operators
        (0x2066, 0x206f), // Cf bidi isolates, deprecated formats
        (0xfeff, 0xfeff), // Cf byte-order mark
        (0xfff9, 0xfffb), // Cf interlinear annotation
        (0x110bd, 0x110bd),
        (0x110cd, 0x110cd),
        (0x13430, 0x1343f), // Cf Egyptian hieroglyph format
        (0x1bca0, 0x1bca3), // Cf shorthand format
        (0x1d173, 0x1d17a), // Cf musical formatting
        (0xe0001, 0xe0001), // Cf language tag
        (0xe0020, 0xe007f), // Cf tag characters
    ];

    #[test]
    fn every_scalar_value_is_escaped_exactly_when_the_policy_says() {
        let mut checked = 0u32;
        for cp in 0..=0x10ffffu32 {
            let Some(c) = char::from_u32(cp) else { continue };
            checked += 1;
            let want = MUST_ESCAPE.iter().any(|&(lo, hi)| (lo..=hi).contains(&cp));
            let one = c.to_string();
            assert_eq!(inert(&one) != one, want, "U+{cp:04X}");
        }
        assert_eq!(checked, 1_112_064);
    }

    #[test]
    fn annotation_and_tag_characters_have_fixed_spellings() {
        for (c, want) in [
            ('\u{061c}', "\\u{61c}"),
            ('\u{fff9}', "\\u{fff9}"),
            ('\u{fffb}', "\\u{fffb}"),
            ('\u{e0001}', "\\u{e0001}"),
            ('\u{e0061}', "\\u{e0061}"),
            ('\u{e007f}', "\\u{e007f}"),
        ] {
            assert_eq!(inert(&format!("x{c}y")), format!("x{want}y"));
        }
        // text-shaping marks are kept
        assert_eq!(inert("a\u{fe0f}\u{e0100}"), "a\u{fe0f}\u{e0100}");
    }

    #[test]
    fn inert_lines_keeps_the_newline_and_nothing_else() {
        assert_eq!(inert_lines("one\n\x1b[2Jtwo\r\n"), "one\n\\x1b[2Jtwo\\r\n");
    }
}
