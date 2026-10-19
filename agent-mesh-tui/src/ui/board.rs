//! The Board tab's state: the selected member and the scroll window.

use std::cell::Cell;

/// Lines a PageUp / PageDown moves.
pub(crate) const PAGE: usize = 10;

#[derive(Default)]
pub(crate) struct BoardState {
    pub selected: usize,
    /// The first member row on screen. Kept between draws so the window only
    /// moves when the selection leaves it; set while drawing, which is where
    /// the height is known.
    pub offset: Cell<usize>,
}

/// The first row to draw when `visible` rows of `len` fit and `selected` must
/// be among them: the same as last time unless the selection (or the roster
/// or the screen) forces the smallest move that brings it in.
pub(crate) fn window(offset: &Cell<usize>, selected: usize, len: usize, visible: usize) -> usize {
    let mut at = offset.get().min(len.saturating_sub(visible));
    if visible > 0 {
        if selected < at {
            at = selected;
        } else if selected >= at + visible {
            at = selected + 1 - visible;
        }
    }
    offset.set(at);
    at
}
