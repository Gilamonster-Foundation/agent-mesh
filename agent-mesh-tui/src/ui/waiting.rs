//! The Waiting tab's state: the selected row and the scroll window.

use std::cell::Cell;

#[derive(Default)]
pub(crate) struct WaitState {
    pub selected: usize,
    pub offset: Cell<usize>,
}
