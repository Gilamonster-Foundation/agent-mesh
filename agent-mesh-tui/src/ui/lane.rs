//! The Lane tab's state: the selected lane, its scroll window and a pending
//! request to check the cited files again.

use std::cell::Cell;

#[derive(Default)]
pub(crate) struct LaneState {
    pub selected: usize,
    pub offset: Cell<usize>,
    pub recheck: bool,
}
