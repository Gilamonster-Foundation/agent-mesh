//! `amesh-tui`: a read-only terminal view of a flock.
//!
//! One feed (a verified stream from the flock server, authorised by the
//! session process: this crate holds no key and has no way to write), one pure
//! model folded from it, and views that are functions of the model. Unix only.
#![cfg(unix)]

pub mod events;
pub mod feed;
pub mod keys;
pub mod model;
pub mod ui;
