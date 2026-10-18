//! The views, as newtui components over the model.

mod app;
mod board;
pub mod inert;
pub mod render;
mod stream;

pub use app::{App, Tab};
pub use stream::Filters;
