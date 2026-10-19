//! The views, as newtui components over the model.

mod app;
mod board;
pub mod inert;
mod lane;
pub mod render;
mod stream;
mod waiting;

pub use app::{App, Tab};
pub use stream::Filters;
