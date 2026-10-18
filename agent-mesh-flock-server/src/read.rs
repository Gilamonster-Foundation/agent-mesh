//! A read-only view of a flock's admitted log: verified like replay, never
//! locked, never repaired.

use crate::frame::Frame;
use crate::init::{load_genesis, LOG_FILE};
use crate::log::read_frames;
use crate::state::{rebuild, State};
use crate::{ServerError, Sessions};
use agent_mesh_flock::Board;
use std::path::Path;

/// The verified prefix of a flock's log at one moment.
///
/// It never takes the server's lock and writes nothing, so it can run beside
/// a live server. An append in flight is either not yet visible or an
/// incomplete final frame, which is left unread (and reported by
/// [`torn`](Self::torn)); either way what is returned is a whole-frame prefix
/// that replayed clean. Damage inside committed history is an error, as for
/// the server.
pub struct Snapshot {
    st: State,
    torn: bool,
}

impl Snapshot {
    /// Read the flock in `dir`.
    ///
    /// # Errors
    /// Missing or bad genesis; [`ServerError::Corrupt`]; I/O.
    pub fn read(dir: &Path) -> Result<Self, ServerError> {
        let genesis = load_genesis(dir)?;
        let (frames, torn) = read_frames::<Frame>(&dir.join(LOG_FILE))?;
        let st = rebuild(&genesis.node, frames)?;
        Ok(Self { st, torn })
    }

    /// The derived board.
    #[must_use]
    pub fn board(&self) -> &Board {
        &self.st.board
    }

    /// The session table, derived from the log.
    #[must_use]
    pub fn sessions(&self) -> &Sessions {
        &self.st.sessions
    }

    /// How many events are admitted in this prefix.
    #[must_use]
    pub fn admitted(&self) -> u64 {
        self.st.chain.next_index - 1
    }

    /// The epoch at the end of this prefix.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.st.chain.epoch
    }

    /// An incomplete final frame was left unread.
    #[must_use]
    pub fn torn(&self) -> bool {
        self.torn
    }
}
