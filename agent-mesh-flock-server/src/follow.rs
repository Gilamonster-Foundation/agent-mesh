//! Following a flock from outside: apply the server's frames one at a time,
//! verifying each exactly as replay does, from a saved head. The follower
//! trusts nothing the server says about itself: a frame that does not extend
//! the head is refused as a rollback, whatever the server claims.

use crate::journal::Head;
use crate::state::{check_frame_shape, State};
use crate::{Chain, Sealed, ServerError, Sessions};
use agent_mesh_flock::{Board, Genesis};
use agent_mesh_protocol::Issuer;
use content_addressable::MerkleNode;

/// Why a frame was refused.
#[derive(Debug, thiserror::Error)]
pub enum FollowError {
    /// The frame does not extend the head: a shorter, rewritten or altered
    /// history.
    #[error("history does not extend the saved head: {0}")]
    DoesNotExtend(String),
    /// The frame extends the head but does not verify.
    #[error("invalid frame: {0}")]
    Invalid(String),
}

/// A verified prefix of a flock, extended frame by frame.
pub struct Follower {
    st: State,
    head: Option<Head>,
}

impl Follower {
    /// Start at genesis.
    ///
    /// # Errors
    /// Encoding failure.
    pub fn new(genesis: &MerkleNode<Genesis>) -> Result<Self, ServerError> {
        let server_pub = genesis.payload.server_cert.agent_pubkey;
        let board = Board::new(genesis).map_err(|e| ServerError::Encoding(e.to_string()))?;
        let Issuer::User(user) = &genesis.payload.server_cert.issuer else {
            return Err(ServerError::Signer(
                "genesis server certificate is not issued by a user key".into(),
            ));
        };
        Ok(Self {
            st: State {
                chain: Chain::new(board.flock(), server_pub, user.clone()),
                board,
                sessions: Sessions::default(),
            },
            head: None,
        })
    }

    /// Verify and apply one frame (all of it or none of it).
    ///
    /// # Errors
    /// [`FollowError::DoesNotExtend`] when it does not link to the head;
    /// [`FollowError::Invalid`] when it links but does not verify.
    pub fn apply(&mut self, frame: &[Sealed]) -> Result<(), FollowError> {
        let first = frame
            .first()
            .ok_or_else(|| FollowError::Invalid("empty frame".into()))?;
        let want = std::iter::once(self.st.chain.prev).collect();
        if first.record.parents != want || first.record.payload.index != self.st.chain.next_index {
            return Err(FollowError::DoesNotExtend(format!(
                "record {} does not follow {}",
                first.record.payload.index,
                self.st.chain.next_index - 1
            )));
        }
        check_frame_shape(frame).map_err(FollowError::Invalid)?;
        let mut next = self.st.clone();
        for s in frame {
            next.replay(s)
                .map_err(|e| FollowError::Invalid(e.to_string()))?;
        }
        self.st = next;
        self.head = frame.last().map(Head::of);
        Ok(())
    }

    /// The signed head: the last record applied (`None` before any).
    #[must_use]
    pub fn head(&self) -> Option<&Head> {
        self.head.as_ref()
    }

    /// The derived board.
    #[must_use]
    pub fn board(&self) -> &Board {
        &self.st.board
    }

    /// The derived session table.
    #[must_use]
    pub fn sessions(&self) -> &Sessions {
        &self.st.sessions
    }

    /// The current epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.st.chain.epoch
    }

    /// How many events are applied.
    #[must_use]
    pub fn admitted(&self) -> u64 {
        self.st.chain.next_index - 1
    }
}
