//! The feed: one verified stream from the flock server, authorised by the
//! session process. This crate holds no key and has no emit path: the stream
//! challenge is signed by the session (`ProveStream`), every frame is verified
//! against the saved head by the `Reader`, saved, and only then folded.

use crate::model::{fold, Link, Model, Source};
use agent_mesh_flock_server::load_genesis;
use agent_mesh_flock_session::{
    call, session_prover, CtlReq, CtlResp, Reader, ReaderError, RealFs, Seen,
};
use anyhow::{anyhow, bail, Context, Result};
use content_addressable::{ContentAddressable as _, ContentId, MerkleNode};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};

/// How a run of the feed ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Caught up (`once`).
    Done,
    /// The server closed the stream or it broke; the view is as of the last
    /// verified event.
    Down(String),
    /// Verification or rollback failed. Nothing after this can be trusted.
    Failed(String),
    /// A verified frame could not be saved, so it is not shown: the view stays
    /// at the last saved prefix.
    Unsaved(String),
}

/// An open feed on one flock.
pub struct Feed {
    name: String,
    id: ContentId,
    serve: PathBuf,
    ctl: PathBuf,
    reader: Reader<RealFs>,
}

/// Create `dir` private to this user (0700) and refuse one that is not ours
/// or that others can enter: reader state is a checkpoint file, and a loose
/// directory lets another user replace it.
fn private_dir(dir: &Path) -> Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("create {}", dir.display()))?;
    let meta = std::fs::symlink_metadata(dir)?;
    let me = rustix::process::geteuid().as_raw();
    if !meta.is_dir() || meta.uid() != me || meta.mode() & 0o077 != 0 {
        bail!(
            "{} must be a directory only its owner can enter",
            dir.display()
        );
    }
    Ok(())
}

impl Feed {
    /// Open the flock in `dir` as the session listening on `ctl`. The session
    /// must belong to this flock (a session of another flock is refused before
    /// anything is read), and the reader state lives under
    /// `<dir>/tui/<id of the member's name>/`, never under the name itself.
    ///
    /// # Errors
    /// A bad genesis, a session of another flock, an unusable state directory,
    /// or a reader already running on it.
    pub fn open(dir: &Path, ctl: &Path) -> Result<Self> {
        let genesis: MerkleNode<_> = load_genesis(dir)
            .map_err(|e| anyhow!("read the genesis in {}: {e}", dir.display()))?
            .node;
        let id = genesis.content_id()?;
        let name = genesis.payload.name.clone();
        let CtlResp::Who { flock, member, .. } = call(ctl, &CtlReq::Whoami)? else {
            bail!("the session answered something else");
        };
        if flock != id {
            bail!("{} is a session of another flock", ctl.display());
        }
        let member_dir = MerkleNode::genesis(member).content_id()?.to_string();
        let tui = dir.join("tui");
        let state = tui.join(member_dir);
        private_dir(&tui)?;
        private_dir(&state)?;
        let reader = Reader::open(genesis, &state, RealFs).map_err(|e| anyhow!("{e}"))?;
        Ok(Self {
            name,
            id,
            serve: dir.join("run").join("serve.sock"),
            ctl: ctl.to_owned(),
            reader,
        })
    }

    /// The model as of the last verified event.
    #[must_use]
    pub fn model(&self, link: Link) -> Model {
        fold(
            &Source::of_follower(&self.name, self.id, self.reader.follower()),
            link,
        )
    }

    /// The link to show when the stream is not running.
    #[must_use]
    pub fn stale(&self) -> Link {
        Link::Stale {
            since: self.reader.follower().admitted(),
        }
    }

    /// Follow the server from the saved head, handing `on` a fresh model after
    /// every verified, saved frame and when the replay is caught up. With
    /// `once`, stop when caught up.
    pub fn run(&mut self, once: bool, on: &mut dyn FnMut(Model)) -> Outcome {
        let (name, id) = (self.name.clone(), self.id);
        let prove = session_prover(&self.ctl);
        let mut live = false;
        let result = self.reader.follow(&self.serve, &prove, once, &mut |seen| {
            let follower = match seen {
                Seen::Frame(_, f) => f,
                Seen::Caught(_, f) => {
                    live = true;
                    f
                }
            };
            let link = if live {
                Link::Live
            } else {
                Link::Stale {
                    since: follower.admitted(),
                }
            };
            on(fold(&Source::of_follower(&name, id, follower), link));
        });
        match result {
            Ok(_) if once => Outcome::Done,
            Ok(why) => Outcome::Down(why),
            Err(e @ (ReaderError::Rollback(_) | ReaderError::Invalid(_))) => {
                Outcome::Failed(e.to_string())
            }
            Err(e @ ReaderError::Save(_)) => Outcome::Unsaved(e.to_string()),
            Err(e) => Outcome::Down(e.to_string()),
        }
    }
}
