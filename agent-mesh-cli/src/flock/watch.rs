//! `watch`: the log as it grows, every frame verified and saved before it is
//! shown. The session signs the stream challenge; this process holds no key.

use super::discover::Where;
use super::read::line;
use agent_mesh_flock_server::private_dir;
use agent_mesh_flock_session::{session_prover, Reader, RealFs, Seen};
use anyhow::{anyhow, Context, Result};
use content_addressable::{ContentAddressable as _, MerkleNode};
use std::path::Path;

/// Follow the flock from the reader's saved head. With `from`, first show the
/// saved events from that index on; with `once`, stop when caught up.
pub fn watch(home: &Path, w: &Where, from: Option<u64>, once: bool) -> Result<()> {
    let dir = w.dir(home)?;
    let (socket, me) = w.session(home)?;
    let genesis = agent_mesh_flock_server::load_genesis(&dir)
        .map_err(|e| anyhow!("read the genesis in {}: {e}", dir.display()))?
        .node;
    // The member name is the roster's, an opaque string: never a path. Its
    // content id is one safe, unambiguous component. Both directories must be
    // ours and closed to others (an existing loose one is refused).
    let id = MerkleNode::genesis(me.member.clone())
        .content_id()
        .map_err(|e| anyhow!("name the reader directory: {e}"))?;
    let watch_dir = dir.join("watch");
    let state = watch_dir.join(id.to_string());
    for d in [&watch_dir, &state] {
        private_dir(d).with_context(|| format!("reader directory {}", d.display()))?;
    }
    let mut reader = Reader::open(genesis, &state, RealFs).map_err(|e| anyhow!("{e}"))?;
    if let Some(from) = from {
        for e in reader
            .follower()
            .board()
            .entries()
            .filter(|e| e.index >= from)
        {
            println!("{}", line(e));
        }
    }
    let serve = dir.join("run").join("serve.sock");
    let prove = session_prover(&socket);
    let reason = reader
        .follow(&serve, &prove, once, &mut |seen| match seen {
            Seen::Frame(frame, board) => {
                for s in frame {
                    if let Some(e) = s.event.content_id().ok().and_then(|id| board.get(&id)) {
                        println!("{}", line(e));
                    }
                }
            }
            Seen::Caught(n) => println!("-- caught up at {n} --"),
        })
        .map_err(|e| anyhow!("{e}"))?;
    if once {
        return Ok(());
    }
    Err(anyhow!("the stream closed: {reason}"))
}
