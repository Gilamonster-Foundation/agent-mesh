//! Ask the home host for a cited file, and check what comes back. The
//! server's word is never taken for the bytes: they are hashed here and must
//! equal the id the event cited.

use crate::{Prover, ReaderError};
use agent_mesh_flock_server::wire::{read_msg, write_msg, Req, Resp, MAX_FILE};
use content_addressable::RawContentId;
use std::os::unix::net::UnixStream;
use std::path::Path;

/// What the home host found at a cited path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cited {
    /// The bytes, which hash to the cited id (checked here).
    Bytes(Vec<u8>),
    /// The file is there but its bytes are not the cited ones; not served.
    Changed {
        /// What it hashes to now.
        current: RawContentId,
    },
    /// The file cannot be read, and why (unknown root, outside the root, not
    /// a regular file, missing, too large).
    Unavailable(String),
}

/// A connection that has proved its session is a member, and asks for files.
pub struct Files {
    conn: UnixStream,
}

fn bad(why: &str) -> ReaderError {
    ReaderError::Invalid(why.into())
}

impl Files {
    /// Connect to `serve`, have `prove` sign a fresh challenge, and keep the
    /// connection for file requests.
    ///
    /// # Errors
    /// The server refused the proof, or the socket failed.
    pub fn open(serve: &Path, prove: Prover<'_>) -> Result<Self, ReaderError> {
        let mut conn = UnixStream::connect(serve)?;
        write_msg(&mut conn, &Req::WatchBegin)?;
        let Some(Resp::StreamChallenge(ch)) = read_msg::<Resp>(&mut conn)? else {
            return Err(ReaderError::Stream("no challenge".into()));
        };
        let proof = Box::new(prove(&ch)?);
        write_msg(&mut conn, &Req::Prove { proof })?;
        match read_msg::<Resp>(&mut conn)? {
            Some(Resp::Proved) => Ok(Self { conn }),
            Some(Resp::Err(why)) => Err(ReaderError::Stream(why)),
            _ => Err(ReaderError::Stream(
                "the server did not accept the proof".into(),
            )),
        }
    }

    /// What `path` under `root` hashes to now, per the home host (which
    /// re-hashes it: the bytes are not sent), or why it cannot be read.
    ///
    /// # Errors
    /// A broken connection or an answer that is not one to this request.
    pub fn stat(
        &mut self,
        root: &str,
        path: &str,
    ) -> Result<Result<RawContentId, String>, ReaderError> {
        write_msg(
            &mut self.conn,
            &Req::FileStat {
                root: root.into(),
                path: path.into(),
            },
        )?;
        match read_msg::<Resp>(&mut self.conn)? {
            Some(Resp::FileId { id }) => Ok(Ok(id)),
            Some(Resp::Unavailable { reason }) => Ok(Err(reason)),
            Some(Resp::Err(why)) => Err(ReaderError::Stream(why)),
            _ => Err(bad("the server answered something else to a stat")),
        }
    }

    /// The file as cited: its bytes if they hash to `id` (recomputed here),
    /// or the report that they do not.
    ///
    /// # Errors
    /// A broken connection; bytes that do not hash to `id` although the
    /// server said they do; a "changed" report naming the cited id itself; an
    /// answer that is not one to this request.
    pub fn read(
        &mut self,
        root: &str,
        path: &str,
        id: &RawContentId,
    ) -> Result<Cited, ReaderError> {
        write_msg(
            &mut self.conn,
            &Req::File {
                root: root.into(),
                path: path.into(),
                id: id.clone(),
            },
        )?;
        match read_msg::<Resp>(&mut self.conn)? {
            Some(Resp::File { bytes }) => {
                if bytes.len() > MAX_FILE || RawContentId::from_content(&bytes) != *id {
                    return Err(bad("the server sent bytes that are not the cited file"));
                }
                Ok(Cited::Bytes(bytes))
            }
            Some(Resp::ChangedSinceCited { current }) => {
                if current == *id {
                    return Err(bad("the server says the file changed to what was cited"));
                }
                Ok(Cited::Changed { current })
            }
            Some(Resp::Unavailable { reason }) => Ok(Cited::Unavailable(reason)),
            Some(Resp::Err(why)) => Err(ReaderError::Stream(why)),
            _ => Err(bad("the server answered something else to a file request")),
        }
    }
}
