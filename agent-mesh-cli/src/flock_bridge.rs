//! The flock over the mesh (step 9b): a bridge on the home host and an attach
//! proxy on the remote one, both carrying the flock server's own wire (`Req` /
//! `Resp`) inside bus session streams, one stream per local connection.
//!
//! Nothing here signs or decides. The bridge connects each accepted stream to
//! the server's *attach* socket (the remote entry class: its allow-list, no
//! `Invite`); the proxy listens on the socket every flock tool already dials
//! and opens a stream to the home for each connection. Membership is still
//! proved the usual way, by invite token, possession proof and a signature
//! over a fresh stream challenge. The bus's own handshake only says the two
//! hosts belong to the same user.

use agent_mesh_bus::{Bus, IncomingSession, PeerEndpoint, Session, Topic};
use agent_mesh_flock_server::wire::{read_msg, write_msg, Req, Resp, MAX_MESSAGE};
use agent_mesh_flock_server::{load_genesis, SignedGenesis, GENESIS_FILE};
use agent_mesh_protocol::Fingerprint;
use anyhow::{anyhow, bail, Context, Result};
use content_addressable::canonical::to_canonical_dagcbor;
use content_addressable::{ContentAddressable as _, ContentId};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{UnixListener, UnixStream};

/// The bus topic a flock's sessions are served on.
#[must_use]
pub fn topic(user: Fingerprint, flock: &ContentId) -> Topic {
    Topic::new(user, format!("flock/{flock}"))
}

/// Where the home host is.
#[derive(Debug, Clone)]
pub enum Peer {
    /// Dial this endpoint directly.
    Direct(PeerEndpoint),
    /// Find this agent on the local network (mDNS).
    Known(Fingerprint),
}

impl Peer {
    async fn open(&self, bus: &Bus, topic: &Topic) -> Result<Session> {
        Ok(match self {
            Self::Direct(at) => bus.open_session_direct(*at, topic).await?,
            Self::Known(fp) => bus.open_session(*fp, topic).await?,
        })
    }
}

/// One wire message exactly as it is on a socket: `len:u32be | payload`.
/// `None` at a clean end of stream.
async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Vec<u8>>> {
    let mut head = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        match r.read(&mut head[got..]).await? {
            0 if got == 0 => return Ok(None),
            0 => bail!("cut-short message"),
            n => got += n,
        }
    }
    let len = u32::from_be_bytes(head) as usize;
    if len > MAX_MESSAGE {
        bail!("message too large");
    }
    let mut frame = Vec::with_capacity(4 + len);
    frame.extend_from_slice(&head);
    frame.resize(4 + len, 0);
    r.read_exact(&mut frame[4..]).await?;
    Ok(Some(frame))
}

/// A stream body must be exactly one wire message, within the limit: what
/// arrives is written to a socket the server reads with that framing, so
/// anything else would desynchronise it.
fn check_frame(body: &[u8]) -> Result<()> {
    let Some(head) = body.get(..4) else {
        bail!("a stream message shorter than a length prefix");
    };
    let len = u32::from_be_bytes([head[0], head[1], head[2], head[3]]) as usize;
    if len > MAX_MESSAGE || body.len() != 4 + len {
        bail!("a stream message that is not exactly one wire message");
    }
    Ok(())
}

/// Carry wire messages both ways between a local socket and a bus session,
/// one session message per wire message, until either side ends.
async fn pipe(session: Session, conn: UnixStream) -> Result<()> {
    let (tx, mut rx) = session.split();
    let (mut from_socket, mut to_socket) = conn.into_split();
    let up = async move {
        while let Some(frame) = read_frame(&mut from_socket).await? {
            tx.send(frame).await?;
        }
        // the local end is done: say goodbye, which ends the far socket too
        tx.close().await?;
        Ok::<(), anyhow::Error>(())
    };
    let down = async move {
        while let Some(body) = rx.recv().await? {
            check_frame(&body)?;
            to_socket.write_all(&body).await?;
        }
        to_socket.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    };
    tokio::try_join!(up, down)?;
    Ok(())
}

/// Home side: serve this flock's sessions by piping each to the server's
/// attach socket. Registration is synchronous.
pub fn serve_home(bus: &Bus, topic: Topic, attach: PathBuf) {
    bus.handle_sessions(topic, move |incoming: IncomingSession| {
        let attach = attach.clone();
        async move {
            let conn = match UnixStream::connect(&attach).await {
                Ok(c) => c,
                Err(e) => {
                    return incoming
                        .refuse(&format!("the flock is not serving: {e}"))
                        .await
                }
            };
            let session = incoming.accept().await?;
            pipe(session, conn)
                .await
                .map_err(|e| agent_mesh_bus::BusError::SessionProtocol(e.to_string()))
        }
    });
}

/// Remote side: for each connection to `listener`, open a session to the home
/// and pipe. Runs until the listener fails; abort the task to stop it.
///
/// # Errors
/// The listener failed.
pub async fn serve_proxy(
    bus: Arc<Bus>,
    peer: Peer,
    topic: Topic,
    listener: UnixListener,
) -> Result<()> {
    loop {
        let (conn, _) = listener.accept().await?;
        let (bus, peer, topic) = (bus.clone(), peer.clone(), topic.clone());
        tokio::spawn(async move {
            // a failed open (the home refused, is gone) just closes this
            // connection; the client sees an end of stream
            if let Ok(session) = peer.open(&bus, &topic).await {
                let _ = pipe(session, conn).await;
            }
        });
    }
}

/// Ask the home for its genesis over one session.
///
/// # Errors
/// The open or the exchange failed, or the answer is not a genesis.
pub async fn fetch_genesis(bus: &Bus, peer: &Peer, topic: &Topic) -> Result<SignedGenesis> {
    let mut session = peer.open(bus, topic).await?;
    let mut ask = Vec::new();
    write_msg(&mut ask, &Req::Genesis)?;
    session.send(ask).await?;
    let body = session
        .recv()
        .await?
        .ok_or_else(|| anyhow!("the home closed without answering"))?;
    check_frame(&body)?;
    let answer: Option<Resp> = read_msg(&mut body.as_slice())?;
    let _ = session.close().await;
    match answer {
        Some(Resp::Genesis(g)) => Ok(g),
        Some(Resp::Err(why)) => bail!("the home refused: {why}"),
        _ => bail!("the home answered something else"),
    }
}

/// Keep `signed` as `dir`'s genesis, but only if it is the flock `id` names:
/// the id is the out-of-band anchor (like a fingerprint), so a home that
/// answers with any other genesis is refused before anything is written. The
/// file is then re-read through the same check the server uses (its signature
/// by the certificate the genesis itself names).
///
/// # Errors
/// The genesis is not `id`'s, or the directory cannot be written.
pub fn pin_genesis(dir: &Path, id: &ContentId, signed: &SignedGenesis) -> Result<()> {
    let got = signed.node.content_id()?;
    if got != *id {
        bail!("the home's flock is {got}, not the {id} you asked for");
    }
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let path = dir.join(GENESIS_FILE);
    std::fs::write(&path, to_canonical_dagcbor(signed)?)?;
    if let Err(e) = load_genesis(dir) {
        let _ = std::fs::remove_file(&path);
        bail!("the home's genesis does not verify: {e}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn framed(payload: &[u8]) -> Vec<u8> {
        let mut v = (payload.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn a_stream_body_is_exactly_one_wire_message() {
        assert!(check_frame(&framed(b"hello")).is_ok());
        assert!(check_frame(&framed(b"")).is_ok());
        // shorter than a prefix, two messages in one body, a body cut short, one too long
        assert!(check_frame(b"ab").is_err());
        let mut two = framed(b"a");
        two.extend(framed(b"b"));
        assert!(check_frame(&two).is_err());
        let mut cut = framed(b"hello");
        cut.pop();
        assert!(check_frame(&cut).is_err());
        let big = framed(&vec![0; MAX_MESSAGE + 1]);
        assert!(check_frame(&big).is_err());
    }

    #[tokio::test]
    async fn a_frame_is_read_whole_with_its_prefix_and_a_clean_end_is_none() {
        let mut bytes = framed(b"one");
        bytes.extend(framed(b"two"));
        let mut r = bytes.as_slice();
        assert_eq!(read_frame(&mut r).await.unwrap().unwrap(), framed(b"one"));
        assert_eq!(read_frame(&mut r).await.unwrap().unwrap(), framed(b"two"));
        assert!(read_frame(&mut r).await.unwrap().is_none());
        // a cut-short prefix or body is an error, an oversized length too
        assert!(read_frame(&mut &[0u8, 0][..]).await.is_err());
        assert!(read_frame(&mut &framed(b"abc")[..5]).await.is_err());
        let huge = ((MAX_MESSAGE + 1) as u32).to_be_bytes();
        assert!(read_frame(&mut &huge[..]).await.is_err());
    }
}
