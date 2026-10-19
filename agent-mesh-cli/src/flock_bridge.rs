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
use agent_mesh_flock_server::{
    load_genesis, private_dir, verify_signed_genesis, SignedGenesis, GENESIS_FILE,
};
use agent_mesh_protocol::Fingerprint;
use anyhow::{anyhow, bail, Context, Result};
use content_addressable::canonical::to_canonical_dagcbor;
use content_addressable::{ContentAddressable as _, ContentId};
use std::collections::HashMap;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{UnixListener, UnixStream};

/// The bus topic a flock's sessions are served on.
#[must_use]
pub fn topic(user: Fingerprint, flock: &ContentId) -> Topic {
    Topic::new(user, format!("flock/{flock}"))
}

/// How many streams may be open at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// In all.
    pub total: usize,
    /// From any one peer.
    pub per_peer: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            total: 64,
            per_peer: 16,
        }
    }
}

#[derive(Default)]
struct Open {
    total: usize,
    by_peer: HashMap<String, usize>,
}

/// Counts open streams against [`Limits`]. A stream holds a [`Permit`] for its
/// whole life; dropping it (the stream ended, failed, was refused or its task
/// was cancelled) gives the capacity back. The count is taken *before* the
/// backend is connected or a task spawned, so a same-user peer that is not a
/// flock member cannot allocate more than the limits allow.
pub struct Gate {
    limits: Limits,
    open: Mutex<Open>,
    changed: tokio::sync::Notify,
}

/// One open stream's share of a [`Gate`].
pub struct Permit {
    gate: Arc<Gate>,
    who: String,
}

impl Gate {
    /// A gate with these limits.
    #[must_use]
    pub fn new(limits: Limits) -> Arc<Self> {
        Arc::new(Self {
            limits,
            open: Mutex::new(Open::default()),
            changed: tokio::sync::Notify::new(),
        })
    }

    /// Take a place for `who`, or `None` when the total or `who`'s share is full.
    #[must_use]
    pub fn try_acquire(self: &Arc<Self>, who: &str) -> Option<Permit> {
        let mut open = self.open.lock().unwrap();
        let mine = open.by_peer.get(who).copied().unwrap_or(0);
        if open.total >= self.limits.total || mine >= self.limits.per_peer {
            return None;
        }
        open.total += 1;
        open.by_peer.insert(who.to_owned(), mine + 1);
        Some(Permit {
            gate: self.clone(),
            who: who.to_owned(),
        })
    }

    /// How many streams are open.
    #[must_use]
    pub fn open(&self) -> usize {
        self.open.lock().unwrap().total
    }

    /// Resolve once at most `n` streams are open (immediately if already so).
    pub async fn wait_open_at_most(&self, n: usize) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.open() <= n {
                return;
            }
            changed.await;
        }
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut open = self.gate.open.lock().unwrap();
        open.total = open.total.saturating_sub(1);
        if let Some(n) = open.by_peer.get_mut(&self.who) {
            *n -= 1;
            if *n == 0 {
                open.by_peer.remove(&self.who);
            }
        }
        drop(open);
        self.gate.changed.notify_waiters();
    }
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
/// attach socket, at most `gate` at a time. Registration is synchronous.
pub fn serve_home(bus: &Bus, topic: Topic, attach: PathBuf, gate: Arc<Gate>) {
    bus.handle_sessions(topic, move |incoming: IncomingSession| {
        let (attach, gate) = (attach.clone(), gate.clone());
        async move {
            // capacity first: nothing is connected for a peer over its share
            let Some(_permit) = gate.try_acquire(&incoming.peer().agent_fp.hex()) else {
                return incoming.refuse("too many open sessions").await;
            };
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
/// and pipe, at most `gate` at a time. Runs until the listener fails; abort the
/// task to stop it (its connections stop with it).
///
/// # Errors
/// The listener failed.
pub async fn serve_proxy(
    bus: Arc<Bus>,
    peer: Peer,
    topic: Topic,
    listener: UnixListener,
    gate: Arc<Gate>,
) -> Result<()> {
    // tracked, so a cancelled proxy takes its connections with it
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        while tasks.try_join_next().is_some() {}
        let (conn, _) = listener.accept().await?;
        // over the limit: this connection just ends; nothing is dialled
        let Some(permit) = gate.try_acquire("local") else {
            continue;
        };
        let (bus, peer, topic) = (bus.clone(), peer.clone(), topic.clone());
        tasks.spawn(async move {
            let _permit = permit;
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

/// The checks a genesis from the wire must pass before anything is kept: it
/// is the flock `id` names, and it verifies as a genesis (signed by the very
/// certificate it names). In memory only: nothing on disk is touched.
///
/// # Errors
/// Which check failed.
pub fn check_genesis(id: &ContentId, signed: &SignedGenesis) -> Result<()> {
    let got = signed.node.content_id()?;
    if got != *id {
        bail!("the home's flock is {got}, not the {id} you asked for");
    }
    verify_signed_genesis(signed).map_err(|e| anyhow!("the home's genesis does not verify: {e}"))
}

/// One attached flock directory, owned exclusively for as long as this lives:
/// a private directory (created 0700, or an existing one only if it is ours
/// and closed to others) and a `flock(2)` lock, so two attaches cannot share
/// it and a stale socket can only be replaced by the one that holds it.
pub struct Attachment {
    dir: PathBuf,
    _lock: std::fs::File,
}

impl Attachment {
    /// Take the directory.
    ///
    /// # Errors
    /// The directory is not private, or another attach holds it.
    pub fn open(dir: &Path) -> Result<Self> {
        private_dir(dir).with_context(|| format!("attach directory {}", dir.display()))?;
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            // never through a link: the lock file is ours or it is refused
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits().try_into().unwrap_or(0))
            .open(dir.join("attach.lock"))
            .with_context(|| format!("lock {}", dir.display()))?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| anyhow!("another `attach` already holds {}", dir.display()))?;
        Ok(Self {
            dir: dir.to_path_buf(),
            _lock: lock,
        })
    }

    /// Keep `signed` as this directory's genesis. It has been checked (see
    /// [`check_genesis`]) and is then installed without replacing or following
    /// anything: an existing pin for the same flock is left exactly as it is,
    /// one for another flock, a link, or anything that is not a regular file is
    /// refused, and a new pin goes in through a fresh temporary file, an fsync
    /// of the file, a rename and an fsync of the directory.
    ///
    /// # Errors
    /// The check failed, the directory holds something else, or I/O.
    pub fn pin(&self, id: &ContentId, signed: &SignedGenesis) -> Result<()> {
        check_genesis(id, signed)?;
        let path = self.dir.join(GENESIS_FILE);
        match std::fs::symlink_metadata(&path) {
            Ok(meta) => {
                if !meta.file_type().is_file() {
                    bail!("{} is not a regular file; not touching it", path.display());
                }
                return match load_genesis(&self.dir) {
                    Ok(have) if have.node.content_id()? == *id => Ok(()),
                    Ok(_) => bail!(
                        "{} holds another flock's genesis; not replacing it",
                        self.dir.display()
                    ),
                    Err(e) => bail!(
                        "the genesis in {} does not verify ({e}); not replacing it",
                        self.dir.display()
                    ),
                };
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let tmp = self
            .dir
            .join(format!("{GENESIS_FILE}.new.{}", std::process::id()));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        file.write_all(&to_canonical_dagcbor(signed)?)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, &path)?;
        std::fs::File::open(&self.dir)?.sync_all()?;
        Ok(())
    }
}

/// Check `signed` against `id`, take `dir`, and pin it: nothing is created
/// unless the genesis is the flock `id` names and verifies. The attachment
/// (and its lock) lives as long as the returned value.
///
/// # Errors
/// As [`check_genesis`], [`Attachment::open`] and [`Attachment::pin`].
pub fn pin_genesis(dir: &Path, id: &ContentId, signed: &SignedGenesis) -> Result<Attachment> {
    check_genesis(id, signed)?;
    let att = Attachment::open(dir)?;
    att.pin(id, signed)?;
    Ok(att)
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
