//! `amesh flock serve`: the one process that owns the log, serving sessions
//! on a local socket. A session's connection is its life: a connection that
//! ends without `End` records the session `lost`, and the epoch bump that
//! follows uncertifies its key.
//!
//! The socket is the flock owner's local surface (the same user can read the
//! server key file anyway). A second socket, the attach socket, is the surface
//! a remote host's bridge connects to; on it only the entries a remote session
//! needs are offered (see [`offered`]) and minting an invite is not one of
//! them. Whoever is on the far end of it proves membership the same way a local
//! session does: an invite token to enroll, a possession proof to renew, a
//! signature over a fresh challenge bound to this flock and connection to
//! watch.

use crate::journal::Cursor;
use crate::wire::{read_msg, write_msg, Req, Resp, StreamChallenge};
use crate::{CrashPlan, Head, Journal, Resume, Server, ServerError};
use agent_mesh_flock::{EndReason, Kind};
use rand::RngCore as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;

/// The epoch after the last operation and the first failure to persist, under
/// ONE mutex with the condvar that announces changes to them. Whoever changes
/// either does so holding that mutex and then notifies, so a waiter that has
/// just evaluated its predicate cannot miss the change (a notification sent
/// between the check and the wait would be lost if they were separate).
struct Signal {
    gate: Mutex<Gate>,
    moved: Condvar,
}

struct Gate {
    epoch: u64,
    failure: Option<String>,
}

impl Signal {
    fn new(epoch: u64) -> Self {
        Self {
            gate: Mutex::new(Gate {
                epoch,
                failure: None,
            }),
            moved: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Gate> {
        self.gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn set_epoch(&self, epoch: u64) {
        self.lock().epoch = epoch;
        self.moved.notify_all();
    }

    /// Record the first failure. Returns whether this call recorded it.
    fn fail(&self, why: String) {
        let mut g = self.lock();
        g.failure.get_or_insert(why);
        drop(g);
        self.moved.notify_all();
    }

    fn failure(&self) -> Option<String> {
        self.lock().failure.clone()
    }

    /// Block until the epoch reaches `n` (true) or a failure is recorded
    /// (false). `checked` runs once per evaluation of a false predicate, with
    /// the mutex held, between the check and the wait: tests use it to land
    /// a change in exactly that window.
    fn wait_epoch(&self, n: u64, mut checked: impl FnMut()) -> bool {
        let mut g = self.lock();
        while g.epoch < n && g.failure.is_none() {
            checked();
            g = self
                .moved
                .wait(g)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        g.epoch >= n
    }
}

/// What the connection threads share: the server, and the first failure to
/// persist anything. After such a failure the server refuses everything (it
/// poisons itself), so the loop stops too instead of carrying on half-alive.
struct Shared {
    server: Mutex<Server>,
    /// The published log: streams read it without the server's lock.
    journal: Arc<Journal>,
    /// Every socket being served, so a stop can wake each accept loop.
    paths: Vec<PathBuf>,
    /// The epoch and the first failure, with their condvar.
    signal: Signal,
    /// Every connection thread, so a stop can join them all.
    conns: Mutex<Vec<JoinHandle<()>>>,
    /// A duplicate of every open connection, so a stop can cut them. A
    /// connection removes its own when it ends, so that closing it really
    /// closes the socket (a duplicate keeps it open).
    socks: Mutex<std::collections::HashMap<u64, UnixStream>>,
    next_id: std::sync::atomic::AtomicU64,
    /// How many connection threads are running, with the condvar that
    /// announces it falling.
    live: Mutex<usize>,
    live_cv: Condvar,
}

/// Counts one running connection thread; ends it on drop.
struct Live(Arc<Shared>);

impl Live {
    fn new(s: &Arc<Shared>) -> Self {
        *s.live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) += 1;
        Self(s.clone())
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        *self
            .0
            .live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) -= 1;
        self.0.live_cv.notify_all();
    }
}

/// A running server loop.
pub struct Serving {
    shared: Arc<Shared>,
    stop: Arc<AtomicBool>,
    joins: Vec<JoinHandle<()>>,
}

/// What the attach socket answers to a request it does not offer.
pub(crate) const NOT_OFFERED: &str = "not offered on the attach socket";

/// Whether `class` may make `req`. Written as one arm per request and no
/// wildcard on the remote side, so a request added to the protocol will not
/// compile until someone decides whether a remote host may make it.
///
/// A remote host's bridge may: say hello, fetch genesis, enroll with an invite
/// token, renew with a possession proof, ask for a session's head, admit events
/// a session signed, open a stream with a signed challenge, and say goodbye. It
/// may not mint invites: that is the owner's alone.
fn offered(class: Class, req: &Req) -> bool {
    if class == Class::Owner {
        return true;
    }
    match req {
        Req::Hello => true,
        Req::Genesis => true,
        Req::EnrollBegin { .. } => true,
        Req::EnrollFinish { .. } => true,
        Req::Renew { .. } => true,
        Req::RenewFinish { .. } => true,
        Req::Head { .. } => true,
        Req::Admit { .. } => true,
        Req::End => true,
        Req::WatchBegin => true,
        Req::Watch { .. } => true,
        Req::Invite { .. } => false,
    }
}

/// Which surface a connection came in on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    /// The owner's socket: everything.
    Owner,
    /// The attach socket: what a remote host's session needs, nothing more.
    Remote,
}

impl Serving {
    /// Block until the loop ends: through [`Serving::stop`] from another
    /// thread, or a failure to persist. Returns that failure.
    pub fn wait(mut self) -> Option<String> {
        for j in self.joins.drain(..) {
            let _ = j.join();
        }
        self.shared.journal.stop();
        end_connections(&self.shared);
        self.failure()
    }

    /// Block until the epoch is at least `n`, or the server has failed.
    /// Returns whether the epoch got there. Causal: woken by the operation
    /// that moves it.
    pub fn wait_epoch(&self, n: u64) -> bool {
        self.shared.signal.wait_epoch(n, || {})
    }

    /// Test-only: how many connection threads are running.
    #[doc(hidden)]
    #[must_use]
    pub fn live_connections(&self) -> usize {
        *self
            .shared
            .live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Test-only: block until at most `n` connection threads are running.
    #[doc(hidden)]
    pub fn wait_connections_at_most(&self, n: usize) {
        let mut g = self
            .shared
            .live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while *g > n {
            g = self
                .shared
                .live_cv
                .wait(g)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    /// The first failure to persist, if one happened.
    #[must_use]
    pub fn failure(&self) -> Option<String> {
        self.shared.signal.failure()
    }

    /// Test-only: arm a crash for the server's next append, as
    /// [`Server::plan_crash`] does.
    pub fn plan_crash(&self, plan: Option<CrashPlan>) {
        lock(&self.shared.server).plan_crash(plan);
    }

    /// Test-only: run `f` on the served server (an administration primitive
    /// that has no wire request yet, such as `handoff`).
    #[doc(hidden)]
    pub fn with_server<T>(&self, f: impl FnOnce(&mut Server) -> T) -> T {
        with(&self.shared, f)
    }

    /// Stop accepting, end every connection, and release the log: when this
    /// returns the log's lock is free.
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for p in &self.shared.paths {
            let _wake = UnixStream::connect(p);
        }
        for j in self.joins.drain(..) {
            let _ = j.join();
        }
        self.shared.journal.stop();
        end_connections(&self.shared);
    }
}

/// Serve `server` on `listener` in a background thread.
///
/// # Errors
/// The socket's address cannot be read.
pub fn serve(server: Server, listener: UnixListener) -> std::io::Result<Serving> {
    start(server, vec![(listener, Class::Owner)])
}

/// [`serve`], and also the attach socket: the surface for a remote host's
/// bridge. Both are served by the same server and stop together.
///
/// # Errors
/// A socket's address cannot be read.
pub fn serve_with_attach(
    server: Server,
    owner: UnixListener,
    attach: UnixListener,
) -> std::io::Result<Serving> {
    start(server, vec![(owner, Class::Owner), (attach, Class::Remote)])
}

fn start(server: Server, listeners: Vec<(UnixListener, Class)>) -> std::io::Result<Serving> {
    let mut paths = Vec::new();
    for (l, _) in &listeners {
        paths.push(
            l.local_addr()?
                .as_pathname()
                .map(Path::to_path_buf)
                .ok_or_else(|| std::io::Error::other("unnamed socket"))?,
        );
    }
    let stop = Arc::new(AtomicBool::new(false));
    let signal = Signal::new(server.epoch());
    let journal = server.journal();
    let shared = Arc::new(Shared {
        server: Mutex::new(server),
        journal,
        paths,
        signal,
        conns: Mutex::new(Vec::new()),
        socks: Mutex::new(std::collections::HashMap::new()),
        next_id: std::sync::atomic::AtomicU64::new(0),
        live: Mutex::new(0),
        live_cv: Condvar::new(),
    });
    let joins = listeners
        .into_iter()
        .map(|(listener, class)| {
            let (flag, state) = (stop.clone(), shared.clone());
            std::thread::spawn(move || accept_loop(&listener, class, &flag, &state))
        })
        .collect();
    Ok(Serving {
        shared,
        stop,
        joins,
    })
}

fn accept_loop(listener: &UnixListener, class: Class, flag: &AtomicBool, state: &Arc<Shared>) {
    for conn in listener.incoming() {
        if flag.load(Ordering::SeqCst) || failed(state) {
            break;
        }
        let Ok(conn) = conn else { continue };
        if crate::peer_ok(&conn).is_err() {
            continue;
        }
        let Ok(mine) = conn.try_clone() else { continue };
        let id = state
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        state
            .socks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id, mine);
        // counted before the thread starts, so a count read after accept
        // cannot miss it
        let live = Live::new(state);
        let handle = std::thread::spawn(move || {
            connection(&live.0, conn, class, id);
        });
        let mut conns = state
            .conns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        conns.retain(|h| !h.is_finished());
        conns.push(handle);
    }
}

fn lock(m: &Mutex<Server>) -> MutexGuard<'_, Server> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Run `f` on the server, then publish the epoch it left.
fn with<T>(s: &Shared, f: impl FnOnce(&mut Server) -> T) -> T {
    let mut server = lock(&s.server);
    let out = f(&mut server);
    publish(s, &server);
    out
}

fn failed(s: &Shared) -> bool {
    s.signal.failure().is_some()
}

/// Shut every connection and wait for its thread, so nothing still holds the
/// server (and so its log lock) afterwards.
fn end_connections(s: &Shared) {
    let socks: Vec<UnixStream> = s
        .socks
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .values()
        .filter_map(|c| c.try_clone().ok())
        .collect();
    for stream in socks {
        let _ = stream.shutdown(std::net::Shutdown::Both);
    }
    let conns = std::mem::take(
        &mut *s
            .conns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    );
    for handle in conns {
        let _ = handle.join();
    }
}

/// Publish the epoch after an operation, while still holding the server.
fn publish(s: &Shared, server: &Server) {
    s.signal.set_epoch(server.epoch());
}

/// Record a failure to persist and wake the accept loop so it stops.
fn fail(s: &Shared, e: &ServerError) {
    s.signal.fail(e.to_string());
    for p in &s.paths {
        let _wake = UnixStream::connect(p);
    }
}

/// An error after which the server no longer reflects what was promised.
fn is_fatal(e: &ServerError) -> bool {
    matches!(e, ServerError::Io(_) | ServerError::Poisoned)
}

/// One connection carries at most one session, and its end is that
/// session's end. A goodbye is answered `Ok` only once the end is durable.
fn connection(shared: &Shared, mut conn: UnixStream, class: Class, id: u64) {
    serve_connection(shared, &mut conn, class);
    // The server keeps a duplicate of every connection so `stop` can cut them,
    // so dropping this handle does not close the socket: the peer would never
    // see the end it is waiting for (a bridge would hold the connection, and
    // its place, forever). Close it for every holder.
    let _ = conn.shutdown(std::net::Shutdown::Both);
    // and drop the duplicate, so this is the last handle: the socket closes
    // whatever the platform does with a shutdown after the peer's
    shared
        .socks
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(&id);
}

fn serve_connection(shared: &Shared, conn: &mut UnixStream, class: Class) {
    let mut bound: Option<String> = None;
    let mut challenge: Option<StreamChallenge> = None;
    while let Ok(Some(req)) = read_msg::<Req>(conn) {
        if !offered(class, &req) {
            if write_msg(conn, &Resp::Err(NOT_OFFERED.into())).is_err() {
                break;
            }
            continue;
        }
        match req {
            Req::WatchBegin => {
                let mut nonce = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut nonce);
                let ch = StreamChallenge {
                    flock: with(shared, |s| s.flock()),
                    nonce,
                };
                challenge = Some(ch.clone());
                if write_msg(conn, &Resp::StreamChallenge(ch)).is_err() {
                    break;
                }
                continue;
            }
            Req::Watch { from, proof } => {
                // the challenge is spent whatever happens: one try per connection
                let opened = challenge
                    .take()
                    .ok_or_else(|| ServerError::Session("ask for a stream challenge first".into()))
                    .and_then(|c| c.id())
                    .and_then(|id| with(shared, |s| s.authorize_stream(&proof, &id)));
                match opened {
                    Ok(session) => stream(shared, conn, &session, from.as_ref()),
                    Err(e) => {
                        let _ = write_msg(conn, &Resp::Err(e.to_string()));
                    }
                }
                break;
            }
            req => {
                if !step(shared, conn, req, &mut bound, class) {
                    break;
                }
                continue;
            }
        }
    }
    if let Some(s) = bound {
        // EOF without `End`: the stream or the process is gone.
        if let Err(e) = with(shared, |srv| srv.end_session(&s, EndReason::Lost)) {
            if is_fatal(&e) {
                fail(shared, &e);
            }
        }
    }
}

/// One ordinary request; false when the connection should end.
fn step(
    shared: &Shared,
    conn: &mut UnixStream,
    req: Req,
    bound: &mut Option<String>,
    class: Class,
) -> bool {
    let goodbye = matches!(req, Req::End);
    let result = if goodbye {
        bound
            .take()
            .map_or(Ok(()), |s| {
                with(shared, |srv| srv.end_session(&s, EndReason::Closed))
            })
            .map(|()| Resp::Ok)
    } else {
        with(shared, |srv| handle(srv, req, bound, class))
    };
    let resp = result.unwrap_or_else(|e| {
        if is_fatal(&e) {
            fail(shared, &e);
        }
        Resp::Err(e.to_string())
    });
    write_msg(conn, &resp).is_ok() && !goodbye
}

/// Serve the frames after `from`, replay then live, until the session's own
/// end or the journal stops. Nothing here takes the server's lock.
fn stream(shared: &Shared, conn: &mut UnixStream, session: &str, from: Option<&Head>) {
    let mut cursor = match shared.journal.cursor_from(from) {
        Ok(c) => c,
        Err(Resume::Behind { have }) => {
            let _ = write_msg(conn, &Resp::Behind { have });
            return;
        }
        Err(_) => {
            let _ = write_msg(conn, &Resp::Diverged);
            return;
        }
    };
    // A peer that goes away must end this worker even though nothing is ever
    // published: watch the socket for its end and cancel the cursor's wait.
    let canceller = cursor.canceller();
    let Ok(mut peer) = conn.try_clone() else {
        return;
    };
    let watcher = std::thread::spawn(move || {
        let mut sink = [0u8; 256];
        while matches!(std::io::Read::read(&mut peer, &mut sink), Ok(n) if n > 0) {}
        canceller.cancel();
    });
    stream_frames(shared, conn, session, &mut cursor);
    // the loop is over: closing wakes the watcher if it still waits
    let _ = conn.shutdown(std::net::Shutdown::Both);
    let _ = watcher.join();
}

fn stream_frames(shared: &Shared, conn: &mut UnixStream, session: &str, cursor: &mut Cursor) {
    let replay_end = shared.journal.len();
    // Eligibility is re-checked at epoch boundaries from the frame on, not
    // for history before this session existed.
    let from_index = with(shared, |s| s.session_start_index(session)).unwrap_or(0);
    let mut caught = false;
    let mut at = cursor.delivered();
    loop {
        if !caught && at >= replay_end {
            caught = true;
            if write_msg(conn, &Resp::Caught { index: at }).is_err() {
                return;
            }
        }
        let Some((frame, eligible)) = cursor.next_frame() else {
            let _ = write_msg(
                conn,
                &Resp::Closed {
                    reason: "the server stopped".into(),
                },
            );
            return;
        };
        at = frame.last().map_or(at, |s| s.record.payload.index);
        let bump = frame.iter().any(|s| s.event.payload.kind == Kind::Epoch);
        let over = bump && at >= from_index && !eligible.contains(session);
        if write_msg(conn, &Resp::Frame(frame.to_vec())).is_err() {
            return;
        }
        if over {
            let _ = write_msg(
                conn,
                &Resp::Closed {
                    reason: "your session ended or its member left the roster".into(),
                },
            );
            return;
        }
    }
}

fn handle(
    server: &mut Server,
    req: Req,
    bound: &mut Option<String>,
    _class: Class,
) -> Result<Resp, ServerError> {
    let taken = || ServerError::Session("this connection already carries a session".into());
    Ok(match req {
        Req::Hello => Resp::Hello {
            flock: server.flock(),
            epoch: server.epoch(),
        },
        Req::Genesis => Resp::Genesis(server.signed_genesis().clone()),
        Req::Invite { member } => Resp::Invited {
            token: server.invite(&member)?.token,
        },
        Req::EnrollBegin { .. } | Req::EnrollFinish { .. } if bound.is_some() => {
            return Err(taken());
        }
        Req::EnrollBegin {
            token,
            member,
            pubkey,
        } => Resp::Challenge(server.enroll_begin(&token, &member, pubkey)?),
        Req::EnrollFinish { challenge, proof } => {
            let e = server.enroll_finish(&challenge, &proof)?;
            *bound = Some(e.session.clone());
            Resp::Enrolled {
                session: e.session,
                cert: e.cert,
                pending: e.pending,
            }
        }
        Req::Renew { last } => {
            let session = last.agent_fingerprint().hex();
            match server.sessions().get(&session) {
                Some(i) if i.epoch >= server.epoch() => Resp::Current,
                _ => Resp::Challenge(server.renew_begin(&last)?),
            }
        }
        Req::RenewFinish { challenge, proof } => {
            Resp::Cert(server.renew_finish(&challenge, &proof)?)
        }
        Req::Head { session } => Resp::Head(server.sessions().chain_head(server.board(), &session)),
        Req::Admit { node, sig } => {
            let r = server.admit(node, sig)?;
            Resp::Admitted {
                index: r.index,
                duplicate: r.duplicate,
            }
        }
        Req::End => Resp::Ok,
        Req::WatchBegin | Req::Watch { .. } => {
            return Err(ServerError::Session(
                "a stream is opened by the connection".into(),
            ))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::Signal;

    /// The waiter has evaluated its predicate (no failure yet) and is about
    /// to wait; a failure lands in exactly that window. It must return false
    /// on that failure alone: no further operation, no timeout. With the
    /// failure kept apart from the waiter's mutex the notification is lost
    /// and this test never returns.
    #[test]
    fn a_failure_landing_between_the_check_and_the_wait_wakes_the_waiter() {
        let sig = std::sync::Arc::new(Signal::new(0));
        let mut landed = None;
        let reached = sig.wait_epoch(1, || {
            let s = sig.clone();
            landed.get_or_insert_with(|| std::thread::spawn(move || s.fail("disk gone".into())));
        });
        assert!(!reached);
        landed.unwrap().join().unwrap();
        assert_eq!(sig.failure().as_deref(), Some("disk gone"));
    }

    #[test]
    fn an_epoch_already_reached_returns_at_once() {
        assert!(Signal::new(2).wait_epoch(1, || panic!("must not wait")));
    }
}
