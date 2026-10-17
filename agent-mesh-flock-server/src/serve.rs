//! `amesh flock serve`: the one process that owns the log, serving sessions
//! on a local socket. A session's connection is its life: a connection that
//! ends without `End` records the session `lost`, and the epoch bump that
//! follows uncertifies its key.
//!
//! The socket is the flock owner's local surface (the same user can read the
//! server key file anyway). The SSH stream of step 9 authenticates by a fresh
//! signed challenge instead; nothing here may be read as that.

use crate::wire::{read_msg, write_msg, Req, Resp};
use crate::{CrashPlan, Server, ServerError};
use agent_mesh_flock::EndReason;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;

/// What the connection threads share: the server, and the first failure to
/// persist anything. After such a failure the server refuses everything (it
/// poisons itself), so the loop stops too instead of carrying on half-alive.
struct Shared {
    server: Mutex<Server>,
    fatal: Mutex<Option<String>>,
    path: PathBuf,
}

/// A running server loop.
pub struct Serving {
    shared: Arc<Shared>,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl Serving {
    /// Block until the loop ends: through [`Serving::stop`] from another
    /// thread, or a failure to persist. Returns that failure.
    pub fn wait(mut self) -> Option<String> {
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
        self.failure()
    }

    /// The first failure to persist, if one happened.
    #[must_use]
    pub fn failure(&self) -> Option<String> {
        self.shared
            .fatal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Test-only: arm a crash for the server's next append, as
    /// [`Server::plan_crash`] does.
    pub fn plan_crash(&self, plan: Option<CrashPlan>) {
        lock(&self.shared.server).plan_crash(plan);
    }

    /// Stop accepting, wait for the loop, and release the log.
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _wake = UnixStream::connect(&self.shared.path);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

/// Serve `server` on `listener` in a background thread.
///
/// # Errors
/// The socket's address cannot be read.
pub fn serve(server: Server, listener: UnixListener) -> std::io::Result<Serving> {
    let path = listener
        .local_addr()?
        .as_pathname()
        .map(Path::to_path_buf)
        .ok_or_else(|| std::io::Error::other("unnamed socket"))?;
    let stop = Arc::new(AtomicBool::new(false));
    let shared = Arc::new(Shared {
        server: Mutex::new(server),
        fatal: Mutex::new(None),
        path,
    });
    let (flag, state) = (stop.clone(), shared.clone());
    let join = std::thread::spawn(move || {
        for conn in listener.incoming() {
            if flag.load(Ordering::SeqCst) || failed(&state) {
                break;
            }
            let Ok(conn) = conn else { continue };
            if crate::peer_ok(&conn).is_err() {
                continue;
            }
            let state = state.clone();
            std::thread::spawn(move || connection(&state, conn));
        }
    });
    Ok(Serving {
        shared,
        stop,
        join: Some(join),
    })
}

fn lock(m: &Mutex<Server>) -> MutexGuard<'_, Server> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn failed(s: &Shared) -> bool {
    s.fatal
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .is_some()
}

/// Record a failure to persist and wake the accept loop so it stops.
fn fail(s: &Shared, e: &ServerError) {
    let mut f = s
        .fatal
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    f.get_or_insert_with(|| e.to_string());
    drop(f);
    let _wake = UnixStream::connect(&s.path);
}

/// An error after which the server no longer reflects what was promised.
fn is_fatal(e: &ServerError) -> bool {
    matches!(e, ServerError::Io(_) | ServerError::Poisoned)
}

/// One connection carries at most one session, and its end is that
/// session's end. A goodbye is answered `Ok` only once the end is durable.
fn connection(shared: &Shared, mut conn: UnixStream) {
    let mut bound: Option<String> = None;
    while let Ok(Some(req)) = read_msg::<Req>(&mut conn) {
        let goodbye = matches!(req, Req::End);
        let result = if goodbye {
            bound
                .take()
                .map_or(Ok(()), |s| {
                    lock(&shared.server).end_session(&s, EndReason::Closed)
                })
                .map(|()| Resp::Ok)
        } else {
            handle(&mut lock(&shared.server), req, &mut bound)
        };
        let resp = result.unwrap_or_else(|e| {
            if is_fatal(&e) {
                fail(shared, &e);
            }
            Resp::Err(e.to_string())
        });
        if write_msg(&mut conn, &resp).is_err() || goodbye {
            break;
        }
    }
    if let Some(s) = bound {
        // EOF without `End`: the stream or the process is gone.
        if let Err(e) = lock(&shared.server).end_session(&s, EndReason::Lost) {
            if is_fatal(&e) {
                fail(shared, &e);
            }
        }
    }
}

fn handle(server: &mut Server, req: Req, bound: &mut Option<String>) -> Result<Resp, ServerError> {
    let taken = || ServerError::Session("this connection already carries a session".into());
    Ok(match req {
        Req::Hello => Resp::Hello {
            flock: server.flock(),
            epoch: server.epoch(),
        },
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
        Req::Head { session } => Resp::Head(server.board().head_of(&session)),
        Req::Admit { node, sig } => {
            let r = server.admit(node, sig)?;
            Resp::Admitted {
                index: r.index,
                duplicate: r.duplicate,
            }
        }
        Req::End => Resp::Ok,
    })
}
