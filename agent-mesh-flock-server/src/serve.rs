//! `amesh flock serve`: the one process that owns the log, serving sessions
//! on a local socket. A session's connection is its life: a connection that
//! ends without `End` records the session `lost`, and the epoch bump that
//! follows uncertifies its key.
//!
//! The socket is the flock owner's local surface (the same user can read the
//! server key file anyway). The SSH stream of step 9 authenticates by a fresh
//! signed challenge instead; nothing here may be read as that.

use crate::wire::{read_msg, write_msg, Req, Resp};
use crate::{Server, ServerError};
use agent_mesh_flock::EndReason;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;

/// A running server loop.
pub struct Serving {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl Serving {
    /// Block until the loop ends (it ends only through [`Serving::stop`]
    /// from another thread, or with the process).
    pub fn wait(mut self) {
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }

    /// Stop accepting, wait for the loop, and release the log.
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _wake = UnixStream::connect(&self.path);
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
    let shared = Arc::new(Mutex::new(server));
    let flag = stop.clone();
    let join = std::thread::spawn(move || {
        for conn in listener.incoming() {
            if flag.load(Ordering::SeqCst) {
                break;
            }
            let Ok(conn) = conn else { continue };
            if crate::peer_ok(&conn).is_err() {
                continue;
            }
            let shared = shared.clone();
            std::thread::spawn(move || connection(&shared, conn));
        }
    });
    Ok(Serving {
        path,
        stop,
        join: Some(join),
    })
}

fn lock(m: &Mutex<Server>) -> MutexGuard<'_, Server> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn connection(shared: &Mutex<Server>, mut conn: UnixStream) {
    let mut bound: Option<String> = None;
    while let Ok(Some(req)) = read_msg::<Req>(&mut conn) {
        let clean = matches!(req, Req::End);
        let resp = handle(&mut lock(shared), req, &mut bound);
        if clean {
            if let Some(s) = bound.take() {
                let _ = lock(shared).end_session(&s, EndReason::Closed);
            }
        }
        if write_msg(&mut conn, &resp).is_err() || clean {
            break;
        }
    }
    if let Some(s) = bound {
        // EOF without `End`: the stream or the process is gone.
        let _ = lock(shared).end_session(&s, EndReason::Lost);
    }
}

fn handle(server: &mut Server, req: Req, bound: &mut Option<String>) -> Resp {
    let r: Result<Resp, ServerError> = (|| {
        Ok(match req {
            Req::Hello => Resp::Hello {
                flock: server.flock(),
                epoch: server.epoch(),
            },
            Req::Invite { member } => Resp::Invited {
                token: server.invite(&member)?.token,
            },
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
    })();
    r.unwrap_or_else(|e| Resp::Err(e.to_string()))
}
