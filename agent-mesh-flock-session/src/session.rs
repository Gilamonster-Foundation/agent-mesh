//! The session: one enrolled key, one connection to the server, one socket
//! for the CLI.

use crate::ctl::{CtlReq, CtlResp};
use crate::{harden, Locked, Policy, SessionError};
use agent_mesh_flock::{Body, Event, Kind};
use agent_mesh_flock_server::wire::{read_msg, write_msg, Req, Resp};
use agent_mesh_protocol::{AgentKey, Assertion};
use content_addressable::{ContentAddressable, ContentId};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use std::collections::BTreeMap;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroizing;

/// An enrolled session. Its connection to the server is its life: dropping
/// it without [`Session::end`] looks to the server like a crash.
pub struct Session {
    key: Locked<AgentKey>,
    conn: UnixStream,
    flock: ContentId,
    member: String,
    session: String,
    pending: bool,
}

impl Session {
    /// Enroll with an invite token: generate a key, prove possession, and
    /// keep the certified key in locked memory.
    ///
    /// # Errors
    /// The server refused, or the key could not be protected.
    pub fn enroll(
        serve: &Path,
        token: &str,
        member: &str,
        policy: Policy,
    ) -> Result<Self, SessionError> {
        let mut conn = UnixStream::connect(serve)?;
        let Resp::Hello { flock, .. } = rpc(&mut conn, &Req::Hello)? else {
            return Err(SessionError::Unexpected);
        };
        let sk = SigningKey::generate(&mut OsRng);
        let seed = Zeroizing::new(sk.to_bytes());
        let begin = Req::EnrollBegin {
            token: token.to_owned(),
            member: member.to_owned(),
            pubkey: sk.verifying_key().to_bytes(),
        };
        let Resp::Challenge(challenge) = rpc(&mut conn, &begin)? else {
            return Err(SessionError::Unexpected);
        };
        let proof = sk.sign(&challenge.signing_bytes());
        let Resp::Enrolled {
            session,
            cert,
            pending,
        } = rpc(&mut conn, &Req::EnrollFinish { challenge, proof })?
        else {
            return Err(SessionError::Unexpected);
        };
        let key = AgentKey::from_seed_and_cert(&seed, cert)
            .map_err(|e| SessionError::Refused(e.to_string()))?;
        Ok(Self {
            key: Locked::new(key, policy)?,
            conn,
            flock,
            member: member.to_owned(),
            session,
            pending,
        })
    }

    /// This session's fingerprint, hex.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.session
    }

    /// Whether the key's memory is actually locked.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.key.is_locked()
    }

    /// Bring the certificate to the current epoch if the server has moved on.
    fn renew(&mut self) -> Result<(), SessionError> {
        let last = self.key.get().cert().clone();
        match rpc(&mut self.conn, &Req::Renew { last })? {
            Resp::Current => Ok(()),
            Resp::Challenge(challenge) => {
                let proof = self.key.get().sign(&challenge.signing_bytes());
                let Resp::Cert(cert) = rpc(&mut self.conn, &Req::RenewFinish { challenge, proof })?
                else {
                    return Err(SessionError::Unexpected);
                };
                let seed = Zeroizing::new(self.key.get().signing_key_bytes());
                let key = AgentKey::from_seed_and_cert(&seed, cert)
                    .map_err(|e| SessionError::Refused(e.to_string()))?;
                self.key = Locked::new(key, self.policy())?;
                Ok(())
            }
            _ => Err(SessionError::Unexpected),
        }
    }

    fn policy(&self) -> Policy {
        if self.key.is_locked() {
            Policy::Locked
        } else {
            Policy::AllowUnlocked
        }
    }

    /// Sign and admit one event as this session.
    ///
    /// # Errors
    /// The server refused it (admission, pending session, ...).
    pub fn emit(
        &mut self,
        kind: Kind,
        refs: BTreeMap<String, ContentId>,
        body: Body,
    ) -> Result<(ContentId, u64), SessionError> {
        self.renew()?;
        let head = Req::Head {
            session: self.session.clone(),
        };
        let Resp::Head(prev) = rpc(&mut self.conn, &head)? else {
            return Err(SessionError::Unexpected);
        };
        let node = Event {
            flock: self.flock,
            kind,
            author: self.session.clone(),
            prev,
            refs,
            files: vec![],
            at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            body,
        }
        .node();
        let event = node
            .content_id()
            .map_err(|e| SessionError::Refused(e.to_string()))?;
        let sig = Assertion::sign(self.key.get(), &event);
        match rpc(&mut self.conn, &Req::Admit { node, sig })? {
            Resp::Admitted { index, .. } => Ok((event, index)),
            _ => Err(SessionError::Unexpected),
        }
    }

    /// A clean goodbye: the server records `closed`, not `lost`.
    ///
    /// # Errors
    /// I/O.
    pub fn end(mut self) -> Result<(), SessionError> {
        rpc(&mut self.conn, &Req::End).map(|_| ())
    }
}

fn rpc(conn: &mut UnixStream, req: &Req) -> Result<Resp, SessionError> {
    write_msg(conn, req)?;
    match read_msg::<Resp>(conn)? {
        Some(Resp::Err(why)) => Err(SessionError::Refused(why)),
        Some(r) => Ok(r),
        None => Err(SessionError::Unexpected),
    }
}

static TERM: AtomicBool = AtomicBool::new(false);

extern "C" fn on_term(_: libc::c_int) {
    TERM.store(true, Ordering::SeqCst);
}

fn catch_term() {
    for sig in [libc::SIGTERM, libc::SIGINT] {
        // SAFETY: a zeroed `sigaction` with a handler that only stores an atomic.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_term as extern "C" fn(libc::c_int) as usize;
            libc::sigemptyset(&mut sa.sa_mask);
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
}

/// Harden the process, enroll, then serve the CLI on `listener` until `End`
/// or SIGTERM/SIGINT. The key is scrubbed when this returns.
///
/// # Errors
/// Hardening or enrollment failed.
pub fn run(
    serve: &Path,
    token: &str,
    member: &str,
    policy: Policy,
    listener: &UnixListener,
    announce: impl FnOnce(&Session),
) -> Result<(), SessionError> {
    harden()?;
    catch_term();
    let mut s = Session::enroll(serve, token, member, policy)?;
    announce(&s);
    listener.set_nonblocking(true)?;
    while !TERM.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((conn, _)) => {
                if agent_mesh_flock_server::peer_ok(&conn).is_ok() && handle(&mut s, conn) {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => wait(listener),
            Err(_) => {}
        }
    }
    s.end()
}

fn wait(listener: &UnixListener) {
    use rustix::event::{poll, PollFd, PollFlags};
    let t = rustix::event::Timespec {
        tv_sec: 0,
        tv_nsec: 250_000_000,
    };
    let _ = poll(&mut [PollFd::new(listener, PollFlags::IN)], Some(&t));
}

/// One request; true when the session should close.
fn handle(s: &mut Session, mut conn: UnixStream) -> bool {
    let _ = conn.set_nonblocking(false);
    let _ = conn.set_read_timeout(Some(std::time::Duration::from_secs(5)));
    let Ok(Some(req)) = read_msg::<CtlReq>(&mut conn) else {
        return false;
    };
    let (resp, close) = match req {
        CtlReq::Whoami => (
            CtlResp::Who {
                flock: s.flock,
                member: s.member.clone(),
                session: s.session.clone(),
                pending: s.pending,
            },
            false,
        ),
        CtlReq::Emit { kind, refs, body } => (
            s.emit(kind, refs, body).map_or_else(
                |e| CtlResp::Err(e.to_string()),
                |(event, index)| CtlResp::Admitted { event, index },
            ),
            false,
        ),
        CtlReq::End => (CtlResp::Ended, true),
    };
    let _ = write_msg(&mut conn, &resp);
    close
}
