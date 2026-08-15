//! Bus [`Transport`] adapter for AgentKey-authenticated SSH sessions.
//!
//! The loopback TCP listener treats every accepted socket as untrusted.  It
//! cannot emit [`Inbound`] until [`UnauthenticatedMeshSession::authenticate`]
//! has verified a fresh mutual proof and returned authenticated typestate.

use crate::error::{Result, SshTransportError};
use crate::process::{OpenSshClient, SshTarget, UnauthenticatedSshCarrier};
use crate::session::{
    AuthenticatedSessionReader, AuthenticatedSessionWriter, SessionParameters, SessionTimeouts,
    UnauthenticatedMeshSession,
};
use agent_mesh_bus::{
    AuthenticatedPeer, BusError, DeliveryProvenance, Inbound, PeerEndpoint, ReplyRoute, Transport,
};
use agent_mesh_protocol::{AgentKey, Fingerprint, SignedEnvelope};
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
#[cfg(test)]
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch, Mutex as AsyncMutex, Notify, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;

type BoxReader = Box<dyn AsyncRead + Send + Unpin + 'static>;
type BoxWriter = Box<dyn AsyncWrite + Send + Unpin + 'static>;
type SessionReader = AuthenticatedSessionReader<BoxReader>;
type SessionWriter = AuthenticatedSessionWriter<BoxWriter>;

const DEFAULT_MAX_SESSIONS: usize = 64;
const DEFAULT_INBOUND_CAPACITY: usize = 256;
const PROCESS_EXIT_GRACE: Duration = Duration::from_secs(1);
const SESSION_SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// Resource, trust-context, and deadline policy for [`SshTransport`].
#[derive(Debug, Clone)]
pub struct SshTransportOptions {
    /// Generation context bound into the inner handshake.
    pub session_parameters: SessionParameters,
    /// One overall authentication deadline and one per-record deadline.
    pub session_timeouts: SessionTimeouts,
    /// Combined cap for authenticating and established inbound/outbound
    /// sessions owned by this transport.
    pub max_sessions: usize,
    /// Bounded queue between authenticated session readers and the bus.
    pub inbound_capacity: usize,
}

impl Default for SshTransportOptions {
    fn default() -> Self {
        Self {
            session_parameters: SessionParameters::new(None),
            session_timeouts: SessionTimeouts::default(),
            max_sessions: DEFAULT_MAX_SESSIONS,
            inbound_capacity: DEFAULT_INBOUND_CAPACITY,
        }
    }
}

#[derive(Clone)]
enum Dialer {
    OpenSsh(Arc<OpenSshClient>),
    #[cfg(test)]
    Loopback,
}

struct SshReplyRoute {
    peer: AuthenticatedPeer,
    writer: Arc<AsyncMutex<SessionWriter>>,
    alive: AtomicBool,
    closed: Notify,
}

impl SshReplyRoute {
    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    fn mark_dead(&self) {
        if self.alive.swap(false, Ordering::AcqRel) {
            self.closed.notify_waiters();
        }
    }

    async fn dead(&self) {
        if !self.is_alive() {
            return;
        }
        let notified = self.closed.notified();
        if !self.is_alive() {
            return;
        }
        notified.await;
    }
}

type OutboundSessions = Arc<AsyncMutex<HashMap<Fingerprint, Arc<SshReplyRoute>>>>;

/// Poison an established writer if its record future is ever cancelled.
///
/// `AsyncWriteExt::write_all` is not cancellation-safe: cancellation can leave
/// a prefix or body fragment on the stream. The next counter must never resume
/// after that point, so only a fully completed record disarms this guard.
struct RouteWriteAttempt<'a> {
    route: &'a SshReplyRoute,
    completed: bool,
}

impl<'a> RouteWriteAttempt<'a> {
    fn new(route: &'a SshReplyRoute) -> Self {
        Self {
            route,
            completed: false,
        }
    }

    fn complete(&mut self) {
        self.completed = true;
    }
}

impl Drop for RouteWriteAttempt<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.route.mark_dead();
        }
    }
}

/// SSH-backed implementation of the bus transport seam.
///
/// Outbound routes are explicit: a mesh agent fingerprint maps to one
/// [`SshTarget`]. The fingerprint is also required by the inner handshake, so
/// a sibling agent under the same user root cannot silently answer for it.
pub struct SshTransport {
    agent: Arc<AgentKey>,
    options: SshTransportOptions,
    dialer: Dialer,
    targets: RwLock<HashMap<Fingerprint, SshTarget>>,
    inbound_rx: AsyncMutex<mpsc::Receiver<Inbound>>,
    inbound_tx: mpsc::Sender<Inbound>,
    local_addr: SocketAddr,
    session_slots: Arc<Semaphore>,
    outbound_sessions: OutboundSessions,
    outbound_connect: AsyncMutex<()>,
    shutdown_tx: watch::Sender<bool>,
    accept_task: Mutex<Option<JoinHandle<()>>>,
    session_tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl SshTransport {
    /// Bind a loopback listener and use the system OpenSSH client for outbound
    /// carriers.
    pub async fn bind(
        agent: Arc<AgentKey>,
        listen_addr: SocketAddr,
        options: SshTransportOptions,
    ) -> Result<Self> {
        let client = OpenSshClient::system()?;
        Self::bind_with_dialer(
            agent,
            listen_addr,
            options,
            Dialer::OpenSsh(Arc::new(client)),
        )
        .await
    }

    /// Bind with an explicitly selected OpenSSH executable.
    pub async fn bind_with_client(
        agent: Arc<AgentKey>,
        listen_addr: SocketAddr,
        options: SshTransportOptions,
        client: OpenSshClient,
    ) -> Result<Self> {
        Self::bind_with_dialer(
            agent,
            listen_addr,
            options,
            Dialer::OpenSsh(Arc::new(client)),
        )
        .await
    }

    async fn bind_with_dialer(
        agent: Arc<AgentKey>,
        listen_addr: SocketAddr,
        options: SshTransportOptions,
        dialer: Dialer,
    ) -> Result<Self> {
        if !listen_addr.ip().is_loopback() {
            return Err(SshTransportError::InvalidConfig(
                "SSH mesh listener must bind a loopback address".into(),
            ));
        }
        if options.max_sessions == 0 || options.inbound_capacity == 0 {
            return Err(SshTransportError::InvalidConfig(
                "max_sessions and inbound_capacity must be non-zero".into(),
            ));
        }
        if options.max_sessions > Semaphore::MAX_PERMITS
            || options.inbound_capacity > Semaphore::MAX_PERMITS
        {
            return Err(SshTransportError::InvalidConfig(format!(
                "max_sessions and inbound_capacity must not exceed {}",
                Semaphore::MAX_PERMITS
            )));
        }
        if options.session_timeouts.authentication.is_zero()
            || options.session_timeouts.record.is_zero()
        {
            return Err(SshTransportError::InvalidConfig(
                "authentication and record timeouts must be non-zero".into(),
            ));
        }
        verify_cert(
            agent.cert(),
            options.session_parameters.current_generation(),
        )?;

        let listener = TcpListener::bind(listen_addr).await?;
        let local_addr = listener.local_addr()?;
        let (inbound_tx, inbound_rx) = mpsc::channel(options.inbound_capacity);
        let session_slots = Arc::new(Semaphore::new(options.max_sessions));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let session_tasks = Arc::new(Mutex::new(Vec::new()));

        let accept_task = tokio::spawn(run_accept_loop(
            listener,
            agent.clone(),
            options.clone(),
            inbound_tx.clone(),
            session_slots.clone(),
            shutdown_rx,
            session_tasks.clone(),
        ));

        Ok(Self {
            agent,
            options,
            dialer,
            targets: RwLock::new(HashMap::new()),
            inbound_rx: AsyncMutex::new(inbound_rx),
            inbound_tx,
            local_addr,
            session_slots,
            outbound_sessions: Arc::new(AsyncMutex::new(HashMap::new())),
            outbound_connect: AsyncMutex::new(()),
            shutdown_tx,
            accept_task: Mutex::new(Some(accept_task)),
            session_tasks,
        })
    }

    /// Add or replace the SSH route for an exact mesh agent fingerprint.
    pub fn add_target(&self, peer: Fingerprint, target: SshTarget) {
        self.targets
            .write()
            .expect("SSH target map poisoned")
            .insert(peer, target);
    }

    /// Remove an outbound SSH route.
    pub fn remove_target(&self, peer: &Fingerprint) {
        self.targets
            .write()
            .expect("SSH target map poisoned")
            .remove(peer);
    }

    /// Loopback address that `sshd` must forward its `direct-tcpip` channel to.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    #[cfg(test)]
    async fn bind_loopback_for_test(
        agent: Arc<AgentKey>,
        options: SshTransportOptions,
    ) -> Result<Self> {
        Self::bind_with_dialer(
            agent,
            "127.0.0.1:0".parse().expect("literal address"),
            options,
            Dialer::Loopback,
        )
        .await
    }

    async fn send_over_session(&self, peer_fp: Fingerprint, env: SignedEnvelope) -> Result<()> {
        let mut shutdown = self.shutdown_tx.subscribe();
        if *shutdown.borrow_and_update() {
            return Err(SshTransportError::Closed);
        }
        let target = self
            .targets
            .read()
            .expect("SSH target map poisoned")
            .get(&peer_fp)
            .cloned()
            .ok_or_else(|| SshTransportError::PeerMismatch {
                expected: peer_fp.hex(),
                actual: "no configured SSH target".into(),
            })?;

        if let Some(route) = self.cached_outbound(peer_fp).await {
            let result = self.send_on_route(&route, &env).await;
            if result.is_err() {
                self.remove_cached_outbound(peer_fp, &route).await;
            }
            return result;
        }

        // Serialize cache misses so concurrent first sends cannot create many
        // redundant OpenSSH processes. Established per-peer writers bypass
        // this lock and remain independently serialized by their own mutexes.
        let _connect = tokio::select! {
            _ = shutdown.changed() => return Err(SshTransportError::Closed),
            lock = self.outbound_connect.lock() => lock,
        };
        if *self.shutdown_tx.borrow() {
            return Err(SshTransportError::Closed);
        }
        if let Some(route) = self.cached_outbound(peer_fp).await {
            let result = self.send_on_route(&route, &env).await;
            if result.is_err() {
                self.remove_cached_outbound(peer_fp, &route).await;
            }
            return result;
        }

        let permit = tokio::time::timeout(
            self.options.session_timeouts.authentication,
            self.session_slots.clone().acquire_owned(),
        )
        .await
        .map_err(|_| SshTransportError::Timeout {
            stage: "waiting for an SSH session slot".into(),
        })?
        .map_err(|_| SshTransportError::Closed)?;
        if *self.shutdown_tx.borrow() {
            return Err(SshTransportError::Closed);
        }

        let (reader, writer, mut process) = self.open_carrier(&target).await?;
        if *self.shutdown_tx.borrow() {
            return Err(SshTransportError::Closed);
        }
        let pending = UnauthenticatedMeshSession::initiator(
            reader,
            writer,
            self.agent.clone(),
            peer_fp,
            self.options.session_parameters.clone(),
            self.options.session_timeouts,
        );
        let authenticated = tokio::select! {
            _ = shutdown.changed() => return Err(SshTransportError::Closed),
            result = pending.authenticate() => result,
        };
        let mut session = match authenticated {
            Ok(session) => session,
            Err(error) => {
                return Err(match process.take() {
                    Some(carrier) => {
                        carrier
                            .fail_inner_auth(error.to_string(), PROCESS_EXIT_GRACE)
                            .await
                    }
                    None => SshTransportError::InnerAuth {
                        message: error.to_string(),
                        stderr: String::new(),
                    },
                });
            }
        };
        if session.peer().agent_fp != peer_fp {
            return Err(SshTransportError::PeerMismatch {
                expected: peer_fp.hex(),
                actual: session.peer().agent_fp.hex(),
            });
        }
        if *self.shutdown_tx.borrow() {
            return Err(SshTransportError::Closed);
        }
        let sent = tokio::select! {
            _ = shutdown.changed() => return Err(SshTransportError::Closed),
            result = session.send_envelope(&env) => result,
        };
        if let Err(error) = sent {
            if let Some(carrier) = process.take() {
                let process_error = carrier
                    .finish(
                        format!("session record send failed: {error}"),
                        PROCESS_EXIT_GRACE,
                    )
                    .await;
                if matches!(&process_error, SshTransportError::ProcessExit { .. }) {
                    return Err(process_error);
                }
                tracing::warn!(error = %process_error, "ssh child terminated after record failure");
            }
            return Err(SshTransportError::Frame(error.to_string()));
        }

        if *self.shutdown_tx.borrow() {
            return Err(SshTransportError::Closed);
        }
        if !self
            .spawn_authenticated_reader(session, process, permit, true)
            .await
        {
            return Err(SshTransportError::Closed);
        }
        Ok(())
    }

    async fn cached_outbound(&self, peer_fp: Fingerprint) -> Option<Arc<SshReplyRoute>> {
        let route = self.outbound_sessions.lock().await.get(&peer_fp).cloned();
        match route {
            Some(route) if route.is_alive() => Some(route),
            Some(route) => {
                self.remove_cached_outbound(peer_fp, &route).await;
                None
            }
            None => None,
        }
    }

    async fn remove_cached_outbound(&self, peer_fp: Fingerprint, route: &Arc<SshReplyRoute>) {
        let mut sessions = self.outbound_sessions.lock().await;
        if sessions
            .get(&peer_fp)
            .is_some_and(|current| Arc::ptr_eq(current, route))
        {
            sessions.remove(&peer_fp);
        }
    }

    async fn send_on_route(&self, route: &SshReplyRoute, env: &SignedEnvelope) -> Result<()> {
        let mut shutdown = self.shutdown_tx.subscribe();
        if *shutdown.borrow_and_update() || !route.is_alive() {
            return Err(SshTransportError::Closed);
        }
        let operation = tokio::time::timeout(self.options.session_timeouts.record, async {
            let mut attempt = RouteWriteAttempt::new(route);
            let mut writer = route.writer.lock().await;
            if !route.is_alive() {
                return Err(SshTransportError::Closed);
            }
            writer
                .send_envelope(env)
                .await
                .map_err(|error| SshTransportError::Frame(error.to_string()))?;
            attempt.complete();
            Ok(())
        });
        let result = tokio::select! {
            _ = shutdown.changed() => {
                route.mark_dead();
                return Err(SshTransportError::Closed);
            }
            result = operation => result,
        };
        match result {
            Ok(result) => result,
            Err(_) => Err(SshTransportError::Timeout {
                stage: "waiting for or writing an authenticated session record".into(),
            }),
        }
    }

    async fn open_carrier(
        &self,
        target: &SshTarget,
    ) -> Result<(BoxReader, BoxWriter, Option<UnauthenticatedSshCarrier>)> {
        match &self.dialer {
            Dialer::OpenSsh(client) => {
                let mut carrier = client.connect(target).await?;
                let reader: BoxReader = Box::new(carrier.take_reader()?);
                let writer: BoxWriter = Box::new(carrier.take_writer()?);
                Ok((reader, writer, Some(carrier)))
            }
            #[cfg(test)]
            Dialer::Loopback => {
                let stream = tokio::time::timeout(
                    self.options.session_timeouts.authentication,
                    TcpStream::connect((target.mesh_host(), target.mesh_port())),
                )
                .await
                .map_err(|_| SshTransportError::Timeout {
                    stage: "loopback carrier connect".into(),
                })??;
                let (reader, writer) = stream.into_split();
                Ok((Box::new(reader), Box::new(writer), None))
            }
        }
    }

    async fn spawn_authenticated_reader(
        &self,
        session: crate::session::AuthenticatedMeshSession<BoxReader, BoxWriter>,
        process: Option<UnauthenticatedSshCarrier>,
        permit: OwnedSemaphorePermit,
        cache_outbound: bool,
    ) -> bool {
        let (reader, writer) = session.into_split();
        let peer = reader.peer();
        let route = Arc::new(SshReplyRoute {
            peer,
            writer: Arc::new(AsyncMutex::new(writer)),
            alive: AtomicBool::new(true),
            closed: Notify::new(),
        });
        let outbound_sessions = cache_outbound.then(|| self.outbound_sessions.clone());
        if let Some(sessions) = &outbound_sessions {
            sessions.lock().await.insert(peer.agent_fp, route.clone());
        }
        let shutdown = self.shutdown_tx.subscribe();
        let task = tokio::spawn(run_session_reader(
            reader,
            route.clone(),
            process,
            permit,
            self.inbound_tx.clone(),
            shutdown.clone(),
            outbound_sessions.clone(),
        ));
        if let Err(task) = track_task(&self.session_tasks, task, &shutdown) {
            task.abort();
            let _ = task.await;
            route.mark_dead();
            if let Some(sessions) = outbound_sessions {
                let mut sessions = sessions.lock().await;
                if sessions
                    .get(&peer.agent_fp)
                    .is_some_and(|current| Arc::ptr_eq(current, &route))
                {
                    sessions.remove(&peer.agent_fp);
                }
            }
            return false;
        }
        true
    }
}

#[async_trait]
impl Transport for SshTransport {
    async fn send_to(&self, fp: Fingerprint, env: SignedEnvelope) -> agent_mesh_bus::Result<()> {
        self.send_over_session(fp, env).await.map_err(backend_error)
    }

    async fn send_to_endpoint(
        &self,
        peer: &PeerEndpoint,
        env: SignedEnvelope,
    ) -> agent_mesh_bus::Result<()> {
        // `PeerEndpoint::addr` is an Iroh/UDP location. SSH uses only its
        // authenticated fingerprint to select a separately configured target.
        self.send_over_session(peer.fingerprint(), env)
            .await
            .map_err(backend_error)
    }

    async fn reply(
        &self,
        fp: Fingerprint,
        route: &ReplyRoute,
        env: SignedEnvelope,
    ) -> agent_mesh_bus::Result<()> {
        if *self.shutdown_tx.borrow() {
            return Err(backend_error(SshTransportError::Closed));
        }
        if let Some(route) = route
            .as_ref()
            .downcast_ref::<SshReplyRoute>()
            .filter(|route| route.peer.agent_fp == fp && route.is_alive())
        {
            // A failed record write may have delivered a prefix or body. Do
            // not retry that ambiguous envelope on another connection and
            // risk duplicate delivery. Routes already known stale, foreign,
            // or from another backend fall through before any write attempt.
            return self.send_on_route(route, &env).await.map_err(backend_error);
        }

        tracing::debug!(peer = %fp.short(), "SSH reply route unavailable; opening configured target");
        self.send_over_session(fp, env).await.map_err(backend_error)
    }

    async fn recv(&self) -> Option<Inbound> {
        let mut shutdown = self.shutdown_tx.subscribe();
        if *shutdown.borrow_and_update() {
            return None;
        }
        let mut inbound = self.inbound_rx.lock().await;
        tokio::select! {
            value = inbound.recv() => value,
            _ = shutdown.changed() => None,
        }
    }

    fn local_port(&self) -> u16 {
        self.local_addr.port()
    }

    async fn close(&self) {
        self.shutdown_tx.send_replace(true);
        self.session_slots.close();
        let cached = std::mem::take(&mut *self.outbound_sessions.lock().await);
        for route in cached.values() {
            route.mark_dead();
        }
        drop(cached);
        let accept_task = {
            self.accept_task
                .lock()
                .expect("SSH accept task lock poisoned")
                .take()
        };
        if let Some(task) = accept_task {
            task.abort();
            let _ = task.await;
        }
        let tasks = std::mem::take(
            &mut *self
                .session_tasks
                .lock()
                .expect("SSH session task lock poisoned"),
        );
        let deadline = tokio::time::Instant::now() + SESSION_SHUTDOWN_GRACE;
        for mut task in tasks {
            if tokio::time::timeout_at(deadline, &mut task).await.is_err() {
                task.abort();
                let _ = task.await;
            }
        }
    }
}

impl Drop for SshTransport {
    fn drop(&mut self) {
        self.shutdown_tx.send_replace(true);
        self.session_slots.close();
        if let Ok(mut sessions) = self.outbound_sessions.try_lock() {
            for route in sessions.values() {
                route.mark_dead();
            }
            sessions.clear();
        }
        if let Some(task) = self
            .accept_task
            .lock()
            .expect("SSH accept task lock poisoned")
            .take()
        {
            task.abort();
        }
        for task in std::mem::take(
            &mut *self
                .session_tasks
                .lock()
                .expect("SSH session task lock poisoned"),
        ) {
            task.abort();
        }
    }
}

async fn run_accept_loop(
    listener: TcpListener,
    agent: Arc<AgentKey>,
    options: SshTransportOptions,
    inbound_tx: mpsc::Sender<Inbound>,
    session_slots: Arc<Semaphore>,
    mut shutdown: watch::Receiver<bool>,
    session_tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
) {
    loop {
        if *shutdown.borrow() {
            break;
        }
        let (stream, source) = tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(error) => {
                    tracing::warn!(error = %error, "SSH loopback listener accept failed");
                    continue;
                }
            },
        };
        let permit = match session_slots.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                tracing::warn!(source = %source, "SSH session limit reached; rejecting carrier");
                continue;
            }
        };
        let agent = agent.clone();
        let options = options.clone();
        let inbound_tx = inbound_tx.clone();
        let mut task_shutdown = shutdown.clone();
        let task = tokio::spawn(async move {
            if *task_shutdown.borrow() {
                return;
            }
            let (reader, writer) = stream.into_split();
            let pending = UnauthenticatedMeshSession::responder(
                Box::new(reader) as BoxReader,
                Box::new(writer) as BoxWriter,
                agent,
                options.session_parameters,
                options.session_timeouts,
            );
            let authenticated = tokio::select! {
                _ = task_shutdown.changed() => return,
                result = pending.authenticate() => result,
            };
            match authenticated {
                Ok(session) => {
                    let (reader, writer) = session.into_split();
                    let peer = reader.peer();
                    let route = Arc::new(SshReplyRoute {
                        peer,
                        writer: Arc::new(AsyncMutex::new(writer)),
                        alive: AtomicBool::new(true),
                        closed: Notify::new(),
                    });
                    run_session_reader(
                        reader,
                        route,
                        None,
                        permit,
                        inbound_tx,
                        task_shutdown,
                        None,
                    )
                    .await;
                }
                Err(error) => {
                    tracing::warn!(source = %source, error = %error, "SSH inner authentication rejected");
                }
            }
        });
        if let Err(task) = track_task(&session_tasks, task, &shutdown) {
            task.abort();
            let _ = task.await;
            break;
        }
    }
}

async fn run_session_reader(
    mut reader: SessionReader,
    route: Arc<SshReplyRoute>,
    process: Option<UnauthenticatedSshCarrier>,
    _permit: OwnedSemaphorePermit,
    inbound_tx: mpsc::Sender<Inbound>,
    mut shutdown: watch::Receiver<bool>,
    outbound_sessions: Option<OutboundSessions>,
) {
    let peer = reader.peer();
    let ending = loop {
        if *shutdown.borrow() {
            break "transport closed".to_string();
        }
        let envelope = tokio::select! {
            _ = shutdown.changed() => break "transport closed".to_string(),
            _ = route.dead() => break "session writer closed".to_string(),
            result = reader.recv_envelope() => match result {
                Ok(envelope) => envelope,
                Err(error) => break error.to_string(),
            },
        };
        let inbound = Inbound {
            envelope,
            provenance: DeliveryProvenance::Direct { carrier: peer },
            reply_route: route.clone(),
        };
        tokio::select! {
            result = inbound_tx.send(inbound) => {
                if result.is_err() {
                    break "bus inbound receiver closed".to_string();
                }
            }
            _ = shutdown.changed() => break "transport closed".to_string(),
            _ = route.dead() => break "session writer closed".to_string(),
        }
    };

    route.mark_dead();
    if let Some(sessions) = outbound_sessions {
        let mut sessions = sessions.lock().await;
        if sessions
            .get(&peer.agent_fp)
            .is_some_and(|current| Arc::ptr_eq(current, &route))
        {
            sessions.remove(&peer.agent_fp);
        }
    }
    drop(route);
    if let Some(carrier) = process {
        let error = carrier.finish(ending, PROCESS_EXIT_GRACE).await;
        match &error {
            SshTransportError::ProcessExit {
                status: Some(0), ..
            } => tracing::debug!(peer = %peer.agent_fp.short(), %error, "SSH child/session ended"),
            _ => tracing::warn!(peer = %peer.agent_fp.short(), %error, "SSH child/session ended"),
        }
    }
}

fn track_task(
    tasks: &Arc<Mutex<Vec<JoinHandle<()>>>>,
    task: JoinHandle<()>,
    shutdown: &watch::Receiver<bool>,
) -> std::result::Result<(), JoinHandle<()>> {
    let mut tasks = tasks.lock().expect("SSH session task lock poisoned");
    if *shutdown.borrow() {
        return Err(task);
    }
    tasks.retain(|task| !task.is_finished());
    tasks.push(task);
    Ok(())
}

fn verify_cert(cert: &agent_mesh_protocol::CertChain, generation: Option<u64>) -> Result<()> {
    match generation {
        Some(generation) => cert.verify_at(generation)?,
        None => cert.verify()?,
    }
    Ok(())
}

fn backend_error(error: SshTransportError) -> BusError {
    BusError::TransportBackend(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::HostKeyPolicy;
    use crate::session::AuthenticatedMeshSession;
    use agent_mesh_bus::{Bus, BusMessage, CorrelationId, Inbox, Topic};
    use agent_mesh_protocol::{AgentMetadata, Caveats, Recipient, UserKey};
    use tempfile::TempDir;

    fn agent(user: &UserKey, role: &str) -> Arc<AgentKey> {
        Arc::new(AgentKey::issue(
            user,
            AgentMetadata {
                role: role.into(),
                host: "ssh-test".into(),
                capabilities: vec!["test".into()],
                issued_at: "2026-08-14T00:00:00Z".into(),
                expires_at: None,
                caveats: Caveats::top(),
            },
        ))
    }

    struct TargetFixture {
        _dir: TempDir,
        target: SshTarget,
    }

    fn target(mesh_port: u16) -> TargetFixture {
        let dir = tempfile::tempdir().expect("temp target files");
        let identity = dir.path().join("id_ed25519");
        let known_hosts = dir.path().join("known_hosts");
        std::fs::write(&identity, b"test-only placeholder").unwrap();
        std::fs::write(&known_hosts, b"test-only placeholder").unwrap();
        let target = SshTarget::new(
            "newtmesh",
            "127.0.0.1",
            22,
            "127.0.0.1",
            mesh_port,
            identity,
            HostKeyPolicy::Pinned {
                known_hosts_file: known_hosts,
            },
        )
        .expect("valid loopback fixture");
        TargetFixture { _dir: dir, target }
    }

    async fn authenticated_pair(
        initiator: Arc<AgentKey>,
        responder: Arc<AgentKey>,
    ) -> (
        AuthenticatedMeshSession<
            tokio::io::ReadHalf<tokio::io::DuplexStream>,
            tokio::io::WriteHalf<tokio::io::DuplexStream>,
        >,
        AuthenticatedMeshSession<
            tokio::io::ReadHalf<tokio::io::DuplexStream>,
            tokio::io::WriteHalf<tokio::io::DuplexStream>,
        >,
    ) {
        let (left, right) = tokio::io::duplex(128 * 1024);
        let (left_read, left_write) = tokio::io::split(left);
        let (right_read, right_write) = tokio::io::split(right);
        let parameters = SessionParameters::new(None);
        let timeouts = SessionTimeouts::default();
        let left = UnauthenticatedMeshSession::initiator(
            left_read,
            left_write,
            initiator,
            responder.fingerprint(),
            parameters.clone(),
            timeouts,
        );
        let right = UnauthenticatedMeshSession::responder(
            right_read,
            right_write,
            responder,
            parameters,
            timeouts,
        );
        tokio::try_join!(left.authenticate(), right.authenticate()).expect("mutual authentication")
    }

    async fn boxed_authenticated_pair(
        initiator: Arc<AgentKey>,
        responder: Arc<AgentKey>,
    ) -> (
        AuthenticatedMeshSession<BoxReader, BoxWriter>,
        AuthenticatedMeshSession<BoxReader, BoxWriter>,
    ) {
        let (left, right) = tokio::io::duplex(128 * 1024);
        let (left_read, left_write) = tokio::io::split(left);
        let (right_read, right_write) = tokio::io::split(right);
        let parameters = SessionParameters::new(None);
        let timeouts = SessionTimeouts::default();
        let left = UnauthenticatedMeshSession::initiator(
            Box::new(left_read) as BoxReader,
            Box::new(left_write) as BoxWriter,
            initiator,
            responder.fingerprint(),
            parameters.clone(),
            timeouts,
        );
        let right = UnauthenticatedMeshSession::responder(
            Box::new(right_read) as BoxReader,
            Box::new(right_write) as BoxWriter,
            responder,
            parameters,
            timeouts,
        );
        tokio::try_join!(left.authenticate(), right.authenticate()).expect("mutual authentication")
    }

    fn reply_envelope(
        signer: &AgentKey,
        recipient: Fingerprint,
        sequence: u64,
        correlation: CorrelationId,
        body: &[u8],
    ) -> SignedEnvelope {
        let payload = serde_json::to_vec(&BusMessage::Reply {
            correlation: correlation.0,
            body: body.to_vec(),
        })
        .unwrap();
        SignedEnvelope::new(
            signer,
            Recipient::Direct {
                agent_fp: recipient,
            },
            sequence,
            payload,
        )
    }

    #[tokio::test]
    async fn bus_request_reply_roundtrip_over_authenticated_ssh_carrier() {
        let user = UserKey::generate();
        let alice = agent(&user, "alice");
        let bob = agent(&user, "bob");
        let options = SshTransportOptions {
            max_sessions: 1,
            ..SshTransportOptions::default()
        };

        let alice_transport = Arc::new(
            SshTransport::bind_loopback_for_test(alice.clone(), options.clone())
                .await
                .unwrap(),
        );
        let bob_transport = Arc::new(
            SshTransport::bind_loopback_for_test(bob.clone(), options)
                .await
                .unwrap(),
        );
        let bob_target = target(bob_transport.local_port());
        alice_transport.add_target(bob.fingerprint(), bob_target.target.clone());

        let alice_bus =
            Bus::bind_with_transport(alice.clone(), alice_transport.clone() as Arc<dyn Transport>)
                .unwrap();
        let bob_bus =
            Bus::bind_with_transport(bob.clone(), bob_transport.clone() as Arc<dyn Transport>)
                .unwrap();
        let topic = Topic::new(user.fingerprint(), "ssh-inner-echo");
        let (context_tx, context_rx) = tokio::sync::oneshot::channel();
        let context_tx = Arc::new(Mutex::new(Some(context_tx)));
        bob_bus.handle_requests_with_context(topic.clone(), move |context, body| {
            let context_tx = context_tx.clone();
            async move {
                if let Some(tx) = context_tx.lock().unwrap().take() {
                    let _ = tx.send(context);
                }
                Ok([b"ssh:".as_slice(), &body].concat())
            }
        });

        let response = alice_bus
            .request(
                bob.fingerprint(),
                &topic,
                b"hello".to_vec(),
                Duration::from_secs(5),
            )
            .await
            .expect("request/reply over authenticated SSH carrier");
        assert_eq!(response, b"ssh:hello");
        let context = context_rx.await.unwrap();
        assert_eq!(context.caller_agent_fp, alice.fingerprint());
        assert_eq!(context.caller_user_fp, user.fingerprint());

        let second = alice_bus
            .request(
                bob.fingerprint(),
                &topic,
                b"again".to_vec(),
                Duration::from_secs(5),
            )
            .await
            .expect("a second request reuses the sole authenticated session");
        assert_eq!(second, b"ssh:again");

        let publish_topic = Topic::new(user.fingerprint(), "ssh-inner-publish");
        let mut published = bob_bus.subscribe(&publish_topic).await;
        for value in 0_u8..4 {
            alice_bus
                .publish_to(bob.fingerprint(), &publish_topic, vec![value])
                .await
                .expect("burst publish reuses the established session");
        }
        for expected in 0_u8..4 {
            let actual = tokio::time::timeout(Duration::from_secs(2), published.recv())
                .await
                .expect("published envelope arrives before deadline")
                .expect("subscription remains open");
            assert_eq!(actual, vec![expected]);
        }

        alice_bus.close().await.unwrap();
        bob_bus.close().await.unwrap();
    }

    #[tokio::test]
    async fn captured_alice_envelope_on_mallory_session_fails_before_replay_state() {
        let user = UserKey::generate();
        let alice = agent(&user, "alice");
        let bob = agent(&user, "bob");
        let mallory = agent(&user, "mallory");
        let options = SshTransportOptions {
            session_timeouts: SessionTimeouts {
                authentication: Duration::from_secs(2),
                record: Duration::from_secs(2),
            },
            max_sessions: 4,
            ..SshTransportOptions::default()
        };
        let alice_transport = Arc::new(
            SshTransport::bind_loopback_for_test(alice.clone(), options.clone())
                .await
                .unwrap(),
        );
        let mallory_transport = Arc::new(
            SshTransport::bind_loopback_for_test(mallory.clone(), options.clone())
                .await
                .unwrap(),
        );
        let bob_transport = Arc::new(
            SshTransport::bind_loopback_for_test(bob.clone(), options)
                .await
                .unwrap(),
        );
        let bob_target = target(bob_transport.local_port());
        alice_transport.add_target(bob.fingerprint(), bob_target.target.clone());
        mallory_transport.add_target(bob.fingerprint(), bob_target.target.clone());

        let payload = serde_json::to_vec(&BusMessage::Publish {
            topic: Topic::new(user.fingerprint(), "relay").wire(),
            body: b"captured".to_vec(),
        })
        .unwrap();
        let captured = SignedEnvelope::new(
            &alice,
            Recipient::Direct {
                agent_fp: bob.fingerprint(),
            },
            1,
            payload,
        );
        let inbox = Inbox::new();

        mallory_transport
            .send_to(bob.fingerprint(), captured.clone())
            .await
            .unwrap();
        let relayed = tokio::time::timeout(Duration::from_secs(2), bob_transport.recv())
            .await
            .expect("Mallory-carried envelope reaches SSH adapter")
            .expect("Bob transport remains open");
        assert_eq!(
            relayed.provenance,
            DeliveryProvenance::Direct {
                carrier: AuthenticatedPeer::new(user.fingerprint(), mallory.fingerprint()),
            },
            "SSH adapter provenance must come from Mallory's authenticated session"
        );
        let error = inbox
            .on_envelope(
                relayed.envelope,
                relayed.provenance,
                user.fingerprint(),
                bob.fingerprint(),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, BusError::CarrierAgentMismatch { .. }));
        assert!(inbox.nonce_cache().is_empty());
        assert_eq!(
            inbox.sequence_tracker().last_seen(&alice.fingerprint()),
            None
        );
        assert_eq!(
            inbox.sequence_tracker().last_seen(&mallory.fingerprint()),
            None
        );

        alice_transport
            .send_to(bob.fingerprint(), captured)
            .await
            .unwrap();
        let honest = tokio::time::timeout(Duration::from_secs(2), bob_transport.recv())
            .await
            .expect("Alice-carried envelope reaches SSH adapter")
            .expect("Bob transport remains open");
        assert_eq!(
            honest.provenance,
            DeliveryProvenance::Direct {
                carrier: AuthenticatedPeer::new(user.fingerprint(), alice.fingerprint()),
            }
        );
        inbox
            .on_envelope(
                honest.envelope,
                honest.provenance,
                user.fingerprint(),
                bob.fingerprint(),
            )
            .await
            .expect("the exact envelope remains admissible on Alice's session");
        assert_eq!(inbox.nonce_cache().len(), 1);
        assert_eq!(
            inbox.sequence_tracker().last_seen(&alice.fingerprint()),
            Some(1)
        );

        alice_transport.close().await;
        mallory_transport.close().await;
        bob_transport.close().await;
    }

    #[tokio::test]
    async fn wrong_authenticated_responder_cannot_consume_reply_waiter() {
        let user = UserKey::generate();
        let alice = agent(&user, "alice");
        let bob = agent(&user, "bob");
        let mallory = agent(&user, "mallory");
        let correlation = CorrelationId([7; 16]);
        let inbox = Inbox::new();
        let waiter = inbox.register_reply(correlation, bob.fingerprint());

        let (mut mallory_side, mut alice_side) =
            authenticated_pair(mallory.clone(), alice.clone()).await;
        mallory_side
            .send_envelope(&reply_envelope(
                &mallory,
                alice.fingerprint(),
                1,
                correlation,
                b"fake",
            ))
            .await
            .unwrap();
        let fake = alice_side.recv_envelope().await.unwrap();
        inbox
            .on_envelope(
                fake,
                DeliveryProvenance::Direct {
                    carrier: alice_side.peer(),
                },
                user.fingerprint(),
                alice.fingerprint(),
            )
            .await
            .unwrap();
        assert_eq!(inbox.pending_replies(), 1);
        assert!(inbox.nonce_cache().is_empty());
        assert_eq!(
            inbox.sequence_tracker().last_seen(&mallory.fingerprint()),
            None
        );

        let (mut bob_side, mut alice_side) = authenticated_pair(bob.clone(), alice.clone()).await;
        bob_side
            .send_envelope(&reply_envelope(
                &bob,
                alice.fingerprint(),
                1,
                correlation,
                b"honest",
            ))
            .await
            .unwrap();
        let honest = alice_side.recv_envelope().await.unwrap();
        inbox
            .on_envelope(
                honest,
                DeliveryProvenance::Direct {
                    carrier: alice_side.peer(),
                },
                user.fingerprint(),
                alice.fingerprint(),
            )
            .await
            .unwrap();
        assert_eq!(waiter.await.unwrap(), b"honest");
        assert_eq!(inbox.pending_replies(), 0);
    }

    #[tokio::test]
    async fn stale_reply_route_falls_back_to_the_exact_configured_peer() {
        let user = UserKey::generate();
        let alice = agent(&user, "alice");
        let bob = agent(&user, "bob");
        let options = SshTransportOptions {
            max_sessions: 2,
            ..SshTransportOptions::default()
        };
        let alice_transport = Arc::new(
            SshTransport::bind_loopback_for_test(alice.clone(), options.clone())
                .await
                .unwrap(),
        );
        let bob_transport = Arc::new(
            SshTransport::bind_loopback_for_test(bob.clone(), options)
                .await
                .unwrap(),
        );
        let bob_target = target(bob_transport.local_port());
        alice_transport.add_target(bob.fingerprint(), bob_target.target.clone());

        let (stale_session, _peer_session) =
            boxed_authenticated_pair(alice.clone(), bob.clone()).await;
        let (_reader, writer) = stale_session.into_split();
        let stale_route: ReplyRoute = Arc::new(SshReplyRoute {
            peer: writer.peer(),
            writer: Arc::new(AsyncMutex::new(writer)),
            alive: AtomicBool::new(false),
            closed: Notify::new(),
        });
        let envelope = SignedEnvelope::new(
            &alice,
            Recipient::Direct {
                agent_fp: bob.fingerprint(),
            },
            1,
            serde_json::to_vec(&BusMessage::Publish {
                topic: Topic::new(user.fingerprint(), "fallback").wire(),
                body: b"fresh route".to_vec(),
            })
            .unwrap(),
        );

        alice_transport
            .reply(bob.fingerprint(), &stale_route, envelope)
            .await
            .expect("known-stale route falls back before attempting a write");
        let inbound = tokio::time::timeout(Duration::from_secs(2), bob_transport.recv())
            .await
            .expect("fallback delivery is bounded")
            .expect("Bob receives fallback delivery");
        assert_eq!(
            inbound.provenance,
            DeliveryProvenance::Direct {
                carrier: AuthenticatedPeer::new(user.fingerprint(), alice.fingerprint()),
            }
        );

        alice_transport.close().await;
        bob_transport.close().await;
    }

    #[tokio::test]
    async fn cancelled_cached_write_poisons_the_session_before_another_counter() {
        let user = UserKey::generate();
        let alice = agent(&user, "alice");
        let bob = agent(&user, "bob");
        let transport = Arc::new(
            SshTransport::bind_loopback_for_test(
                alice.clone(),
                SshTransportOptions {
                    max_sessions: 1,
                    ..SshTransportOptions::default()
                },
            )
            .await
            .unwrap(),
        );
        let (alice_session, _bob_session) =
            boxed_authenticated_pair(alice.clone(), bob.clone()).await;
        let permit = transport
            .session_slots
            .clone()
            .acquire_owned()
            .await
            .expect("test reserves the sole session slot");
        assert!(
            transport
                .spawn_authenticated_reader(alice_session, None, permit, true)
                .await
        );
        let route = transport
            .cached_outbound(bob.fingerprint())
            .await
            .expect("authenticated session is cached");
        let large = SignedEnvelope::new(
            &alice,
            Recipient::Direct {
                agent_fp: bob.fingerprint(),
            },
            1,
            vec![0x5a; 2 * 1024 * 1024],
        );
        let first = tokio::spawn({
            let transport = transport.clone();
            let route = route.clone();
            async move { transport.send_on_route(&route, &large).await }
        });

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if route.writer.try_lock().is_err() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first record owns the session writer");

        let second_envelope = SignedEnvelope::new(
            &alice,
            Recipient::Direct {
                agent_fp: bob.fingerprint(),
            },
            2,
            b"must not follow a partial record".to_vec(),
        );
        let second = tokio::spawn({
            let transport = transport.clone();
            let route = route.clone();
            async move { transport.send_on_route(&route, &second_envelope).await }
        });
        tokio::task::yield_now().await;
        first.abort();
        let _ = first.await;

        let error = tokio::time::timeout(Duration::from_secs(1), second)
            .await
            .expect("queued writer observes poisoning")
            .expect("queued writer task does not panic")
            .expect_err("a counter must not follow a cancelled partial record");
        assert!(matches!(error, SshTransportError::Closed));
        assert!(!route.is_alive());
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if transport.outbound_sessions.lock().await.is_empty()
                    && transport.session_slots.available_permits() == 1
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("poison wakes the reader, evicts the route, and releases its slot");

        transport.close().await;
    }

    #[tokio::test]
    async fn zero_session_limit_is_refused() {
        let user = UserKey::generate();
        let local = agent(&user, "local");
        let error = match SshTransport::bind_loopback_for_test(
            local,
            SshTransportOptions {
                max_sessions: 0,
                ..SshTransportOptions::default()
            },
        )
        .await
        {
            Ok(_) => panic!("zero session limit must be rejected"),
            Err(error) => error,
        };
        assert!(matches!(error, SshTransportError::InvalidConfig(_)));
    }

    #[tokio::test]
    async fn oversized_resource_limits_are_refused_without_panicking() {
        let user = UserKey::generate();
        let local = agent(&user, "local");
        let error = match SshTransport::bind_loopback_for_test(
            local,
            SshTransportOptions {
                max_sessions: usize::MAX,
                inbound_capacity: usize::MAX,
                ..SshTransportOptions::default()
            },
        )
        .await
        {
            Ok(_) => panic!("oversized resource limits must be rejected"),
            Err(error) => error,
        };
        assert!(matches!(error, SshTransportError::InvalidConfig(_)));
    }

    #[tokio::test]
    async fn close_unblocks_recv_and_a_waiting_send_then_rejects_new_work() {
        let user = UserKey::generate();
        let local = agent(&user, "local");
        let peer = agent(&user, "peer");
        let peer_fp = peer.fingerprint();
        let transport = Arc::new(
            SshTransport::bind_loopback_for_test(
                local.clone(),
                SshTransportOptions {
                    session_timeouts: SessionTimeouts {
                        authentication: Duration::from_secs(2),
                        record: Duration::from_secs(2),
                    },
                    max_sessions: 1,
                    ..SshTransportOptions::default()
                },
            )
            .await
            .unwrap(),
        );
        let peer_target = target(9);
        transport.add_target(peer_fp, peer_target.target.clone());

        let held_permit = transport
            .session_slots
            .clone()
            .acquire_owned()
            .await
            .expect("test reserves sole slot");
        let envelope = SignedEnvelope::new(
            &local,
            Recipient::Direct { agent_fp: peer_fp },
            1,
            serde_json::to_vec(&BusMessage::Publish {
                topic: Topic::new(user.fingerprint(), "close-race").wire(),
                body: b"never delivered".to_vec(),
            })
            .unwrap(),
        );

        let recv_task = tokio::spawn({
            let transport = transport.clone();
            async move { transport.recv().await }
        });
        let send_task = tokio::spawn({
            let transport = transport.clone();
            let envelope = envelope.clone();
            async move { transport.send_to(peer_fp, envelope).await }
        });
        tokio::task::yield_now().await;

        transport.close().await;
        drop(held_permit);

        assert!(tokio::time::timeout(Duration::from_secs(1), recv_task)
            .await
            .expect("recv observes close")
            .expect("recv task does not panic")
            .is_none());
        let send_error = tokio::time::timeout(Duration::from_secs(1), send_task)
            .await
            .expect("slot waiter observes close")
            .expect("send task does not panic")
            .expect_err("send racing close must fail");
        assert!(matches!(send_error, BusError::TransportBackend(_)));

        let post_close = transport
            .send_to(peer_fp, envelope)
            .await
            .expect_err("post-close send must fail");
        assert!(matches!(post_close, BusError::TransportBackend(_)));
        assert!(transport.outbound_sessions.lock().await.is_empty());
        assert!(transport
            .session_tasks
            .lock()
            .expect("task lock")
            .is_empty());
    }
}
