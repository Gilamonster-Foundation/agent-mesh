//! SSH byte-stream carriage via an explicitly selected OpenSSH client.
//!
//! This module owns only the process boundary.  A successfully spawned child
//! is still an *unauthenticated mesh carrier*: the session layer must complete
//! the AgentKey handshake before constructing authenticated provenance or
//! allowing application frames onto the stream.

use crate::error::{Result, SshTransportError};
use std::ffi::OsString;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};
use tokio::task::JoinHandle;
use tokio::time;

/// Maximum number of bytes retained from OpenSSH's stderr stream.
///
/// The complete stream is drained so the child cannot block on a full pipe;
/// only its tail is retained for process-contextual errors.
pub const MAX_STDERR_BYTES: usize = 64 * 1024;

const STDERR_READ_CHUNK_BYTES: usize = 8 * 1024;
const DROP_REAP_TIMEOUT: Duration = Duration::from_secs(2);

/// How OpenSSH authenticates the server host key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyPolicy {
    /// Require an existing matching entry in the dedicated file.
    Pinned {
        /// The only user host-key database passed to OpenSSH.
        known_hosts_file: PathBuf,
    },
    /// Trust an unknown key on first contact, but reject changed keys later.
    ///
    /// This is an explicit bootstrap/TOFU mode, not a pinned production mode.
    BootstrapTofu {
        /// The dedicated file in which OpenSSH stores the first-seen key.
        known_hosts_file: PathBuf,
    },
}

impl HostKeyPolicy {
    /// Return the dedicated known-hosts file used by this policy.
    #[must_use]
    pub fn known_hosts_file(&self) -> &Path {
        match self {
            Self::Pinned { known_hosts_file } | Self::BootstrapTofu { known_hosts_file } => {
                known_hosts_file
            }
        }
    }

    fn strict_host_key_checking(&self) -> &'static str {
        match self {
            Self::Pinned { .. } => "yes",
            Self::BootstrapTofu { .. } => "accept-new",
        }
    }
}

/// Validated OpenSSH destination and remote forwarding target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshTarget {
    user: String,
    host: String,
    ssh_port: u16,
    mesh_host: String,
    mesh_port: u16,
    identity_file: PathBuf,
    host_key_policy: HostKeyPolicy,
}

impl SshTarget {
    /// Validate and construct an SSH target.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        user: impl Into<String>,
        host: impl Into<String>,
        ssh_port: u16,
        mesh_host: impl Into<String>,
        mesh_port: u16,
        identity_file: impl Into<PathBuf>,
        host_key_policy: HostKeyPolicy,
    ) -> Result<Self> {
        let user = user.into();
        let host = host.into();
        let mesh_host = mesh_host.into();
        let identity_file = identity_file.into();

        validate_user(&user)?;
        validate_host("SSH host", &host)?;
        let mesh_ip = mesh_host
            .parse::<IpAddr>()
            .map_err(|_| invalid("mesh forwarding host must be a numeric loopback IP address"))?;
        if !mesh_ip.is_loopback() {
            return Err(invalid("mesh forwarding host must be loopback"));
        }
        validate_port("SSH port", ssh_port)?;
        validate_port("mesh forwarding port", mesh_port)?;
        validate_absolute_path("identity file", &identity_file, true)?;
        validate_absolute_path("known-hosts file", host_key_policy.known_hosts_file(), true)?;

        Ok(Self {
            user,
            host,
            ssh_port,
            mesh_host,
            mesh_port,
            identity_file,
            host_key_policy,
        })
    }

    /// SSH account name.
    #[must_use]
    pub fn user(&self) -> &str {
        &self.user
    }

    /// SSH server hostname or numeric address.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// SSH server port.
    #[must_use]
    pub const fn ssh_port(&self) -> u16 {
        self.ssh_port
    }

    /// Host reached by OpenSSH's remote `direct-tcpip` channel.
    #[must_use]
    pub fn mesh_host(&self) -> &str {
        &self.mesh_host
    }

    /// Port reached by OpenSSH's remote `direct-tcpip` channel.
    #[must_use]
    pub const fn mesh_port(&self) -> u16 {
        self.mesh_port
    }

    /// Explicit private-key path.
    #[must_use]
    pub fn identity_file(&self) -> &Path {
        &self.identity_file
    }

    /// Server host-key policy.
    #[must_use]
    pub const fn host_key_policy(&self) -> &HostKeyPolicy {
        &self.host_key_policy
    }

    /// Build the exact OpenSSH argument vector.
    ///
    /// Every value is a distinct OS argument.  Configuration files, ambient
    /// host databases, authentication agents, multiplexed control sockets,
    /// password-like authentication, and agent forwarding are disabled.
    #[must_use]
    pub fn ssh_args(&self) -> Vec<OsString> {
        let mut args = vec![
            OsString::from("-F"),
            OsString::from("none"),
            OsString::from("-T"),
            OsString::from("-W"),
            OsString::from(format!(
                "{}:{}",
                forwarding_host(&self.mesh_host),
                self.mesh_port
            )),
        ];

        push_option(&mut args, "BatchMode=yes");
        push_option(
            &mut args,
            &format!(
                "StrictHostKeyChecking={}",
                self.host_key_policy.strict_host_key_checking()
            ),
        );

        let mut known_hosts = OsString::from("UserKnownHostsFile=");
        known_hosts.push(self.host_key_policy.known_hosts_file().as_os_str());
        push_os_option(&mut args, known_hosts);

        // Do not allow the system-wide host-key database to silently turn a
        // dedicated pin miss into success.
        push_option(&mut args, "GlobalKnownHostsFile=none");
        push_option(&mut args, "IdentitiesOnly=yes");

        // Supplying IdentityFile as an explicit configuration option replaces
        // OpenSSH's default identity-file list even when this path is absent.
        // In contrast, `-i <absent-path>` can leave defaults in the evaluated
        // configuration and therefore does not fail closed to exactly one key.
        let mut identity_file = OsString::from("IdentityFile=");
        identity_file.push(self.identity_file.as_os_str());
        push_os_option(&mut args, identity_file);

        push_option(&mut args, "PreferredAuthentications=publickey");
        push_option(&mut args, "PasswordAuthentication=no");
        push_option(&mut args, "KbdInteractiveAuthentication=no");
        push_option(&mut args, "GSSAPIAuthentication=no");
        push_option(&mut args, "ForwardAgent=no");
        push_option(&mut args, "IdentityAgent=none");
        push_option(&mut args, "ControlMaster=no");
        push_option(&mut args, "ControlPath=none");
        push_option(&mut args, "ExitOnForwardFailure=yes");
        push_option(&mut args, "ClearAllForwardings=yes");
        push_option(&mut args, "UpdateHostKeys=no");
        push_option(&mut args, "EscapeChar=none");

        args.push(OsString::from("-p"));
        args.push(OsString::from(self.ssh_port.to_string()));

        // Terminate option processing even though the validated destination
        // cannot begin with `-`.
        args.push(OsString::from("--"));
        args.push(OsString::from(format!(
            "{}@{}",
            self.user,
            forwarding_host(&self.host)
        )));
        args
    }
}

/// Explicitly selected OpenSSH executable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenSshClient {
    executable: PathBuf,
}

impl OpenSshClient {
    /// Select an OpenSSH executable by absolute path.
    pub fn new(executable: impl Into<PathBuf>) -> Result<Self> {
        let executable = executable.into();
        validate_absolute_path("OpenSSH executable", &executable, false)?;
        Ok(Self { executable })
    }

    /// Select the platform's system OpenSSH client by an absolute path.
    ///
    /// No `PATH` lookup is performed.
    pub fn system() -> Result<Self> {
        [Path::new("/usr/bin/ssh"), Path::new("/bin/ssh")]
            .into_iter()
            .find(|candidate| candidate.is_file())
            .map(Path::to_path_buf)
            .ok_or_else(|| {
                SshTransportError::InvalidConfig(
                    "no system OpenSSH executable found at /usr/bin/ssh or /bin/ssh".into(),
                )
            })
            .and_then(Self::new)
    }

    /// Return the selected absolute executable path.
    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    /// Spawn OpenSSH and return an unauthenticated byte-stream carrier.
    ///
    /// Spawning a process is not evidence that either SSH establishment or
    /// the mesh handshake succeeded.  The caller must take the raw halves,
    /// complete inner authentication, and retain the returned carrier as the
    /// child-process owner for the authenticated session's lifetime.
    pub(crate) async fn connect(&self, target: &SshTarget) -> Result<UnauthenticatedSshCarrier> {
        let mut child = Command::new(&self.executable)
            .args(target.ssh_args())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(SshTransportError::Io)?;

        let writer = child.stdin.take();
        let reader = child.stdout.take();
        let stderr = child.stderr.take();
        let (Some(writer), Some(reader), Some(stderr)) = (writer, reader, stderr) else {
            kill_and_reap_child(&mut child, DROP_REAP_TIMEOUT).await;
            return Err(SshTransportError::Closed);
        };

        let stderr_capture = Arc::new(Mutex::new(BoundedStderr::default()));
        let stderr_task = tokio::spawn(drain_stderr(stderr, Arc::clone(&stderr_capture)));

        Ok(UnauthenticatedSshCarrier {
            child: Some(child),
            reader: Some(reader),
            writer: Some(writer),
            stderr_capture,
            stderr_task: Some(stderr_task),
        })
    }
}

/// A spawned OpenSSH byte stream that has not yet proven a mesh peer.
///
/// The stream halves are deliberately crate-private.  Keeping this value
/// alive keeps ownership of the child process and its stderr drain.
pub(crate) struct UnauthenticatedSshCarrier {
    child: Option<Child>,
    reader: Option<ChildStdout>,
    writer: Option<ChildStdin>,
    stderr_capture: Arc<Mutex<BoundedStderr>>,
    stderr_task: Option<JoinHandle<()>>,
}

impl UnauthenticatedSshCarrier {
    /// Take the raw reader for the crate's inner-authentication layer.
    pub(crate) fn take_reader(&mut self) -> Result<ChildStdout> {
        self.reader.take().ok_or(SshTransportError::Closed)
    }

    /// Take the raw writer for the crate's inner-authentication layer.
    pub(crate) fn take_writer(&mut self) -> Result<ChildStdin> {
        self.writer.take().ok_or(SshTransportError::Closed)
    }

    /// Attach OpenSSH process evidence to an inner-authentication failure.
    ///
    /// If OpenSSH exits within `grace`, its status is the strongest available
    /// evidence and a [`SshTransportError::ProcessExit`] is returned.  If it
    /// remains alive, it is killed and reaped before the inner failure is
    /// returned.  stderr is drained continuously and retained only up to
    /// [`MAX_STDERR_BYTES`].
    pub(crate) async fn fail_inner_auth(
        mut self,
        error: impl Into<String>,
        grace: Duration,
    ) -> SshTransportError {
        let message = error.into();
        self.close_owned_halves();

        match self.wait_for_exit(grace).await {
            WaitOutcome::Exited(status) => {
                let stderr = self.collect_stderr(grace).await;
                SshTransportError::ProcessExit {
                    status: status.code(),
                    stderr,
                    context: format!("inner mesh authentication failed: {message}"),
                }
            }
            WaitOutcome::TimedOut => match self.kill_and_reap(grace).await {
                ReapOutcome::Reaped => {
                    let stderr = self.collect_stderr(grace).await;
                    SshTransportError::InnerAuth { message, stderr }
                }
                ReapOutcome::TimedOut => {
                    let stderr = self.collect_stderr(grace).await;
                    SshTransportError::ProcessTimeout {
                        stage: "reaping OpenSSH after inner mesh authentication failure".into(),
                        stderr,
                    }
                }
                ReapOutcome::WaitFailed(wait_error) => {
                    let stderr = self.collect_stderr(grace).await;
                    SshTransportError::ProcessExit {
                        status: None,
                        stderr,
                        context: format!(
                            "inner mesh authentication failed: {message}; process wait failed: {wait_error}"
                        ),
                    }
                }
            },
            WaitOutcome::WaitFailed(wait_error) => {
                let _ = self.kill_and_reap(grace).await;
                let stderr = self.collect_stderr(grace).await;
                SshTransportError::ProcessExit {
                    status: None,
                    stderr,
                    context: format!(
                        "inner mesh authentication failed: {message}; process wait failed: {wait_error}"
                    ),
                }
            }
            WaitOutcome::Missing => {
                let stderr = self.collect_stderr(grace).await;
                SshTransportError::InnerAuth { message, stderr }
            }
        }
    }

    /// Supervise OpenSSH after an authenticated stream ends or fails.
    ///
    /// The method waits at most `grace` for an exit.  A child that remains
    /// alive is killed and reaped with the same bound.
    pub(crate) async fn finish(
        mut self,
        context: impl Into<String>,
        grace: Duration,
    ) -> SshTransportError {
        let context = context.into();
        self.close_owned_halves();

        match self.wait_for_exit(grace).await {
            WaitOutcome::Exited(status) => {
                let stderr = self.collect_stderr(grace).await;
                SshTransportError::ProcessExit {
                    status: status.code(),
                    stderr,
                    context,
                }
            }
            WaitOutcome::TimedOut => match self.kill_and_reap(grace).await {
                ReapOutcome::Reaped => {
                    let stderr = self.collect_stderr(grace).await;
                    SshTransportError::ProcessTimeout {
                        stage: format!("{context}; waiting for OpenSSH to exit"),
                        stderr,
                    }
                }
                ReapOutcome::TimedOut => {
                    let stderr = self.collect_stderr(grace).await;
                    SshTransportError::ProcessTimeout {
                        stage: format!("{context}; reaping OpenSSH after termination"),
                        stderr,
                    }
                }
                ReapOutcome::WaitFailed(wait_error) => {
                    let stderr = self.collect_stderr(grace).await;
                    SshTransportError::ProcessExit {
                        status: None,
                        stderr,
                        context: format!("{context}; process wait failed: {wait_error}"),
                    }
                }
            },
            WaitOutcome::WaitFailed(wait_error) => {
                let _ = self.kill_and_reap(grace).await;
                let stderr = self.collect_stderr(grace).await;
                SshTransportError::ProcessExit {
                    status: None,
                    stderr,
                    context: format!("{context}; process wait failed: {wait_error}"),
                }
            }
            WaitOutcome::Missing => SshTransportError::Closed,
        }
    }

    fn close_owned_halves(&mut self) {
        self.writer.take();
        self.reader.take();
    }

    async fn wait_for_exit(&mut self, grace: Duration) -> WaitOutcome {
        let Some(child) = self.child.as_mut() else {
            return WaitOutcome::Missing;
        };

        match time::timeout(grace, child.wait()).await {
            Ok(Ok(status)) => {
                self.child.take();
                WaitOutcome::Exited(status)
            }
            Ok(Err(error)) => WaitOutcome::WaitFailed(error.to_string()),
            Err(_) => WaitOutcome::TimedOut,
        }
    }

    async fn kill_and_reap(&mut self, grace: Duration) -> ReapOutcome {
        let Some(child) = self.child.as_mut() else {
            return ReapOutcome::Reaped;
        };

        // `start_kill` can race with a natural exit.  Waiting is authoritative
        // and also performs the required reap, so retain only a wait failure.
        let _ = child.start_kill();
        match time::timeout(grace, child.wait()).await {
            Ok(Ok(_status)) => {
                self.child.take();
                ReapOutcome::Reaped
            }
            Ok(Err(error)) => ReapOutcome::WaitFailed(error.to_string()),
            Err(_) => ReapOutcome::TimedOut,
        }
    }

    async fn collect_stderr(&mut self, grace: Duration) -> String {
        if let Some(mut task) = self.stderr_task.take() {
            if time::timeout(grace, &mut task).await.is_err() {
                task.abort();
                let _ = task.await;
            }
        }

        let snapshot = match self.stderr_capture.lock() {
            Ok(capture) => capture.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        snapshot.render()
    }

    #[cfg(test)]
    fn child_id(&self) -> Option<u32> {
        self.child.as_ref().and_then(Child::id)
    }
}

impl Drop for UnauthenticatedSshCarrier {
    fn drop(&mut self) {
        self.close_owned_halves();

        let Some(mut child) = self.child.take() else {
            if let Some(task) = self.stderr_task.take() {
                task.abort();
            }
            return;
        };

        let _ = child.start_kill();
        let stderr_task = self.stderr_task.take();

        // Drop cannot await.  When called in the Tokio context required to
        // create this carrier, hand the killed child to a bounded reaper task.
        // `kill_on_drop(true)` remains the fallback if the runtime is already
        // unavailable.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = time::timeout(DROP_REAP_TIMEOUT, child.wait()).await;
                if let Some(task) = stderr_task {
                    task.abort();
                    let _ = task.await;
                }
            });
        } else if let Some(task) = stderr_task {
            task.abort();
        }
    }
}

#[derive(Debug)]
enum WaitOutcome {
    Exited(ExitStatus),
    TimedOut,
    WaitFailed(String),
    Missing,
}

#[derive(Debug)]
enum ReapOutcome {
    Reaped,
    TimedOut,
    WaitFailed(String),
}

#[derive(Debug, Default, Clone)]
struct BoundedStderr {
    tail: Vec<u8>,
    truncated: bool,
    read_error: Option<String>,
}

impl BoundedStderr {
    fn push(&mut self, bytes: &[u8]) {
        if bytes.len() >= MAX_STDERR_BYTES {
            self.tail.clear();
            self.tail
                .extend_from_slice(&bytes[bytes.len() - MAX_STDERR_BYTES..]);
            self.truncated = true;
            return;
        }

        let excess = self
            .tail
            .len()
            .saturating_add(bytes.len())
            .saturating_sub(MAX_STDERR_BYTES);
        if excess > 0 {
            self.tail.drain(..excess);
            self.truncated = true;
        }
        self.tail.extend_from_slice(bytes);
    }

    fn render(&self) -> String {
        let mut rendered = String::new();
        if self.truncated {
            rendered.push_str("[... stderr truncated ...]\n");
        }
        rendered.push_str(&String::from_utf8_lossy(&self.tail));
        if let Some(error) = &self.read_error {
            rendered.push_str("\n[stderr read failed: ");
            rendered.push_str(error);
            rendered.push(']');
        }
        bounded_utf8_tail(&rendered, MAX_STDERR_BYTES)
    }
}

async fn drain_stderr(stderr: ChildStderr, capture: Arc<Mutex<BoundedStderr>>) {
    let mut stderr = stderr;
    let mut chunk = vec![0_u8; STDERR_READ_CHUNK_BYTES];
    loop {
        match stderr.read(&mut chunk).await {
            Ok(0) => break,
            Ok(read) => match capture.lock() {
                Ok(mut capture) => capture.push(&chunk[..read]),
                Err(poisoned) => poisoned.into_inner().push(&chunk[..read]),
            },
            Err(error) => {
                match capture.lock() {
                    Ok(mut capture) => capture.read_error = Some(error.to_string()),
                    Err(poisoned) => {
                        poisoned.into_inner().read_error = Some(error.to_string());
                    }
                }
                break;
            }
        }
    }
}

async fn kill_and_reap_child(child: &mut Child, grace: Duration) {
    let _ = child.start_kill();
    let _ = time::timeout(grace, child.wait()).await;
}

fn push_option(args: &mut Vec<OsString>, option: &str) {
    push_os_option(args, OsString::from(option));
}

fn push_os_option(args: &mut Vec<OsString>, option: OsString) {
    args.push(OsString::from("-o"));
    args.push(option);
}

fn forwarding_host(host: &str) -> String {
    if host
        .parse::<IpAddr>()
        .is_ok_and(|address| address.is_ipv6())
    {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

fn validate_user(user: &str) -> Result<()> {
    let mut chars = user.chars();
    let Some(first) = chars.next() else {
        return Err(invalid("SSH user must not be empty"));
    };
    if !(first.is_ascii_alphanumeric() || first == '_')
        || !chars.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
        })
    {
        return Err(invalid(
            "SSH user must contain only ASCII letters, digits, '_', '-', or '.', and cannot begin with an option",
        ));
    }
    Ok(())
}

fn validate_host(field: &str, host: &str) -> Result<()> {
    if host.is_empty() {
        return Err(invalid(format!("{field} must not be empty")));
    }
    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    if host.len() > 253 {
        return Err(invalid(format!("{field} is too long")));
    }

    let valid = host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
    });
    if !valid {
        return Err(invalid(format!(
            "{field} must be a numeric IP address or a valid ASCII DNS hostname"
        )));
    }
    Ok(())
}

fn validate_port(field: &str, port: u16) -> Result<()> {
    if port == 0 {
        Err(invalid(format!("{field} must not be zero")))
    } else {
        Ok(())
    }
}

fn validate_absolute_path(field: &str, path: &Path, config_option: bool) -> Result<()> {
    if !path.is_absolute() {
        return Err(invalid(format!("{field} must be an absolute path")));
    }

    let display = path.to_string_lossy();
    if display.chars().any(char::is_control) {
        return Err(invalid(format!("{field} must not contain control bytes")));
    }
    if display.contains('%') || display.contains('$') || display.contains('~') {
        return Err(invalid(format!(
            "{field} must not contain OpenSSH path expansion tokens"
        )));
    }
    if config_option
        && display.chars().any(|character| {
            character.is_ascii_whitespace() || matches!(character, '\'' | '"' | '\\')
        })
    {
        return Err(invalid(format!(
            "{field} contains characters unsafe in an OpenSSH -o value"
        )));
    }
    Ok(())
}

fn bounded_utf8_tail(value: &str, maximum: usize) -> String {
    if value.len() <= maximum {
        return value.to_owned();
    }

    let mut start = value.len() - maximum;
    while !value.is_char_boundary(start) {
        start += 1;
    }
    value[start..].to_owned()
}

fn invalid(message: impl Into<String>) -> SshTransportError {
    SshTransportError::InvalidConfig(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pinned_target() -> SshTarget {
        SshTarget::new(
            "newtmesh",
            "hub.example",
            22,
            "127.0.0.1",
            7777,
            "/home/spoke/.ssh/id_ed25519",
            HostKeyPolicy::Pinned {
                known_hosts_file: PathBuf::from("/home/spoke/.ssh/mesh_known_hosts"),
            },
        )
        .expect("valid fixture")
    }

    fn string_args(target: &SshTarget) -> Vec<String> {
        target
            .ssh_args()
            .into_iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect()
    }

    fn has_option(args: &[String], expected: &str) -> bool {
        args.windows(2)
            .any(|pair| pair[0] == "-o" && pair[1] == expected)
    }

    #[test]
    fn pinned_argv_is_isolated_and_strict() {
        let target = pinned_target();
        let args = string_args(&target);

        assert_eq!(&args[..2], ["-F", "none"]);
        assert!(args.iter().any(|argument| argument == "-T"));
        assert!(args.windows(2).any(|pair| pair == ["-W", "127.0.0.1:7777"]));
        assert!(has_option(&args, "BatchMode=yes"));
        assert!(has_option(&args, "StrictHostKeyChecking=yes"));
        assert!(has_option(
            &args,
            "UserKnownHostsFile=/home/spoke/.ssh/mesh_known_hosts"
        ));
        assert!(has_option(&args, "GlobalKnownHostsFile=none"));
        assert!(has_option(&args, "IdentitiesOnly=yes"));
        assert!(has_option(
            &args,
            "IdentityFile=/home/spoke/.ssh/id_ed25519"
        ));
        assert!(has_option(&args, "PreferredAuthentications=publickey"));
        assert!(has_option(&args, "PasswordAuthentication=no"));
        assert!(has_option(&args, "KbdInteractiveAuthentication=no"));
        assert!(has_option(&args, "GSSAPIAuthentication=no"));
        assert!(has_option(&args, "ForwardAgent=no"));
        assert!(has_option(&args, "IdentityAgent=none"));
        assert!(has_option(&args, "ControlMaster=no"));
        assert!(has_option(&args, "ControlPath=none"));
        assert!(has_option(&args, "ExitOnForwardFailure=yes"));
        assert!(has_option(&args, "ClearAllForwardings=yes"));
        assert!(has_option(&args, "UpdateHostKeys=no"));
        assert!(has_option(&args, "EscapeChar=none"));
        assert!(!args.iter().any(|argument| argument == "-i"));
        assert!(!args
            .iter()
            .any(|argument| argument.contains("StrictHostKeyChecking=accept-new")));
        assert_eq!(&args[args.len() - 2..], ["--", "newtmesh@hub.example"]);
    }

    #[test]
    fn bootstrap_tofu_argv_is_explicitly_accept_new() {
        let target = SshTarget::new(
            "newtmesh",
            "::1",
            2222,
            "::1",
            7777,
            "/keys/id_ed25519",
            HostKeyPolicy::BootstrapTofu {
                known_hosts_file: PathBuf::from("/state/bootstrap_known_hosts"),
            },
        )
        .expect("valid bootstrap target");
        let args = string_args(&target);

        assert!(has_option(&args, "StrictHostKeyChecking=accept-new"));
        assert!(has_option(
            &args,
            "UserKnownHostsFile=/state/bootstrap_known_hosts"
        ));
        assert!(has_option(&args, "GlobalKnownHostsFile=none"));
        assert!(args.windows(2).any(|pair| pair == ["-W", "[::1]:7777"]));
        assert_eq!(&args[args.len() - 2..], ["--", "newtmesh@[::1]"]);
    }

    #[test]
    fn hostile_fields_and_relative_paths_are_rejected() {
        for user in ["", "-oProxyCommand=evil", "mesh user", "mesh@evil"] {
            assert!(target_with(user, "hub.example", "/keys/id", "/state/known").is_err());
        }
        for host in [
            "",
            "-oProxyCommand=evil",
            "hub example",
            "hub@evil",
            "hub\nevil",
        ] {
            assert!(target_with("newtmesh", host, "/keys/id", "/state/known").is_err());
        }
        assert!(target_with("newtmesh", "hub.example", "relative-id", "/state/known").is_err());
        assert!(target_with("newtmesh", "hub.example", "/keys/id", "relative-known").is_err());
        assert!(target_with(
            "newtmesh",
            "hub.example",
            "/keys/id -oProxyCommand=evil",
            "/state/known"
        )
        .is_err());
        assert!(target_with("newtmesh", "hub.example", "/keys/id", "/state/%h").is_err());
        assert!(target_with(
            "newtmesh",
            "hub.example",
            "/keys/id",
            "/state/known -oProxyCommand=evil"
        )
        .is_err());
        assert!(OpenSshClient::new("ssh").is_err());
        assert!(SshTarget::new(
            "newtmesh",
            "hub.example",
            22,
            "mesh.internal",
            7777,
            "/keys/id",
            HostKeyPolicy::Pinned {
                known_hosts_file: PathBuf::from("/state/known"),
            },
        )
        .is_err());
        assert!(SshTarget::new(
            "newtmesh",
            "hub.example",
            22,
            "192.0.2.1",
            7777,
            "/keys/id",
            HostKeyPolicy::Pinned {
                known_hosts_file: PathBuf::from("/state/known"),
            },
        )
        .is_err());
    }

    fn target_with(
        user: &str,
        host: &str,
        identity_file: &str,
        known_hosts_file: &str,
    ) -> Result<SshTarget> {
        SshTarget::new(
            user,
            host,
            22,
            "127.0.0.1",
            7777,
            identity_file,
            HostKeyPolicy::Pinned {
                known_hosts_file: PathBuf::from(known_hosts_file),
            },
        )
    }

    #[test]
    fn option_terminator_and_separate_arguments_prevent_injection() {
        let target = pinned_target();
        let args = target.ssh_args();
        assert_eq!(args[args.len() - 2], std::ffi::OsStr::new("--"));
        assert_eq!(
            args[args.len() - 1],
            std::ffi::OsStr::new("newtmesh@hub.example")
        );
        assert!(!args.iter().any(|argument| argument == "ProxyCommand=evil"));
    }

    #[cfg(unix)]
    mod unix_process {
        use super::*;
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        use std::process::Command as StdCommand;
        use std::sync::atomic::{AtomicBool, Ordering};
        use tempfile::TempDir;

        /// Materialize an executable fake OpenSSH client in a private
        /// temporary directory.
        ///
        /// The script bytes are written to a staging file that is never
        /// executed, and a child process copies them into the path this test
        /// binary later `exec`s. That indirection is load-bearing.
        ///
        /// Writing the executable in-process — `fs::write(&executable, ..)` —
        /// is racy under libtest's thread-per-test model. glibc's
        /// `posix_spawn` issues `clone3` *without* `CLONE_FILES`, so a
        /// sibling test thread's spawn duplicates this process's whole
        /// descriptor table. The duplicate keeps the write descriptor's
        /// open-file-description alive past our own `close()`, the inode's
        /// `i_writecount` stays non-zero, and our `execve` is refused with
        /// `ETXTBSY` ("Text file busy"). `O_CLOEXEC` does not help: it is
        /// honored at the forked child's `exec`, not at `fork`.
        ///
        /// Delegating the write removes the precondition rather than
        /// retrying around it. `status()` returns only once the copier has
        /// exited, and `do_exit()` runs `exit_files()` and then
        /// `exit_task_work()` — which flushes the deferred `__fput` — before
        /// `exit_notify()` releases our wait. The write access is therefore
        /// released before this function returns, and no descriptor for the
        /// executable ever existed in this process to be inherited.
        fn fake_ssh(body: &str) -> (TempDir, PathBuf) {
            let directory = tempfile::tempdir().expect("tempdir");
            let staged = directory.path().join("fake-ssh.staged");
            let executable = directory.path().join("fake-ssh");
            fs::write(&staged, format!("#!/bin/sh\n{body}\n")).expect("write script");
            let copied = StdCommand::new("/bin/cp")
                .arg(&staged)
                .arg(&executable)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("copy script into place");
            assert!(copied.success(), "cp fake-ssh exited {copied:?}");
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
                .expect("make executable");
            (directory, executable)
        }

        fn process_exists(pid: u32) -> bool {
            StdCommand::new("/bin/kill")
                .args(["-0", &pid.to_string()])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|status| status.success())
        }

        #[tokio::test]
        async fn stderr_flood_is_drained_and_bounded() {
            let (_directory, executable) = fake_ssh(
                "printf '%70000s' first >&2\nprintf '%70000s' diagnostic-tail >&2\nexit 23",
            );
            let client = OpenSshClient::new(executable).expect("client");
            let carrier = client.connect(&pinned_target()).await.expect("spawn");
            let error = carrier
                .finish("stderr flood test", Duration::from_secs(3))
                .await;

            match error {
                SshTransportError::ProcessExit {
                    status,
                    stderr,
                    context,
                } => {
                    assert_eq!(status, Some(23));
                    assert_eq!(context, "stderr flood test");
                    assert!(stderr.len() <= MAX_STDERR_BYTES);
                    assert!(stderr.ends_with("diagnostic-tail"), "stderr tail: {stderr}");
                }
                other => panic!("unexpected error: {other:?}"),
            }
        }

        #[tokio::test]
        async fn immediate_exit_during_inner_auth_surfaces_status_and_stderr() {
            let (_directory, executable) = fake_ssh("printf 'outer transport failed' >&2\nexit 42");
            let client = OpenSshClient::new(executable).expect("client");
            let carrier = client.connect(&pinned_target()).await.expect("spawn");
            let pid = carrier.child_id().expect("child pid");

            let error = carrier
                .fail_inner_auth("unexpected EOF", Duration::from_secs(2))
                .await;
            match error {
                SshTransportError::ProcessExit {
                    status,
                    stderr,
                    context,
                } => {
                    assert_eq!(status, Some(42));
                    assert_eq!(stderr, "outer transport failed");
                    assert!(context.contains("unexpected EOF"));
                }
                other => panic!("unexpected error: {other:?}"),
            }
            assert!(!process_exists(pid), "wait() must reap the exited child");
        }

        #[tokio::test]
        async fn inner_auth_failure_kills_and_reaps_live_child_with_stderr() {
            let (_directory, executable) =
                fake_ssh("printf 'inner-auth process context' >&2\nprintf R\nexec /bin/sleep 30");
            let client = OpenSshClient::new(executable).expect("client");
            let mut carrier = client.connect(&pinned_target()).await.expect("spawn");
            let pid = carrier.child_id().expect("child pid");

            // Synchronize with the fake client's transition into its live
            // state. In production, the failed inner handshake itself has
            // already exchanged bytes; a bare spawn does not imply that the
            // child has executed far enough to emit a diagnostic.
            let mut reader = carrier.take_reader().expect("reader");
            let mut ready = [0_u8; 1];
            time::timeout(Duration::from_secs(1), reader.read_exact(&mut ready))
                .await
                .expect("fake client readiness timeout")
                .expect("fake client readiness read");
            assert_eq!(ready, *b"R");
            drop(reader);

            let error = carrier
                .fail_inner_auth("bad peer proof", Duration::from_millis(100))
                .await;
            match error {
                SshTransportError::InnerAuth { message, stderr } => {
                    assert_eq!(message, "bad peer proof");
                    assert_eq!(stderr, "inner-auth process context");
                }
                other => panic!("unexpected error: {other:?}"),
            }
            assert!(
                !process_exists(pid),
                "inner-auth cleanup must kill and reap a live child"
            );
        }

        #[tokio::test]
        async fn dropping_carrier_kills_and_reaps_child() {
            let (_directory, executable) = fake_ssh("exec /bin/sleep 30");
            let client = OpenSshClient::new(executable).expect("client");
            let carrier = client.connect(&pinned_target()).await.expect("spawn");
            let pid = carrier.child_id().expect("child pid");
            assert!(process_exists(pid));

            drop(carrier);
            for _ in 0..100 {
                if !process_exists(pid) {
                    return;
                }
                time::sleep(Duration::from_millis(20)).await;
            }
            panic!("dropped carrier child {pid} was not killed and reaped");
        }

        /// Regression coverage for the `ETXTBSY` spawn race that the previous
        /// in-process [`fake_ssh`] created; that function's comment carries
        /// the mechanism.
        ///
        /// This test is *probabilistic by necessity*, and says so out loud.
        /// The race window is the `open`/`close` pair inside the write
        /// itself, so no safe-Rust test can schedule a sibling `fork` inside
        /// it on demand. What it can do is make the window overwhelmingly
        /// likely to be hit — writer threads materializing fake clients while
        /// forker threads churn `fork`+`exec` — and assert that not one spawn
        /// is refused with `ETXTBSY`. Against the old helper this fails on
        /// essentially every run; against the copy-into-place helper the
        /// refusal is impossible by construction, so the test is stable.
        ///
        /// Only `ETXTBSY` is asserted on. A saturated machine may
        /// legitimately refuse a `fork` with `EAGAIN`, and failing on that
        /// would trade one flake for another.
        #[test]
        fn fake_clients_are_executable_under_concurrent_fork_pressure() {
            const WRITER_THREADS: usize = 4;
            const SCRIPTS_PER_WRITER: usize = 40;
            const FORKER_THREADS: usize = 4;
            // `ETXTBSY` is 26 on Linux and macOS. `ErrorKind::
            // ExecutableFileBusy` would read better but needs Rust 1.83, and
            // the workspace MSRV is 1.75.
            const ETXTBSY: i32 = 26;

            let stop = Arc::new(AtomicBool::new(false));
            let forkers: Vec<_> = (0..FORKER_THREADS)
                .map(|_| {
                    let stop = Arc::clone(&stop);
                    std::thread::spawn(move || {
                        while !stop.load(Ordering::Relaxed) {
                            let _ = StdCommand::new("/bin/true")
                                .stdin(Stdio::null())
                                .stdout(Stdio::null())
                                .stderr(Stdio::null())
                                .status();
                        }
                    })
                })
                .collect();

            let writers: Vec<_> = (0..WRITER_THREADS)
                .map(|_| {
                    std::thread::spawn(|| {
                        let mut refused = 0_usize;
                        for _ in 0..SCRIPTS_PER_WRITER {
                            let (_directory, executable) = fake_ssh("exit 0");
                            let spawned = StdCommand::new(&executable)
                                .stdin(Stdio::null())
                                .stdout(Stdio::null())
                                .stderr(Stdio::null())
                                .status();
                            if let Err(error) = spawned {
                                if error.raw_os_error() == Some(ETXTBSY) {
                                    refused += 1;
                                }
                            }
                        }
                        refused
                    })
                })
                .collect();

            let refused: usize = writers
                .into_iter()
                .map(|writer| writer.join().expect("writer thread"))
                .sum();
            stop.store(true, Ordering::Relaxed);
            for forker in forkers {
                forker.join().expect("forker thread");
            }

            let attempted = WRITER_THREADS * SCRIPTS_PER_WRITER;
            assert_eq!(
                refused, 0,
                "{refused} of {attempted} fake clients were refused with ETXTBSY"
            );
        }
    }
}
