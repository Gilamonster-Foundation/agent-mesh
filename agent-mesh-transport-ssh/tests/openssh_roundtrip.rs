#![cfg(target_os = "macos")]

use agent_mesh_bus::{Bus, BusError, Topic, Transport};
use agent_mesh_protocol::{AgentKey, AgentMetadata, Caveats, Fingerprint, UserKey};
use agent_mesh_transport_ssh::{
    HostKeyPolicy, OpenSshClient, SessionTimeouts, SshTarget, SshTransport, SshTransportOptions,
};
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};
use tokio::time::{self, Instant};

const SSH: &str = "/usr/bin/ssh";
const SSHD: &str = "/usr/sbin/sshd";
const SSH_KEYGEN: &str = "/usr/bin/ssh-keygen";
const ID: &str = "/usr/bin/id";

const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const SERVER_READY_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(8);
const OPERATION_TIMEOUT: Duration = Duration::from_secs(12);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(8);

type TestError = Box<dyn Error + Send + Sync>;
type TestResult<T> = Result<T, TestError>;

struct OpenSshServer {
    _dir: TempDir,
    child: Option<Child>,
    log_path: PathBuf,
    username: String,
    ssh_port: u16,
    authorized_identity: PathBuf,
    unauthorized_identity: PathBuf,
    known_hosts: PathBuf,
    unknown_known_hosts: PathBuf,
    changed_known_hosts: PathBuf,
}

impl OpenSshServer {
    async fn start(mesh_port: u16) -> TestResult<Self> {
        for path in [SSH, SSHD, SSH_KEYGEN, ID] {
            require_tool(Path::new(path))?;
        }

        let username = current_username().await?;
        let dir = tempfile::tempdir()?;
        let host_key = dir.path().join("ssh_host_ed25519_key");
        let authorized_identity = dir.path().join("authorized_client_ed25519");
        let unauthorized_identity = dir.path().join("unauthorized_client_ed25519");
        generate_key(&host_key, "ephemeral smoke-test host key").await?;
        generate_key(&authorized_identity, "ephemeral authorized client").await?;
        generate_key(&unauthorized_identity, "ephemeral unauthorized client").await?;

        let authorized_keys = dir.path().join("authorized_keys");
        std::fs::write(
            &authorized_keys,
            std::fs::read(authorized_identity.with_extension("pub"))?,
        )?;

        let ssh_port = unused_loopback_port().await?;
        let known_hosts = dir.path().join("known_hosts");
        write_pinned_known_hosts(&known_hosts, ssh_port, &host_key.with_extension("pub"))?;
        let unknown_known_hosts = dir.path().join("unknown_known_hosts");
        std::fs::write(&unknown_known_hosts, b"")?;
        let changed_known_hosts = dir.path().join("changed_known_hosts");
        write_pinned_known_hosts(
            &changed_known_hosts,
            ssh_port,
            &unauthorized_identity.with_extension("pub"),
        )?;

        let pid_path = dir.path().join("sshd.pid");
        let log_path = dir.path().join("sshd.log");
        let config_path = dir.path().join("sshd_config");
        let config = format!(
            "AddressFamily inet\n\
             ListenAddress 127.0.0.1\n\
             Port {ssh_port}\n\
             HostKey {}\n\
             PidFile {}\n\
             AuthorizedKeysFile {}\n\
             StrictModes no\n\
             PubkeyAuthentication yes\n\
             AuthenticationMethods publickey\n\
             PasswordAuthentication no\n\
             KbdInteractiveAuthentication no\n\
             UsePAM no\n\
             PermitRootLogin no\n\
             PermitTTY no\n\
             X11Forwarding no\n\
             AllowAgentForwarding no\n\
             AllowTcpForwarding local\n\
             PermitOpen 127.0.0.1:{mesh_port}\n\
             GatewayPorts no\n\
             PermitTunnel no\n\
             PermitUserEnvironment no\n\
             UseDNS no\n\
             LoginGraceTime 5\n\
             MaxAuthTries 3\n\
             LogLevel VERBOSE\n",
            sshd_path(&host_key)?,
            sshd_path(&pid_path)?,
            sshd_path(&authorized_keys)?,
        );
        std::fs::write(&config_path, config)?;

        let mut validate = Command::new(SSHD);
        validate.arg("-t").arg("-f").arg(&config_path);
        run_checked(&mut validate, "validate the generated sshd configuration").await?;

        let stderr = std::fs::File::create(&log_path)?;
        let mut child = Command::new(SSHD)
            .arg("-D")
            .arg("-e")
            .arg("-f")
            .arg(&config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr))
            .kill_on_drop(true)
            .spawn()
            .map_err(|error| failure(format!("failed to start {SSHD}: {error}")))?;

        wait_until_ready(&mut child, ssh_port, &log_path).await?;
        Ok(Self {
            _dir: dir,
            child: Some(child),
            log_path,
            username,
            ssh_port,
            authorized_identity,
            unauthorized_identity,
            known_hosts,
            unknown_known_hosts,
            changed_known_hosts,
        })
    }

    fn target(&self, mesh_port: u16, identity: &Path, known_hosts: &Path) -> TestResult<SshTarget> {
        Ok(SshTarget::new(
            self.username.clone(),
            "127.0.0.1",
            self.ssh_port,
            "127.0.0.1",
            mesh_port,
            identity,
            HostKeyPolicy::Pinned {
                known_hosts_file: known_hosts.to_path_buf(),
            },
        )?)
    }

    fn authorized_target(&self, mesh_port: u16) -> TestResult<SshTarget> {
        self.target(mesh_port, &self.authorized_identity, &self.known_hosts)
    }

    fn unauthorized_target(&self, mesh_port: u16) -> TestResult<SshTarget> {
        self.target(mesh_port, &self.unauthorized_identity, &self.known_hosts)
    }

    fn unknown_host_target(&self, mesh_port: u16) -> TestResult<SshTarget> {
        self.target(
            mesh_port,
            &self.authorized_identity,
            &self.unknown_known_hosts,
        )
    }

    fn changed_host_target(&self, mesh_port: u16) -> TestResult<SshTarget> {
        self.target(
            mesh_port,
            &self.authorized_identity,
            &self.changed_known_hosts,
        )
    }

    fn diagnostics(&self) -> String {
        std::fs::read_to_string(&self.log_path)
            .unwrap_or_else(|error| format!("<unable to read sshd log: {error}>"))
    }

    async fn shutdown(&mut self) -> TestResult<()> {
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };
        let _ = child.start_kill();
        time::timeout(CLEANUP_TIMEOUT, child.wait())
            .await
            .map_err(|_| failure("timed out reaping the ephemeral sshd"))?
            .map_err(|error| failure(format!("failed to reap the ephemeral sshd: {error}")))?;
        Ok(())
    }
}

impl Drop for OpenSshServer {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = child.start_kill();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = time::timeout(CLEANUP_TIMEOUT, child.wait()).await;
            });
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_openssh_enforces_both_ssh_and_mesh_authentication() {
    if let Err(error) = run_smoke_test().await {
        panic!("OpenSSH transport smoke test failed: {error}");
    }
}

async fn run_smoke_test() -> TestResult<()> {
    let user = UserKey::generate();
    let hub_agent = agent(&user, "hub");
    let hub_fp = hub_agent.fingerprint();
    let spoke_agent = agent(&user, "spoke");
    let valid_but_ssh_unauthorized_agent = agent(&user, "ssh-unauthorized");
    let unknown_host_agent = agent(&user, "unknown-host");
    let changed_host_agent = agent(&user, "changed-host");
    let foreign_user = UserKey::generate();
    let foreign_agent = agent(&foreign_user, "foreign-root");

    let hub_transport = Arc::new(
        SshTransport::bind(
            hub_agent.clone(),
            "127.0.0.1:0".parse()?,
            transport_options(),
        )
        .await?,
    );
    let mesh_port = hub_transport.local_addr().port();
    let hub_bus = Bus::bind_with_transport(
        hub_agent.clone(),
        hub_transport.clone() as Arc<dyn Transport>,
    )?;
    let topic = Topic::new(user.fingerprint(), "openssh-smoke");
    let handled = Arc::new(AtomicUsize::new(0));
    let handled_by_handler = handled.clone();
    hub_bus.handle_requests_with_context(topic.clone(), move |context, body| {
        handled_by_handler.fetch_add(1, Ordering::SeqCst);
        let response = format!(
            "{}|{}|{}",
            context.caller_user_fp.hex(),
            context.caller_agent_fp.hex(),
            String::from_utf8_lossy(&body),
        )
        .into_bytes();
        async move { Ok(response) }
    });

    let mut server = OpenSshServer::start(mesh_port).await?;
    let scenarios = exercise_authentication_boundaries(
        &server,
        mesh_port,
        &topic,
        hub_fp,
        user.fingerprint(),
        spoke_agent,
        valid_but_ssh_unauthorized_agent,
        unknown_host_agent,
        changed_host_agent,
        foreign_agent,
        handled.clone(),
    )
    .await;
    let hub_close = close_bus(hub_bus, "hub bus").await;
    let server_close = server.shutdown().await;

    if let Err(error) = scenarios {
        return Err(failure(format!(
            "{error}\n--- ephemeral sshd log ---\n{}",
            server.diagnostics()
        )));
    }
    hub_close?;
    server_close?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn exercise_authentication_boundaries(
    server: &OpenSshServer,
    mesh_port: u16,
    topic: &Topic,
    hub_fp: Fingerprint,
    expected_user: Fingerprint,
    spoke_agent: Arc<AgentKey>,
    ssh_unauthorized_agent: Arc<AgentKey>,
    unknown_host_agent: Arc<AgentKey>,
    changed_host_agent: Arc<AgentKey>,
    foreign_agent: Arc<AgentKey>,
    handled: Arc<AtomicUsize>,
) -> TestResult<()> {
    let expected_spoke = spoke_agent.fingerprint();
    let authorized =
        bind_spoke(spoke_agent, (hub_fp, server.authorized_target(mesh_port)?)).await?;
    let reply_result = time::timeout(
        OPERATION_TIMEOUT,
        authorized.request(hub_fp, topic, b"ping".to_vec(), REQUEST_TIMEOUT),
    )
    .await;
    let authorized_close = close_bus(authorized, "authorized spoke bus").await;
    let reply = reply_result
        .map_err(|_| failure("authorized OpenSSH request exceeded its outer deadline"))??;
    authorized_close?;
    let expected_reply =
        format!("{}|{}|ping", expected_user.hex(), expected_spoke.hex()).into_bytes();
    ensure(
        reply == expected_reply,
        format!(
            "request/reply caller context mismatch: expected {:?}, got {:?}",
            String::from_utf8_lossy(&expected_reply),
            String::from_utf8_lossy(&reply)
        ),
    )?;

    let unknown_host = bind_spoke(
        unknown_host_agent,
        (hub_fp, server.unknown_host_target(mesh_port)?),
    )
    .await?;
    let unknown_host_result = time::timeout(
        OPERATION_TIMEOUT,
        unknown_host.request(hub_fp, topic, b"unknown-host".to_vec(), REQUEST_TIMEOUT),
    )
    .await;
    let unknown_host_close = close_bus(unknown_host, "unknown-host spoke bus").await;
    let unknown_host_error = unknown_host_result
        .map_err(|_| failure("unknown-host pinned request exceeded its outer deadline"))?
        .expect_err("strict pinned mode must reject an absent host-key entry");
    unknown_host_close?;
    assert_pre_mesh_process_failure("unknown host key", &unknown_host_error)?;

    let changed_host = bind_spoke(
        changed_host_agent,
        (hub_fp, server.changed_host_target(mesh_port)?),
    )
    .await?;
    let changed_host_result = time::timeout(
        OPERATION_TIMEOUT,
        changed_host.request(hub_fp, topic, b"changed-host".to_vec(), REQUEST_TIMEOUT),
    )
    .await;
    let changed_host_close = close_bus(changed_host, "changed-host spoke bus").await;
    let changed_host_error = changed_host_result
        .map_err(|_| failure("changed-host pinned request exceeded its outer deadline"))?
        .expect_err("strict pinned mode must reject a changed host key");
    changed_host_close?;
    assert_pre_mesh_process_failure("changed host key", &changed_host_error)?;

    let unauthorized = bind_spoke(
        ssh_unauthorized_agent,
        (hub_fp, server.unauthorized_target(mesh_port)?),
    )
    .await?;
    let unauthorized_result = time::timeout(
        OPERATION_TIMEOUT,
        unauthorized.request(hub_fp, topic, b"must-not-arrive".to_vec(), REQUEST_TIMEOUT),
    )
    .await;
    let unauthorized_close = close_bus(unauthorized, "SSH-unauthorized spoke bus").await;
    let unauthorized_error = unauthorized_result
        .map_err(|_| failure("unauthorized SSH request exceeded its outer deadline"))?
        .expect_err("an SSH key absent from AuthorizedKeysFile must be rejected");
    unauthorized_close?;
    assert_ssh_access_failure(&unauthorized_error)?;

    let foreign = bind_spoke(
        foreign_agent,
        (hub_fp, server.authorized_target(mesh_port)?),
    )
    .await?;
    let foreign_result = time::timeout(
        OPERATION_TIMEOUT,
        foreign.request(hub_fp, topic, b"foreign-root".to_vec(), REQUEST_TIMEOUT),
    )
    .await;
    let foreign_close = close_bus(foreign, "foreign-root spoke bus").await;
    let foreign_error = foreign_result
        .map_err(|_| failure("foreign-root inner-auth request exceeded its outer deadline"))?
        .expect_err("an AgentKey rooted in another UserKey must be rejected");
    foreign_close?;
    assert_foreign_root_failure(&foreign_error)?;
    ensure(
        handled.load(Ordering::SeqCst) == 1,
        "rejected SSH or inner-mesh clients reached the request handler",
    )?;
    Ok(())
}

async fn bind_spoke(
    agent: Arc<AgentKey>,
    (hub_fp, target): (Fingerprint, SshTarget),
) -> TestResult<Bus> {
    let transport = Arc::new(
        SshTransport::bind_with_client(
            agent.clone(),
            "127.0.0.1:0".parse()?,
            transport_options(),
            OpenSshClient::new(SSH)?,
        )
        .await?,
    );
    transport.add_target(hub_fp, target);
    Ok(Bus::bind_with_transport(
        agent,
        transport as Arc<dyn Transport>,
    )?)
}

fn assert_ssh_access_failure(error: &BusError) -> TestResult<()> {
    assert_pre_mesh_process_failure("unauthorized SSH client key", error)
}

fn assert_pre_mesh_process_failure(label: &str, error: &BusError) -> TestResult<()> {
    ensure(
        matches!(error, BusError::TransportBackend(_)),
        format!("unexpected {label} error type: {error}"),
    )?;
    let rendered = error.to_string();
    ensure(
        rendered.contains("ssh process exited during inner mesh authentication failed"),
        format!("{label} failure did not expose process exit context: {rendered}"),
    )?;
    ensure(
        rendered.contains("status Some(255)"),
        format!("{label} failure did not expose exit status 255: {rendered}"),
    )?;
    let stderr = rendered
        .rsplit_once("): ")
        .map(|(_, stderr)| stderr.trim())
        .unwrap_or_default();
    ensure(
        !stderr.is_empty(),
        format!("{label} failure did not expose stderr: {rendered}"),
    )
}

fn assert_foreign_root_failure(error: &BusError) -> TestResult<()> {
    ensure(
        matches!(error, BusError::TransportBackend(_)),
        format!("unexpected foreign-root error type: {error}"),
    )?;
    let rendered = error.to_string();
    ensure(
        rendered.contains("inner mesh authentication failed")
            && rendered.contains("peer user")
            && rendered.contains("does not match local user"),
        format!("foreign UserKey was not rejected by inner authentication: {rendered}"),
    )
}

async fn close_bus(bus: Bus, label: &str) -> TestResult<()> {
    time::timeout(CLEANUP_TIMEOUT, bus.close())
        .await
        .map_err(|_| failure(format!("timed out closing {label}")))??;
    Ok(())
}

fn transport_options() -> SshTransportOptions {
    SshTransportOptions {
        session_timeouts: SessionTimeouts {
            authentication: Duration::from_secs(5),
            record: Duration::from_secs(8),
        },
        ..SshTransportOptions::default()
    }
}

fn agent(user: &UserKey, role: &str) -> Arc<AgentKey> {
    Arc::new(AgentKey::issue(
        user,
        AgentMetadata {
            role: role.into(),
            host: "openssh-smoke".into(),
            capabilities: vec!["test".into()],
            issued_at: "2026-08-14T00:00:00Z".into(),
            expires_at: None,
            caveats: Caveats::top(),
        },
    ))
}

async fn current_username() -> TestResult<String> {
    let mut command = Command::new(ID);
    command.arg("-un");
    let output = run_checked(
        &mut command,
        "determine the current user with /usr/bin/id -un",
    )
    .await?;
    let username = String::from_utf8(output.stdout)
        .map_err(|error| {
            failure(format!(
                "/usr/bin/id -un returned non-UTF-8 output: {error}"
            ))
        })?
        .trim()
        .to_string();
    ensure(
        !username.is_empty(),
        "/usr/bin/id -un returned an empty username",
    )?;
    ensure(
        !username.chars().any(char::is_whitespace),
        format!("current username cannot be represented as an SSH target: {username:?}"),
    )?;
    Ok(username)
}

async fn generate_key(path: &Path, comment: &str) -> TestResult<()> {
    let mut command = Command::new(SSH_KEYGEN);
    command
        .arg("-q")
        .arg("-t")
        .arg("ed25519")
        .arg("-N")
        .arg("")
        .arg("-C")
        .arg(comment)
        .arg("-f")
        .arg(path);
    run_checked(
        &mut command,
        &format!("generate ephemeral key at {}", path.display()),
    )
    .await?;
    Ok(())
}

async fn unused_loopback_port() -> TestResult<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

fn write_pinned_known_hosts(path: &Path, ssh_port: u16, host_public_key: &Path) -> TestResult<()> {
    let public_key = std::fs::read_to_string(host_public_key)?;
    let mut fields = public_key.split_whitespace();
    let algorithm = fields
        .next()
        .ok_or_else(|| failure("generated host public key had no algorithm"))?;
    let key = fields
        .next()
        .ok_or_else(|| failure("generated host public key had no key data"))?;
    std::fs::write(path, format!("[127.0.0.1]:{ssh_port} {algorithm} {key}\n"))?;
    Ok(())
}

fn sshd_path(path: &Path) -> TestResult<String> {
    let path = path
        .to_str()
        .ok_or_else(|| failure(format!("sshd fixture path is not UTF-8: {path:?}")))?;
    ensure(
        !path.contains('\n') && !path.contains('\r'),
        format!("sshd fixture path contains a newline: {path:?}"),
    )?;
    Ok(format!(
        "\"{}\"",
        path.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

async fn run_checked(command: &mut Command, description: &str) -> TestResult<Output> {
    let output = time::timeout(COMMAND_TIMEOUT, command.output())
        .await
        .map_err(|_| failure(format!("timed out trying to {description}")))?
        .map_err(|error| failure(format!("failed to {description}: {error}")))?;
    ensure(
        output.status.success(),
        format!(
            "failed to {description} (status {:?})\nstdout: {}\nstderr: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ),
    )?;
    Ok(output)
}

async fn wait_until_ready(child: &mut Child, ssh_port: u16, log_path: &Path) -> TestResult<()> {
    let deadline = Instant::now() + SERVER_READY_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait()? {
            return Err(failure(format!(
                "ephemeral sshd exited before becoming ready (status {:?}): {}",
                status.code(),
                read_log(log_path)
            )));
        }
        if matches!(
            time::timeout(
                Duration::from_millis(250),
                TcpStream::connect(("127.0.0.1", ssh_port))
            )
            .await,
            Ok(Ok(_))
        ) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(failure(format!(
                "ephemeral sshd did not listen on 127.0.0.1:{ssh_port} within {SERVER_READY_TIMEOUT:?}: {}",
                read_log(log_path)
            )));
        }
        time::sleep(Duration::from_millis(50)).await;
    }
}

fn read_log(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|error| format!("<unable to read sshd log: {error}>"))
}

fn require_tool(path: &Path) -> TestResult<()> {
    let usable = path.metadata().is_ok_and(|metadata| metadata.is_file());
    ensure(
        usable,
        format!(
            "required OpenSSH smoke-test tool is missing at {}; install the OpenSSH client/server tools or provision this Unix runner accordingly",
            path.display()
        ),
    )
}

fn ensure(condition: bool, message: impl Into<String>) -> TestResult<()> {
    if condition {
        Ok(())
    } else {
        Err(failure(message))
    }
}

fn failure(message: impl Into<String>) -> TestError {
    Box::new(io::Error::other(message.into()))
}
