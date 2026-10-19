//! A loopback OpenSSH server with throwaway host and user keys, started by the
//! test and torn down with it. Modelled on the transport crate's
//! `openssh_roundtrip`; it forwards only to the mesh port it was given.
//!
//! Where `sshd` is not installed the test says so and returns; set
//! `AMESH_REQUIRE_SSHD` (CI should) to make that a failure instead, so a
//! runner without it cannot pass quietly.
#![allow(dead_code)]

use agent_mesh_transport_ssh::{HostKeyPolicy, SshTarget};
use std::io::{BufRead as _, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;

/// The longest the test waits for sshd to say it is listening. A hang guard,
/// not a pace: the wait ends the moment sshd reports.
const READY: Duration = Duration::from_secs(60);

pub struct Sshd {
    _dir: TempDir,
    child: Child,
    log: Arc<Mutex<String>>,
    user: String,
    port: u16,
    identity: PathBuf,
    known_hosts: PathBuf,
    pub ssh: PathBuf,
}

fn find(name: &str, dirs: &[&str]) -> Option<PathBuf> {
    dirs.iter()
        .map(|d| Path::new(d).join(name))
        .find(|p| p.is_file())
}

fn run(cmd: &mut Command, what: &str) -> String {
    let out = cmd.output().unwrap_or_else(|e| panic!("{what}: {e}"));
    assert!(
        out.status.success(),
        "{what}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

fn quoted(p: &Path) -> String {
    let s = p.to_str().expect("a UTF-8 path");
    assert!(!s.contains(['\n', '\r', '"']), "{s:?}");
    format!("\"{s}\"")
}

impl Sshd {
    /// Start sshd forwarding only to `mesh_port`, or `None` (loudly) when
    /// OpenSSH is not installed and `AMESH_REQUIRE_SSHD` is not set.
    pub fn start(mesh_port: u16) -> Option<Self> {
        let bins = ["/usr/bin", "/usr/local/bin", "/bin"];
        let sbins = ["/usr/sbin", "/usr/local/sbin", "/sbin", "/usr/bin"];
        let (ssh, keygen, sshd) = (
            find("ssh", &bins),
            find("ssh-keygen", &bins),
            find("sshd", &sbins),
        );
        let (Some(ssh), Some(keygen), Some(sshd)) = (ssh, keygen, sshd) else {
            let why = "OpenSSH (ssh, ssh-keygen, sshd) is not installed";
            assert!(
                std::env::var_os("AMESH_REQUIRE_SSHD").is_none(),
                "{why}, and AMESH_REQUIRE_SSHD is set"
            );
            eprintln!("SKIPPED: {why}; the SSH carrier was NOT exercised");
            return None;
        };
        let user = run(Command::new("id").arg("-un"), "id -un");
        let dir = tempfile::tempdir().unwrap();
        let (host, ident) = (dir.path().join("host"), dir.path().join("user"));
        for key in [&host, &ident] {
            run(
                Command::new(&keygen)
                    .args(["-q", "-t", "ed25519", "-N", ""])
                    .arg("-f")
                    .arg(key),
                "ssh-keygen",
            );
        }
        let authorized = dir.path().join("authorized_keys");
        std::fs::copy(ident.with_extension("pub"), &authorized).unwrap();
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        // the host key is pinned: nothing is trusted on first use
        let hostpub = std::fs::read_to_string(host.with_extension("pub")).unwrap();
        let mut f = hostpub.split_whitespace();
        let known_hosts = dir.path().join("known_hosts");
        std::fs::write(
            &known_hosts,
            format!(
                "[127.0.0.1]:{port} {} {}\n",
                f.next().unwrap(),
                f.next().unwrap()
            ),
        )
        .unwrap();
        let config = dir.path().join("sshd_config");
        std::fs::write(
            &config,
            format!(
                "AddressFamily inet\nListenAddress 127.0.0.1\nPort {port}\nHostKey {}\n\
                 PidFile {}\nAuthorizedKeysFile {}\nStrictModes no\nPubkeyAuthentication yes\n\
                 AuthenticationMethods publickey\nPasswordAuthentication no\n\
                 KbdInteractiveAuthentication no\nUsePAM no\nPermitRootLogin no\nPermitTTY no\n\
                 X11Forwarding no\nAllowAgentForwarding no\nAllowTcpForwarding local\n\
                 PermitOpen 127.0.0.1:{mesh_port}\nGatewayPorts no\nPermitTunnel no\n\
                 PermitUserEnvironment no\nUseDNS no\nLoginGraceTime 5\nMaxAuthTries 3\n\
                 LogLevel VERBOSE\n",
                quoted(&host),
                quoted(&dir.path().join("sshd.pid")),
                quoted(&authorized),
            ),
        )
        .unwrap();
        run(
            Command::new(&sshd).arg("-t").arg("-f").arg(&config),
            "sshd -t",
        );
        let mut child = Command::new(&sshd)
            .args(["-D", "-e", "-f"])
            .arg(&config)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start sshd");
        // sshd logs to stderr; read it until it reports it is listening, and
        // keep draining so it never blocks on a full pipe
        let log = Arc::new(Mutex::new(String::new()));
        let (tx, rx) = mpsc::channel();
        let (out, sink) = (child.stderr.take().unwrap(), log.clone());
        std::thread::spawn(move || {
            let mut said = false;
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                sink.lock().unwrap().push_str(&format!("{line}\n"));
                if !said && line.contains("Server listening on") {
                    said = true;
                    let _ = tx.send(());
                }
            }
        });
        if rx.recv_timeout(READY).is_err() {
            let _ = child.kill();
            panic!("sshd did not start listening:\n{}", log.lock().unwrap());
        }
        Some(Self {
            _dir: dir,
            child,
            log,
            user,
            port,
            identity: ident,
            known_hosts,
            ssh,
        })
    }

    /// The way to the mesh endpoint on this host, through this sshd.
    pub fn target(&self, mesh_port: u16) -> SshTarget {
        SshTarget::new(
            self.user.clone(),
            "127.0.0.1",
            self.port,
            "127.0.0.1",
            mesh_port,
            &self.identity,
            HostKeyPolicy::Pinned {
                known_hosts_file: self.known_hosts.clone(),
            },
        )
        .unwrap()
    }

    pub fn log(&self) -> String {
        self.log.lock().unwrap().clone()
    }
}

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
