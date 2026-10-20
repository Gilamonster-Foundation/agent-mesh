//! `amesh flock` — the flock server's command line.

use crate::util;
#[cfg(unix)]
use agent_mesh_flock::{Body, Kind};
use agent_mesh_flock::{Member, Role};
use agent_mesh_flock_server::{init as flock_init, InitSpec};
use agent_mesh_protocol::UserKey;
use anyhow::{anyhow, Context, Result};
use clap::Subcommand;
use rand::RngCore;
use std::path::PathBuf;

#[cfg(unix)]
mod close;
#[cfg(unix)]
mod discover;
#[cfg(unix)]
mod emit;
#[cfg(unix)]
pub(crate) mod mcp;
#[cfg(unix)]
mod nudge;
#[cfg(unix)]
mod nudging;
mod panes;
#[cfg(unix)]
mod read;
#[cfg(unix)]
mod run;
#[cfg(unix)]
mod watch;

#[cfg(unix)]
use discover::Where;

/// `amesh flock` subcommands.
#[derive(Subcommand, Debug)]
pub enum FlockCommand {
    /// Create a flock: mint its server key and genesis, once (like `git init`).
    Init {
        /// Flock name.
        #[arg(long)]
        name: String,
        /// A roster member as `name:role` (repeatable). Roles: shepherd,
        /// reviewer, helper, adapter, operator.
        #[arg(long = "member", required = true)]
        members: Vec<String>,
        /// Flock directory (defaults to `<home>/flocks/<name>`).
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Serve the flock's log on a local socket (owns the log; run once).
    #[cfg(unix)]
    Serve {
        /// Flock directory.
        #[arg(long)]
        dir: PathBuf,
        /// Also serve the attach socket (`run/attach.sock`, mode 0600), the
        /// surface a remote host's bridge connects to. It offers enroll, renew,
        /// admit and watch, never an invite. Without it nothing remote can
        /// reach this flock.
        #[arg(long)]
        attach: bool,
        /// Also offer this flock to other hosts of the same user over the
        /// mesh: each stream a remote opens is piped to the attach socket (so
        /// the allow-list applies). Needs `--attach` and a user key
        /// (`amesh keygen`). Prints `bridge <agent fingerprint> <agent pubkey>
        /// <port>`, what a remote's `attach --peer` needs.
        #[arg(long, requires = "attach")]
        bridge: bool,
        /// The UDP port the bridge listens on (0 = any).
        #[arg(long, default_value_t = 0, requires = "bridge")]
        bridge_port: u16,
        /// Do not announce the bridge on mDNS: peers must dial it with
        /// `--peer <pubkey>@<addr>`.
        #[arg(long, requires = "bridge")]
        bridge_quiet: bool,
        /// A directory a member may cite files from, `name=path` (repeatable).
        /// The roster declares the name (the log never holds the path); a
        /// member of the flock can read, through the attach socket, a file
        /// under it whose bytes still hash to the id it was cited with.
        #[arg(long = "root")]
        roots: Vec<String>,
    },
    /// Attach to a flock served by another host of the same user: fetch its
    /// genesis (refused unless it is the flock `--id` names), then serve
    /// `<dir>/run/serve.sock` for the local session, reader and TUI, piping
    /// each connection to the home over the mesh. Holds no key.
    #[cfg(unix)]
    Attach {
        /// Where to keep the flock locally.
        #[arg(long)]
        dir: PathBuf,
        /// The flock's id (the genesis hash): the anchor you were given.
        #[arg(long)]
        id: String,
        /// The home bridge: `<agent pubkey hex>@<ip:port>` to dial it, or its
        /// agent fingerprint to find it on the local network.
        #[arg(long)]
        peer: String,
    },
    /// Mint an invite for a member through the running server; prints the
    /// token once.
    #[cfg(unix)]
    Invite {
        /// Flock directory.
        #[arg(long)]
        dir: PathBuf,
        /// The roster member.
        member: String,
    },
    /// Hold one session key in memory and serve the CLI over a socket
    /// (like ssh-agent -D). The key is locked in RAM; core dumps are off.
    #[cfg(unix)]
    Session {
        /// Flock directory (where the server's socket is).
        #[arg(long)]
        dir: PathBuf,
        /// The roster member to enroll as.
        #[arg(long)]
        member: String,
        /// Invite token. Prefer the environment: argv shows in `ps`.
        #[arg(long, env = "AMESH_FLOCK_TOKEN", hide_env_values = true)]
        token: String,
        /// Where to listen (default: `<dir>/run/session-<pid>.sock`).
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Carry on if memory cannot be locked: the key may reach swap.
        #[arg(long)]
        allow_unlocked: bool,
    },
    /// Which session this is, and optionally tell the log its herdr pane.
    #[cfg(unix)]
    Join {
        #[command(flatten)]
        at: Where,
        /// Also announce the herdr pane this session runs in.
        #[arg(long)]
        announce: bool,
    },
    /// Briefs and reviews addressed to this session's member and still open.
    #[cfg(unix)]
    Inbox {
        #[command(flatten)]
        at: Where,
    },
    /// Every lane and where it stands.
    #[cfg(unix)]
    Status {
        #[command(flatten)]
        at: Where,
    },
    /// The admitted events in order, with their content ids.
    #[cfg(unix)]
    Log {
        #[command(flatten)]
        at: Where,
        /// First admission index to show.
        #[arg(long, default_value_t = 0)]
        from: u64,
    },
    /// Shepherd: give a member a task.
    #[cfg(unix)]
    Brief {
        #[command(flatten)]
        at: Where,
        /// The addressee.
        #[arg(long)]
        to: String,
        /// The lane.
        #[arg(long)]
        lane: String,
    },
    /// Shepherd: ask a member to review a head.
    #[cfg(unix)]
    Review {
        #[command(flatten)]
        at: Where,
        /// The reviewer.
        #[arg(long)]
        to: String,
        /// The lane.
        #[arg(long)]
        lane: String,
        /// The head under review.
        #[arg(long)]
        head: String,
    },
    /// Acknowledge a brief or review (an `ack`).
    #[cfg(unix)]
    Take {
        #[command(flatten)]
        at: Where,
        /// The brief or review's content id.
        cid: String,
    },
    /// Close a brief with its outcome.
    #[cfg(unix)]
    Result {
        #[command(flatten)]
        at: Where,
        /// The brief's content id (or use `--lane`).
        #[arg(required_unless_present = "lane")]
        brief: Option<String>,
        /// Close this member's open brief in this lane instead of naming it.
        /// Refused when there is none or several.
        #[arg(long, conflicts_with = "brief")]
        lane: Option<String>,
        /// `completed` or `failed`.
        #[arg(long)]
        outcome: String,
    },
    /// Close a review with a verdict.
    #[cfg(unix)]
    Verdict {
        #[command(flatten)]
        at: Where,
        /// The review's content id (or use `--lane`).
        #[arg(required_unless_present = "lane")]
        review: Option<String>,
        /// Close this member's open review in this lane instead of naming it.
        /// Refused when there is none or several.
        #[arg(long, conflicts_with = "review")]
        lane: Option<String>,
        /// The head the review named.
        #[arg(long)]
        head: String,
        /// Approve it.
        #[arg(long, conflicts_with = "reject")]
        approve: bool,
        /// Reject it.
        #[arg(long)]
        reject: bool,
    },
    /// Run a command as a job: a `job` event, the command, then a `job-end`
    /// with its exit code or the signal that ended it. Exits as the command did.
    #[cfg(unix)]
    Run {
        #[command(flatten)]
        at: Where,
        /// The lane the job belongs to.
        #[arg(long)]
        lane: String,
        /// A short label (default: the command's name).
        #[arg(long)]
        label: Option<String>,
        /// The command and its arguments, after `--`.
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
    /// Follow the log: every frame is verified against the reader's saved
    /// state, saved, then printed. Stops when the server closes the stream.
    #[cfg(unix)]
    Watch {
        #[command(flatten)]
        at: Where,
        /// First show saved events from this admission index on.
        #[arg(long)]
        from: Option<u64>,
        /// Stop once caught up instead of following.
        #[arg(long)]
        once: bool,
    },
    /// Operator: mint this machine's answer-signing device. Asks for a
    /// passphrase twice on the terminal, stores the seed age-encrypted and
    /// prints the certificate to register.
    #[cfg(unix)]
    DeviceInit {
        /// Where the device lives (default `<home>/operator`).
        #[arg(long)]
        device_dir: Option<PathBuf>,
    },
    /// Owner: register a device's certificate with the running server. This
    /// grants nothing until the roster lists the device.
    #[cfg(unix)]
    DeviceRegister {
        /// Flock directory.
        #[arg(long)]
        dir: PathBuf,
        /// The certificate file `device-init` wrote.
        #[arg(long)]
        cert: PathBuf,
    },
    /// Operator: the answer signer. Run it on your own terminal; it shows each
    /// answer and signs only after you type `y` and your passphrase.
    #[cfg(unix)]
    Sign {
        /// Flock directory.
        #[arg(long)]
        dir: PathBuf,
        /// Where the device lives (default `<home>/operator`).
        #[arg(long)]
        device_dir: Option<PathBuf>,
    },
    /// Ask the running signer to sign and admit an answer to an ask.
    #[cfg(unix)]
    Answer {
        /// Flock directory.
        #[arg(long)]
        dir: PathBuf,
        /// The ask's content id.
        #[arg(long)]
        ask: String,
        /// The answer.
        #[arg(long)]
        text: String,
        /// Where the device lives (default `<home>/operator`).
        #[arg(long)]
        device_dir: Option<PathBuf>,
    },
    /// The herdr adapter: prompt a member's pane to `take` a brief or review
    /// addressed to it, and record that (or why not) in the log. Run it as the
    /// adapter member's session. Best effort: herdr cannot prompt only if idle.
    #[cfg(unix)]
    Nudge {
        #[command(flatten)]
        at: Where,
        #[command(flatten)]
        opts: nudging::Opts,
    },
    /// Show the roster next to the herdr panes that carry its members.
    /// Read-only: reads the log without its lock and asks herdr only to list.
    Panes {
        /// Flock name.
        #[arg(long)]
        name: String,
        /// Flock directory (defaults to `<home>/flocks/<name>`).
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Only panes in this herdr tab (pane labels repeat across tabs).
        #[arg(long)]
        tab: Option<String>,
        /// Map a member to a pane id, `member=pane` (repeatable). Otherwise a
        /// member is the pane whose label is its name.
        #[arg(long = "map")]
        maps: Vec<String>,
    },
}

/// Dispatch a flock subcommand.
pub async fn run(home: PathBuf, cmd: FlockCommand) -> Result<()> {
    match cmd {
        FlockCommand::Init { name, members, dir } => init(home, name, &members, dir),
        #[cfg(unix)]
        FlockCommand::Serve {
            dir,
            attach,
            bridge,
            bridge_port,
            bridge_quiet,
            roots,
        } => {
            let bridge = bridge.then_some((bridge_port, !bridge_quiet));
            let roots = unix::parse_roots(&roots)?;
            unix::serve(&home, &dir, attach, bridge, roots).await
        }
        #[cfg(unix)]
        FlockCommand::Attach { dir, id, peer } => unix::attach(&home, &dir, &id, &peer).await,
        #[cfg(unix)]
        FlockCommand::Invite { dir, member } => unix::invite(&dir, &member),
        #[cfg(unix)]
        FlockCommand::Session {
            dir,
            member,
            token,
            socket,
            allow_unlocked,
        } => unix::session(&dir, &member, &token, socket, allow_unlocked),
        #[cfg(unix)]
        FlockCommand::Join { at, announce } => emit::join(&home, &at, announce),
        #[cfg(unix)]
        FlockCommand::Inbox { at } => read::inbox(&home, &at),
        #[cfg(unix)]
        FlockCommand::Status { at } => read::status(&home, &at),
        #[cfg(unix)]
        FlockCommand::Log { at, from } => read::log(&home, &at, from),
        #[cfg(unix)]
        FlockCommand::Brief { at, to, lane } => {
            emit::emit(&home, &at, Kind::Brief, &[], Body::Brief { to, lane })
        }
        #[cfg(unix)]
        FlockCommand::Review { at, to, lane, head } => emit::emit(
            &home,
            &at,
            Kind::Review,
            &[],
            Body::Review { to, lane, head },
        ),
        #[cfg(unix)]
        FlockCommand::Take { at, cid } => {
            emit::emit(&home, &at, Kind::Ack, &[("of", &cid)], Body::Ack)
        }
        #[cfg(unix)]
        FlockCommand::Result {
            at,
            brief,
            lane,
            outcome,
        } => {
            let outcome = emit::parse_outcome(&outcome)?;
            let brief = close::pick(
                &home,
                &at,
                close::Closing::Brief,
                brief.as_deref(),
                lane.as_deref(),
            )?;
            emit::emit(
                &home,
                &at,
                Kind::Result,
                &[("brief", &brief)],
                Body::Result { outcome },
            )
        }
        #[cfg(unix)]
        FlockCommand::Verdict {
            at,
            review,
            lane,
            head,
            approve,
            reject,
        } => {
            if approve == reject {
                return Err(anyhow!("say exactly one of --approve or --reject"));
            }
            let review = close::pick(
                &home,
                &at,
                close::Closing::Review,
                review.as_deref(),
                lane.as_deref(),
            )?;
            emit::emit(
                &home,
                &at,
                Kind::Verdict,
                &[("review", &review)],
                Body::Verdict {
                    head,
                    approved: approve,
                },
            )
        }
        #[cfg(unix)]
        FlockCommand::Run {
            at,
            lane,
            label,
            cmd,
        } => {
            let code = run::run(&home, &at, lane, label, &cmd)?;
            if code != 0 {
                std::process::exit(code);
            }
            Ok(())
        }
        #[cfg(unix)]
        FlockCommand::Watch { at, from, once } => watch::watch(&home, &at, from, once),
        #[cfg(unix)]
        FlockCommand::DeviceInit { device_dir } => unix::device_init(&home, device_dir),
        #[cfg(unix)]
        FlockCommand::DeviceRegister { dir, cert } => unix::device_register(&dir, &cert),
        #[cfg(unix)]
        FlockCommand::Sign { dir, device_dir } => unix::sign(&home, &dir, device_dir),
        #[cfg(unix)]
        FlockCommand::Answer {
            dir,
            ask,
            text,
            device_dir,
        } => unix::answer(&home, &dir, &ask, text, device_dir),
        #[cfg(unix)]
        FlockCommand::Nudge { at, opts } => nudging::run(&home, &at, &opts),
        FlockCommand::Panes {
            name,
            dir,
            tab,
            maps,
        } => panes::panes(&home, &name, dir, tab.as_deref(), &maps),
    }
}

fn parse_member(spec: &str) -> Result<Member> {
    let (name, role) = spec
        .split_once(':')
        .filter(|(n, _)| !n.is_empty())
        .ok_or_else(|| anyhow!("member '{spec}' must be name:role"))?;
    let role: Role =
        serde_json::from_value(serde_json::Value::String(role.into())).map_err(|_| {
            anyhow!(
                "unknown role '{role}' — expected shepherd, reviewer, helper, adapter or operator"
            )
        })?;
    Ok(Member {
        name: name.into(),
        role,
        devices: vec![],
        delegate: false,
    })
}

fn init(home: PathBuf, name: String, members: &[String], dir: Option<PathBuf>) -> Result<()> {
    let roster = members
        .iter()
        .map(|m| parse_member(m))
        .collect::<Result<Vec<_>>>()?;
    let key_path = home.join("user.key");
    let user = UserKey::load(&key_path)
        .with_context(|| format!("load {} — run `amesh keygen` first?", key_path.display()))?;
    let dir = dir.unwrap_or_else(|| home.join("flocks").join(&name));
    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let spec = InitSpec {
        name,
        roster,
        salt: hex::encode(salt),
        host: util::current_hostname(),
        issued_at: util::now_rfc3339(),
    };
    let flock = flock_init(&dir, &user, spec)
        .with_context(|| format!("init flock in {}", dir.display()))?;
    println!("flock id: {flock}");
    println!("dir:      {}", dir.display());
    Ok(())
}

#[cfg(unix)]
mod unix {
    use super::{anyhow, Context, PathBuf, Result};
    use crate::flock_bridge;
    use agent_mesh_bus::{Bus, BusOptions, PeerEndpoint};
    use agent_mesh_flock_server::wire::{read_msg, write_msg, Req, Resp};
    use agent_mesh_flock_server::{bind_private, serve as serve_log, serve_with_attach, Server};
    use agent_mesh_flock_session::Policy;
    use agent_mesh_protocol::{AgentKey, AgentMetadata, Caveats, Fingerprint, UserKey};
    use anyhow::bail;
    use content_addressable::{ContentAddressable as _, ContentId};
    use std::os::unix::net::UnixStream;
    use std::path::Path;

    fn sock(dir: &Path) -> PathBuf {
        dir.join("run").join("serve.sock")
    }

    fn attach_sock(dir: &Path) -> PathBuf {
        dir.join("run").join("attach.sock")
    }

    /// The bus identity this host uses for the flock: its user key's agent.
    fn bus_identity(home: &Path, role: &str) -> Result<(UserKey, AgentKey)> {
        let key_path = home.join("user.key");
        let user = UserKey::load(&key_path)
            .with_context(|| format!("load {} — run `amesh keygen` first", key_path.display()))?;
        let agent = AgentKey::issue(
            &user,
            AgentMetadata {
                role: role.into(),
                host: crate::util::current_hostname(),
                capabilities: vec![],
                issued_at: crate::util::now_rfc3339(),
                expires_at: None,
                caveats: Caveats::top(),
            },
        );
        Ok((user, agent))
    }

    /// `name=path` pairs: a plain, unique name and an existing directory.
    pub fn parse_roots(raw: &[String]) -> Result<std::collections::BTreeMap<String, PathBuf>> {
        let mut out = std::collections::BTreeMap::new();
        for r in raw {
            let (name, path) = r
                .split_once('=')
                .ok_or_else(|| anyhow!("--root wants name=path, got {r:?}"))?;
            if !agent_mesh_flock::roots_well_formed(&[name.to_owned()]) {
                bail!("--root name {name:?} is not a plain name");
            }
            let path = PathBuf::from(path);
            if !path.is_dir() {
                bail!("--root {name}: {} is not a directory", path.display());
            }
            if out.insert(name.to_owned(), path).is_some() {
                bail!("--root {name} given twice");
            }
        }
        Ok(out)
    }

    pub async fn serve(
        home: &Path,
        dir: &Path,
        attach: bool,
        bridge: Option<(u16, bool)>,
        roots: std::collections::BTreeMap<String, PathBuf>,
    ) -> Result<()> {
        let mut server = Server::open(dir).with_context(|| format!("open {}", dir.display()))?;
        server.serve_roots(roots).context("declare the roots")?;
        let id = server.genesis().content_id()?;
        // The log lock is ours, so any socket file left behind is stale.
        let listener = bind_private(&sock(dir))?;
        let serving = if attach {
            let remote = bind_private(&attach_sock(dir))?;
            println!("serving {}", sock(dir).display());
            println!("attach {}", attach_sock(dir).display());
            serve_with_attach(server, listener, remote)?
        } else {
            println!("serving {}", sock(dir).display());
            serve_log(server, listener)?
        };
        let _bus = match bridge {
            Some((port, announce)) => {
                let (user, agent) = bus_identity(home, "amesh-flock-bridge")?;
                let (fp, pubkey) = (agent.fingerprint(), agent.public_bytes());
                let bus = Bus::bind_with(&user, agent, port, BusOptions { announce }).await?;
                flock_bridge::serve_home(
                    &bus,
                    flock_bridge::topic(user.fingerprint(), &id),
                    attach_sock(dir),
                    flock_bridge::Gate::new(flock_bridge::Limits::default()),
                );
                println!("bridge {fp} {} {}", hex::encode(pubkey), bus.local_port());
                Some(bus)
            }
            None => None,
        };
        match tokio::task::spawn_blocking(move || serving.wait()).await? {
            Some(why) => Err(anyhow!("stopped: could not persist: {why}")),
            None => Ok(()),
        }
    }

    pub async fn attach(home: &Path, dir: &Path, id: &str, peer: &str) -> Result<()> {
        let id: ContentId = id
            .parse()
            .map_err(|e| anyhow!("--id is not a content id: {e}"))?;
        let peer = match peer.split_once('@') {
            Some((pubkey, addr)) => {
                let key: [u8; 32] = hex::decode(pubkey)
                    .ok()
                    .and_then(|b| b.try_into().ok())
                    .ok_or_else(|| anyhow!("--peer: the part before @ is not a 32-byte hex key"))?;
                let addr: std::net::SocketAddr = addr
                    .parse()
                    .map_err(|e| anyhow!("--peer: the part after @ is not ip:port: {e}"))?;
                flock_bridge::Peer::Direct(PeerEndpoint::new(key, addr))
            }
            None => flock_bridge::Peer::Known(
                peer.parse::<Fingerprint>()
                    .map_err(|e| anyhow!("--peer is neither pubkey@addr nor a fingerprint: {e}"))?,
            ),
        };
        let (user, agent) = bus_identity(home, "amesh-flock-attach")?;
        let bus = std::sync::Arc::new(Bus::bind_outbound_only(&user, agent).await?);
        let topic = flock_bridge::topic(user.fingerprint(), &id);
        let signed = flock_bridge::fetch_genesis(&bus, &peer, &topic).await?;
        // the directory is ours (private, locked) for as long as this runs
        let _attachment = flock_bridge::pin_genesis(dir, &id, &signed)?;
        let listener = bind_private(&sock(dir))?;
        listener.set_nonblocking(true)?;
        let listener = tokio::net::UnixListener::from_std(listener)?;
        println!("serving {}", sock(dir).display());
        let gate = flock_bridge::Gate::new(flock_bridge::Limits::default());
        flock_bridge::serve_proxy(bus, peer, topic, listener, gate).await
    }

    pub fn invite(dir: &Path, member: &str) -> Result<()> {
        let mut c = UnixStream::connect(sock(dir)).context("is `amesh flock serve` running?")?;
        write_msg(
            &mut c,
            &Req::Invite {
                member: member.into(),
            },
        )?;
        match read_msg::<Resp>(&mut c)? {
            // The server mints 32 random bytes as lowercase hex. Anything else is
            // not an invite, and is not ours to print to a terminal.
            Some(Resp::Invited { token })
                if token.len() == 64
                    && token
                        .bytes()
                        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) =>
            {
                println!("{token}");
            }
            Some(Resp::Invited { .. }) => {
                return Err(anyhow!("the server answered with a malformed invite token"))
            }
            Some(Resp::Err(why)) => return Err(anyhow!("refused: {why}")),
            _ => return Err(anyhow!("unexpected answer")),
        }
        Ok(())
    }

    fn operator_dir(home: &Path, d: Option<PathBuf>) -> PathBuf {
        d.unwrap_or_else(|| home.join("operator"))
    }

    pub fn device_init(home: &Path, device_dir: Option<PathBuf>) -> Result<()> {
        use crate::operator::{Device, TtyUi, Ui as _};
        let key_path = home.join("user.key");
        let user = UserKey::load(&key_path)
            .with_context(|| format!("load {} — run `amesh keygen` first", key_path.display()))?;
        let mut ui = TtyUi::open()?;
        let a = ui.passphrase("new device passphrase: ")?;
        let b = ui.passphrase("again: ")?;
        {
            use age::secrecy::ExposeSecret as _;
            if a.expose_secret() != b.expose_secret() || a.expose_secret().is_empty() {
                bail!("the passphrases differ, or are empty");
            }
        }
        let dir = operator_dir(home, device_dir);
        let cert = Device::at(&dir).init(
            &user,
            &a,
            &crate::util::current_hostname(),
            &crate::util::now_rfc3339(),
        )?;
        println!("device fingerprint: {}", cert.agent_fingerprint());
        println!("certificate: {}", dir.join("device.cert.json").display());
        println!("register it with `amesh flock device-register`, then list the");
        println!("fingerprint under the operator in the roster.");
        Ok(())
    }

    pub fn device_register(dir: &Path, cert: &Path) -> Result<()> {
        let cert: agent_mesh_protocol::CertChain =
            serde_json::from_slice(&std::fs::read(cert)?).context("not a device certificate")?;
        let mut c = UnixStream::connect(sock(dir)).context("is `amesh flock serve` running?")?;
        write_msg(&mut c, &Req::RegisterDevice { cert })?;
        match read_msg::<Resp>(&mut c)? {
            Some(Resp::Ok) => {
                println!("registered");
                Ok(())
            }
            Some(Resp::Err(why)) => Err(anyhow!("refused: {why}")),
            _ => Err(anyhow!("unexpected answer")),
        }
    }

    pub fn sign(home: &Path, dir: &Path, device_dir: Option<PathBuf>) -> Result<()> {
        use crate::operator::{serve_signer, Device, TtyUi};
        let od = operator_dir(home, device_dir);
        let device = Device::at(&od);
        device.cert()?;
        let mut ui = TtyUi::open()?;
        let listener = bind_private(&od.join("sign.sock"))?;
        println!("signer ready on {}", od.join("sign.sock").display());
        serve_signer(&listener, dir, &device, &mut ui, None)
    }

    pub fn answer(
        home: &Path,
        dir: &Path,
        ask: &str,
        text: String,
        device_dir: Option<PathBuf>,
    ) -> Result<()> {
        use crate::operator::{request_answer, SignRequest};
        let ask: ContentId = ask
            .parse()
            .map_err(|e| anyhow!("--ask is not a content id: {e}"))?;
        let flock = agent_mesh_flock_server::load_genesis(dir)
            .map_err(|e| anyhow!("read the genesis: {e}"))?
            .node
            .content_id()?;
        let sock = operator_dir(home, device_dir).join("sign.sock");
        let (event, index) = request_answer(&sock, &SignRequest { flock, ask, text })?;
        println!("admitted {event} at {index}");
        Ok(())
    }

    pub fn session(
        dir: &Path,
        member: &str,
        token: &str,
        socket: Option<PathBuf>,
        allow_unlocked: bool,
    ) -> Result<()> {
        let path = socket.unwrap_or_else(|| {
            dir.join("run")
                .join(format!("session-{}.sock", std::process::id()))
        });
        let listener = bind_private(&path)?;
        let policy = if allow_unlocked {
            eprintln!("warning: --allow-unlocked: the session key may be swapped to disk");
            Policy::AllowUnlocked
        } else {
            Policy::Locked
        };
        // herdr sets both in every pane; either alone is not a claim.
        let pane = std::env::var("HERDR_PANE_ID")
            .ok()
            .zip(std::env::var("HERDR_TAB_ID").ok());
        let result = agent_mesh_flock_session::run(
            &sock(dir),
            token,
            member,
            policy,
            &listener,
            pane,
            |s| {
                println!("session: {}", s.id());
                println!("socket: {}", path.display());
            },
        );
        let _ = std::fs::remove_file(&path);
        result.map_err(Into::into)
    }

    #[cfg(test)]
    mod tests {
        use super::parse_roots;

        fn args(v: &[&str]) -> Vec<String> {
            v.iter().map(|s| (*s).to_owned()).collect()
        }

        #[test]
        fn a_root_is_a_plain_name_and_an_existing_directory() {
            let dir = tempfile::tempdir().unwrap();
            let d = dir.path().display().to_string();
            let ok = parse_roots(&args(&[&format!("notes={d}")])).unwrap();
            assert_eq!(ok["notes"], dir.path());
            for bad in [
                "notes".to_owned(),
                format!("={d}"),
                format!("a/b={d}"),
                format!("..={d}"),
                "notes=/no/such/dir".to_owned(),
                format!("notes={d}/missing"),
            ] {
                assert!(parse_roots(&args(&[&bad])).is_err(), "{bad}");
            }
            let twice = [format!("a={d}"), format!("a={d}")];
            assert!(parse_roots(&twice).is_err());
        }
    }
}
