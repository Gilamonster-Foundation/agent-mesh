//! The operator's answer signer: a device seed held age-encrypted on disk and
//! opened only here, for one answer at a time, after a human has read exactly
//! what will be signed on a terminal and typed `y`.
//!
//! Boundary: this keeps the key from agents that cannot reach the operator's
//! terminal and files. It does not defend against a process of the same user
//! that can read the passphrase as it is typed, ptrace this process or replace
//! the binary; the signer socket is `0600`, which keeps out other users only.

use age::secrecy::{ExposeSecret, SecretString};
use agent_mesh_flock::text::inert_lines;
use agent_mesh_flock::{Body, Event, Kind};
use agent_mesh_flock_server::wire::{read_msg, write_msg, Req, Resp};
use agent_mesh_flock_server::Snapshot;
use agent_mesh_protocol::{AgentKey, AgentMetadata, Assertion, Caveats, CertChain, UserKey};
use anyhow::{anyhow, bail, Context, Result};
use content_addressable::{ContentAddressable as _, ContentId};
use serde::{Deserialize, Serialize};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// The longest answer the signer will show and sign.
pub const MAX_ANSWER: usize = 8 * 1024;

const SEED_FILE: &str = "device.key.age";
const CERT_FILE: &str = "device.cert.json";
const DEFAULT_WORK_FACTOR: u8 = 18;

/// The only thing the signer is ever asked: this answer to this ask, in this
/// flock. There is no "sign these bytes".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    /// The flock the answer is for.
    pub flock: ContentId,
    /// The ask being answered.
    pub ask: ContentId,
    /// The answer text.
    pub text: String,
}

/// The signer's reply.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignReply {
    /// The server admitted the answer.
    Admitted {
        /// The answer event's id.
        event: ContentId,
        /// Its admission index.
        index: u64,
    },
    /// Nothing was signed.
    Refused(String),
}

/// How the signer talks to the human. Production is the controlling terminal.
pub trait Ui {
    /// Show `shown` and ask whether to sign it.
    ///
    /// # Errors
    /// The terminal could not be used.
    fn confirm(&mut self, shown: &str) -> Result<bool>;
    /// Ask for a passphrase (not echoed).
    ///
    /// # Errors
    /// The terminal could not be used.
    fn passphrase(&mut self, prompt: &str) -> Result<SecretString>;
}

/// The operator's terminal: `/dev/tty`, and only when stdin is a terminal.
pub struct TtyUi {
    tty: std::fs::File,
}

impl TtyUi {
    /// # Errors
    /// Stdin is not a terminal, or there is no controlling terminal.
    pub fn open() -> Result<Self> {
        if !rustix::termios::isatty(rustix::stdio::stdin()) {
            bail!("the signer must run on the operator's own terminal (stdin is not a TTY)");
        }
        let tty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .context("no controlling terminal")?;
        Ok(Self { tty })
    }

    fn line(&mut self) -> Result<String> {
        let mut out = Vec::new();
        let mut b = [0u8; 1];
        while self.tty.read(&mut b)? == 1 && b[0] != b'\n' {
            out.push(b[0]);
        }
        Ok(String::from_utf8_lossy(&out).into_owned())
    }
}

impl Ui for TtyUi {
    fn confirm(&mut self, shown: &str) -> Result<bool> {
        write!(self.tty, "{shown}\nSign this answer? [y/N] ")?;
        self.tty.flush()?;
        Ok(self.line()?.trim() == "y")
    }

    fn passphrase(&mut self, prompt: &str) -> Result<SecretString> {
        use rustix::termios::{tcgetattr, tcsetattr, LocalModes, OptionalActions};
        write!(self.tty, "{prompt}")?;
        self.tty.flush()?;
        let before = tcgetattr(&self.tty)?;
        let mut quiet = before.clone();
        quiet.local_modes.remove(LocalModes::ECHO);
        tcsetattr(&self.tty, OptionalActions::Flush, &quiet)?;
        let got = self.line();
        tcsetattr(&self.tty, OptionalActions::Flush, &before)?;
        writeln!(self.tty)?;
        Ok(SecretString::from(got?))
    }
}

/// A UI that answers for itself. Only built for tests; the binary never names
/// it (checked by a test).
#[cfg(feature = "test-ui")]
pub struct AutoUi {
    /// Whether to say yes.
    pub yes: bool,
    /// The passphrase to give.
    pub pass: String,
    /// What was shown, for the test to check.
    pub shown: Vec<String>,
    /// How many times the passphrase was asked for.
    pub passphrases: usize,
}

#[cfg(feature = "test-ui")]
impl AutoUi {
    /// A UI that says `yes` and gives `pass`.
    #[must_use]
    pub fn new(yes: bool, pass: &str) -> Self {
        Self {
            yes,
            pass: pass.into(),
            shown: vec![],
            passphrases: 0,
        }
    }
}

#[cfg(feature = "test-ui")]
impl Ui for AutoUi {
    fn confirm(&mut self, shown: &str) -> Result<bool> {
        self.shown.push(shown.to_owned());
        Ok(self.yes)
    }
    fn passphrase(&mut self, _: &str) -> Result<SecretString> {
        self.passphrases += 1;
        Ok(SecretString::from(self.pass.clone()))
    }
}

/// The operator's device on disk: an age-encrypted seed and its public cert.
pub struct Device {
    dir: PathBuf,
    work_factor: u8,
}

impl Device {
    /// The device kept in `dir`.
    #[must_use]
    pub fn at(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
            work_factor: DEFAULT_WORK_FACTOR,
        }
    }

    /// The same, with a cheaper passphrase hash (tests).
    #[must_use]
    pub fn with_work_factor(mut self, wf: u8) -> Self {
        self.work_factor = wf;
        self
    }

    /// Mint a device seed, have `user` certify it directly, write the seed
    /// age-encrypted under `pass` (0600, in a 0700 directory) and the
    /// certificate beside it. Returns the certificate to register.
    ///
    /// # Errors
    /// A device already exists here, or a file could not be written.
    pub fn init(
        &self,
        user: &UserKey,
        pass: &SecretString,
        host: &str,
        now: &str,
    ) -> Result<CertChain> {
        let seed_path = self.dir.join(SEED_FILE);
        if seed_path.exists() {
            bail!("a device already exists in {}", self.dir.display());
        }
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.dir)?;
        let key = AgentKey::issue(
            user,
            AgentMetadata {
                role: "operator".into(),
                host: host.into(),
                capabilities: vec![],
                issued_at: now.into(),
                expires_at: None,
                caveats: Caveats::top(),
            },
        );
        let seed = Zeroizing::new(key.signing_key_bytes());
        let mut rec = age::scrypt::Recipient::new(pass.clone());
        rec.set_work_factor(self.work_factor);
        let enc = age::Encryptor::with_recipients(std::iter::once(&rec as &dyn age::Recipient))?;
        let mut out = Vec::new();
        let armored =
            age::armor::ArmoredWriter::wrap_output(&mut out, age::armor::Format::AsciiArmor)?;
        let mut w = enc.wrap_output(armored)?;
        w.write_all(&*seed)?;
        w.finish().and_then(|a| a.finish())?;
        write_private(&seed_path, &out)?;
        let cert = key.cert().clone();
        write_private(
            &self.dir.join(CERT_FILE),
            serde_json::to_string_pretty(&cert)?.as_bytes(),
        )?;
        Ok(cert)
    }

    /// The device's public certificate.
    ///
    /// # Errors
    /// No device here, or an unreadable certificate.
    pub fn cert(&self) -> Result<CertChain> {
        let p = self.dir.join(CERT_FILE);
        serde_json::from_slice(&std::fs::read(&p).with_context(|| format!("read {}", p.display()))?)
            .context("the device certificate is not valid")
    }

    fn open(&self, pass: &SecretString) -> Result<AgentKey> {
        let bytes = std::fs::read(self.dir.join(SEED_FILE)).context("read the device seed")?;
        let dec = age::Decryptor::new_buffered(age::armor::ArmoredReader::new(&bytes[..]))?;
        let mut id =
            age::scrypt::Identity::new(SecretString::from(pass.expose_secret().to_owned()));
        id.set_max_work_factor(DEFAULT_WORK_FACTOR.max(self.work_factor));
        let mut plain = Zeroizing::new(Vec::new());
        dec.decrypt(std::iter::once(&id as &dyn age::Identity))
            .map_err(|_| anyhow!("wrong passphrase, or the device seed is damaged"))?
            .read_to_end(&mut plain)?;
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
            plain[..]
                .try_into()
                .map_err(|_| anyhow!("the device seed has the wrong length"))?,
        );
        AgentKey::from_seed_and_cert(&seed, self.cert()?).map_err(|e| anyhow!("{e}"))
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    Ok(f.sync_all()?)
}

/// What the human is shown: everything that will be signed, escaped.
fn shown(
    flock: &ContentId,
    ask: &ContentId,
    lane: Option<&str>,
    ask_text: &str,
    text: &str,
) -> String {
    inert_lines(&format!(
        "flock:  {flock}\nask:    {ask}\nlane:   {}\nasked:  {ask_text}\n---- answer (exactly as signed) ----\n{text}\n----",
        lane.unwrap_or("-")
    ))
    .into_owned()
}

/// Check one request against the verified log, show it, and only on `y` and a
/// correct passphrase sign that one event and submit it.
///
/// # Errors
/// Anything wrong with the request, a declined prompt, a wrong passphrase, or
/// the server's refusal. Nothing is signed before the human has said `y`.
pub fn sign_one(
    req: &SignRequest,
    flock_dir: &Path,
    device: &Device,
    ui: &mut dyn Ui,
) -> Result<(ContentId, u64)> {
    if req.text.is_empty() || req.text.len() > MAX_ANSWER {
        bail!("the answer must be 1 to {MAX_ANSWER} bytes");
    }
    let genesis = agent_mesh_flock_server::load_genesis(flock_dir)
        .map_err(|e| anyhow!("read the genesis: {e}"))?;
    let flock = genesis.node.content_id()?;
    if req.flock != flock {
        bail!("that request is for another flock than the one this signer serves");
    }
    let cert = device.cert()?;
    let snap = Snapshot::read(flock_dir).context("read the verified log")?;
    let board = snap.board();
    let (lane, ask_text) = match board.get(&req.ask) {
        Some(e) if e.conflict.is_none() && e.event.kind == Kind::Ask => match &e.event.body {
            Body::Ask { lane, text } => (lane.clone(), text.clone()),
            _ => bail!("not an ask"),
        },
        _ => bail!("{} is not an ask in this flock's verified log", req.ask),
    };
    if board.closer_of(&req.ask).is_some() {
        bail!("that ask is already answered");
    }
    let node = Event {
        flock,
        kind: Kind::Answer,
        author: cert.agent_fingerprint().hex(),
        prev: None,
        refs: [("ask".to_owned(), req.ask)].into_iter().collect(),
        files: vec![],
        at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
        body: Body::Answer {
            text: req.text.clone(),
        },
    }
    .node();
    if !ui.confirm(&shown(
        &flock,
        &req.ask,
        lane.as_deref(),
        &ask_text,
        &req.text,
    ))? {
        bail!("declined");
    }
    let pass = ui.passphrase("device passphrase: ")?;
    let key = device.open(&pass)?;
    let event = node.content_id()?;
    let sig = Assertion::sign(&key, &event);
    drop(key);
    let mut c = UnixStream::connect(flock_dir.join("run").join("serve.sock"))
        .context("is `amesh flock serve` running?")?;
    write_msg(&mut c, &Req::Admit { node, sig })?;
    match read_msg::<Resp>(&mut c)? {
        Some(Resp::Admitted { index, .. }) => Ok((event, index)),
        Some(Resp::Err(why)) => bail!("refused: {why}"),
        _ => bail!("unexpected answer from the server"),
    }
}

/// Serve requests one at a time on `listener` until `limit` have been handled
/// (`None` = forever).
///
/// # Errors
/// The listener failed.
pub fn serve_signer(
    listener: &UnixListener,
    flock_dir: &Path,
    device: &Device,
    ui: &mut dyn Ui,
    limit: Option<usize>,
) -> Result<()> {
    let mut handled = 0;
    while limit.is_none_or(|l| handled < l) {
        let (mut c, _) = listener.accept()?;
        handled += 1;
        let reply = match read_msg::<SignRequest>(&mut c) {
            Ok(Some(req)) => match sign_one(&req, flock_dir, device, ui) {
                Ok((event, index)) => SignReply::Admitted { event, index },
                Err(e) => SignReply::Refused(format!("{e:#}")),
            },
            _ => SignReply::Refused("not a sign request".into()),
        };
        let _ = write_msg(&mut c, &reply);
    }
    Ok(())
}

/// Ask the signer at `socket` to sign an answer; the id and index admitted.
///
/// # Errors
/// The signer is not running, or refused.
pub fn request_answer(socket: &Path, req: &SignRequest) -> Result<(ContentId, u64)> {
    let mut c = UnixStream::connect(socket).context("is `amesh flock sign` running?")?;
    write_msg(&mut c, req)?;
    match read_msg::<SignReply>(&mut c)? {
        Some(SignReply::Admitted { event, index }) => Ok((event, index)),
        Some(SignReply::Refused(why)) => bail!("{why}"),
        None => bail!("the signer closed without an answer"),
    }
}
