//! `amesh-tui`: a read-only terminal view of a flock.

#[cfg(not(unix))]
fn main() {
    eprintln!("amesh-tui runs on Unix only");
    std::process::exit(1);
}

/// The whole failure report is printed through `inert`: it can carry a reason
/// a session or server supplied, or a path the operator was handed, and the
/// default `main() -> Result` formatter would hand those to the terminal raw.
#[cfg(unix)]
fn main() -> std::process::ExitCode {
    match run::main() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!(
                "Error: {}",
                agent_mesh_tui::ui::inert::inert(&format!("{e:#}"))
            );
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(unix)]
mod run {
    use agent_mesh_tui::drift::{check_all_via, Remote, Roots};
    use agent_mesh_tui::feed::{Feed, Outcome};
    use agent_mesh_tui::keys::decode;
    use agent_mesh_tui::model::Link;
    use agent_mesh_tui::ui::{render, App};
    use anyhow::{bail, Result};
    use clap::Parser;
    use newtui::{Component as _, Flow, Key};
    use ratatui::crossterm::event::{self, Event};
    use std::path::PathBuf;
    use std::sync::mpsc;

    /// A read-only view of a flock: it reads the log through a session and
    /// can neither write to it nor sign anything.
    #[derive(Parser, Debug)]
    #[command(name = "amesh-tui", version)]
    struct Args {
        /// The flock directory (on this host).
        #[arg(long)]
        dir: PathBuf,
        /// The session's socket (`amesh flock session` prints it).
        #[arg(long, env = "AMESH_FLOCK_SESSION")]
        session: PathBuf,
        /// Print one frame as text and exit, instead of opening the terminal.
        #[arg(long)]
        once: bool,
        /// With --once, the view to print: board, stream or lane.
        #[arg(long, default_value = "board", requires = "once")]
        tab: String,
        /// Where a root the events cite is on this host (`name=path`, repeat
        /// for more). Only to read cited files and say whether they changed;
        /// nothing is ever written there. A root not given here is asked of
        /// the flock's server (the home host, when attached remotely).
        #[arg(long = "root", value_name = "NAME=PATH", value_parser = Roots::parse)]
        roots: Vec<(String, PathBuf)>,
    }

    enum Msg {
        Key(Key),
        Model(Box<agent_mesh_tui::model::Model>),
        Redraw,
        Drift(agent_mesh_tui::drift::Drift),
    }

    /// The flock's server and the session: where a root this host does not
    /// map is asked for.
    struct Sockets {
        serve: PathBuf,
        ctl: PathBuf,
    }

    impl Sockets {
        fn remote(&self) -> Remote<'_> {
            Remote {
                serve: &self.serve,
                ctl: &self.ctl,
            }
        }
    }

    pub fn main() -> Result<()> {
        let args = Args::parse();
        let mut feed = Feed::open(&args.dir, &args.session)?;
        let mut roots = Roots::default();
        for (name, dir) in args.roots {
            roots.insert(&name, dir);
        }
        let serve = args.dir.join("run").join("serve.sock");
        let remote = Sockets {
            serve,
            ctl: args.session,
        };
        if args.once {
            return once(&mut feed, &roots, &remote, &args.tab);
        }
        interactive(feed, roots, remote)
    }

    fn once(feed: &mut Feed, roots: &Roots, sockets: &Sockets, tab: &str) -> Result<()> {
        let outcome = feed.run(true, &mut |_| {});
        let link = match &outcome {
            Outcome::Done => Link::Live,
            Outcome::Down(_) => feed.stale(),
            Outcome::Failed(why) => Link::Failed(why.clone()),
            Outcome::Unsaved(why) => Link::Unsaved(why.clone()),
        };
        let mut app = App::new(feed.model(link));
        let rows = match tab {
            "board" => app.model().members.len(),
            "stream" => {
                app.handle(Key::Char('2'));
                app.model().events.len()
            }
            "lane" => {
                app.handle(Key::Char('3'));
                app.set_drift(check_all_via(
                    roots,
                    Some(sockets.remote()),
                    &app.cited_files(),
                ));
                app.model().lanes.len() + app.cited_files().len() + 12
            }
            other => bail!("no view called {other}: board, stream or lane"),
        };
        let height = u16::try_from(rows + 5).unwrap_or(u16::MAX);
        print!("{}", render::to_text(&app, 110, height));
        match outcome {
            Outcome::Done => Ok(()),
            Outcome::Down(why) | Outcome::Failed(why) | Outcome::Unsaved(why) => bail!("{why}"),
        }
    }

    fn interactive(mut feed: Feed, roots: Roots, sockets: Sockets) -> Result<()> {
        let (tx, rx) = mpsc::channel::<Msg>();
        let mut app = App::new(feed.model(feed.stale()));
        let feed_tx = tx.clone();
        std::thread::spawn(move || {
            let outcome = feed.run(false, &mut |m| {
                let _ = feed_tx.send(Msg::Model(Box::new(m)));
            });
            let link = match outcome {
                Outcome::Failed(why) => Link::Failed(why),
                Outcome::Unsaved(why) => Link::Unsaved(why),
                _ => feed.stale(),
            };
            let _ = feed_tx.send(Msg::Model(Box::new(feed.model(link))));
        });
        // Cited files are hashed here, never on the UI thread: it is told
        // which files, and gets the answer as a message.
        let (check_tx, check_rx) = mpsc::channel::<Vec<agent_mesh_flock::FileRef>>();
        let drift_tx = tx.clone();
        std::thread::spawn(move || {
            while let Ok(mut files) = check_rx.recv() {
                // only the newest request matters
                while let Ok(newer) = check_rx.try_recv() {
                    files = newer;
                }
                if drift_tx
                    .send(Msg::Drift(check_all_via(
                        &roots,
                        Some(sockets.remote()),
                        &files,
                    )))
                    .is_err()
                {
                    break;
                }
            }
        });
        std::thread::spawn(move || {
            while let Ok(e) = event::read() {
                let msg = match e {
                    Event::Key(k) => decode(&k).map(Msg::Key),
                    Event::Resize(..) => Some(Msg::Redraw),
                    _ => None,
                };
                if let Some(m) = msg {
                    if tx.send(m).is_err() {
                        break;
                    }
                }
            }
        });
        let mut asked: Vec<agent_mesh_flock::FileRef> = vec![];
        let mut terminal = ratatui::init();
        let result = (|| -> Result<()> {
            loop {
                terminal.draw(|f| render::draw(f, &app))?;
                match rx.recv() {
                    Ok(Msg::Key(k)) => {
                        if matches!(app.handle(k), Flow::Close(_)) {
                            return Ok(());
                        }
                        if app.take_recheck() {
                            let _ = check_tx.send(app.cited_files());
                        }
                    }
                    Ok(Msg::Drift(d)) => app.set_drift(d),
                    Ok(Msg::Model(m)) => {
                        app.set_model(*m);
                        // check again when the log cites something new
                        let cited = app.cited_files();
                        if cited != asked {
                            let _ = check_tx.send(cited.clone());
                            asked = cited;
                        }
                    }
                    Ok(Msg::Redraw) => {}
                    Err(_) => return Ok(()),
                }
            }
        })();
        ratatui::restore();
        result
    }
}
