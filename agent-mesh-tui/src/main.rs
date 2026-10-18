//! `amesh-tui`: a read-only terminal view of a flock.

#[cfg(not(unix))]
fn main() {
    eprintln!("amesh-tui runs on Unix only");
    std::process::exit(1);
}

#[cfg(unix)]
fn main() -> anyhow::Result<()> {
    run::main()
}

#[cfg(unix)]
mod run {
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
    }

    enum Msg {
        Key(Key),
        Model(Box<agent_mesh_tui::model::Model>),
        Redraw,
    }

    pub fn main() -> Result<()> {
        let args = Args::parse();
        let mut feed = Feed::open(&args.dir, &args.session)?;
        if args.once {
            return once(&mut feed);
        }
        interactive(feed)
    }

    fn once(feed: &mut Feed) -> Result<()> {
        let outcome = feed.run(true, &mut |_| {});
        let link = match &outcome {
            Outcome::Done => Link::Live,
            Outcome::Down(_) => feed.stale(),
            Outcome::Failed(why) => Link::Failed(why.clone()),
            Outcome::Unsaved(why) => Link::Unsaved(why.clone()),
        };
        let app = App::new(feed.model(link));
        let height = u16::try_from(app.model().members.len() + 5).unwrap_or(u16::MAX);
        print!("{}", render::to_text(&app, 110, height));
        match outcome {
            Outcome::Done => Ok(()),
            Outcome::Down(why) | Outcome::Failed(why) | Outcome::Unsaved(why) => {
                // the reason can come from the server: print it inert
                bail!("{}", agent_mesh_tui::ui::inert::inert(&why))
            }
        }
    }

    fn interactive(mut feed: Feed) -> Result<()> {
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
        let mut terminal = ratatui::init();
        let result = (|| -> Result<()> {
            loop {
                terminal.draw(|f| render::draw(f, &app))?;
                match rx.recv() {
                    Ok(Msg::Key(k)) => {
                        if matches!(app.handle(k), Flow::Close(_)) {
                            return Ok(());
                        }
                    }
                    Ok(Msg::Model(m)) => app.set_model(*m),
                    Ok(Msg::Redraw) => {}
                    Err(_) => return Ok(()),
                }
            }
        })();
        ratatui::restore();
        result
    }
}
