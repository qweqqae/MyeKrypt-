mod app;
mod events;
mod job;
mod ui;

use std::io::{self, Stdout};
use std::time::Duration;

use crossterm::event;
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use app::App;

const BUSY_TICK: Duration = Duration::from_millis(80);
const IDLE_TICK: Duration = Duration::from_millis(250);

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    panic_hook();
    let mut terminal = TerminalGuard::enter()?;
    let mut app = App::new();

    while !app.should_quit {
        terminal.inner.draw(|frame| ui::draw(frame, &mut app))?;
        app.check_job();

        let tick = if app.busy() { BUSY_TICK } else { IDLE_TICK };
        if event::poll(tick)? {
            let incoming = event::read()?;
            if app.busy() {
                continue;
            }
            events::handle(&mut app, incoming);
        }
    }

    Ok(())
}

struct TerminalGuard {
    inner: Terminal<CrosstermBackend<Stdout>>,
}

impl TerminalGuard {
    fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let inner = Terminal::new(CrosstermBackend::new(stdout))?;
        Ok(TerminalGuard { inner })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(self.inner.backend_mut(), LeaveAlternateScreen);
        let _ = self.inner.show_cursor();
    }
}

fn panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        previous(info);
    }));
}
