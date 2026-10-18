use std::{io, time::Duration};

use crossterm::event::{self, Event, KeyCode};
use cryptand::app::{App, Screen};
use cryptand::ui;

fn main() -> io::Result<()> {
    let mut app = App::new();

    ratatui::run(|terminal| {
        while app.is_running() {
            terminal.draw(|frame| ui::render(frame, &app))?;

            if !event::poll(Duration::from_millis(200))? {
                continue;
            }

            let Event::Key(key) = event::read()? else {
                continue;
            };

            match key.code {
                KeyCode::Char('q') if app.screen() == Screen::Home => {
                    app.quit();
                }
                KeyCode::Esc => app.back(),
                KeyCode::Up => app.handle_up(),
                KeyCode::Down => app.handle_down(),
                KeyCode::Enter => app.select(),
                KeyCode::Backspace => app.backspace(),
                KeyCode::Char(c) => app.push_char(c),
                _ => {}
            }
        }

        Ok(())
    })
}
