use std::io;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode};
use ratatui::{
    layout::{Constraint, Direction, Layout},
    widgets::{Block, Borders, Paragraph},
};

fn main() -> io::Result<()> {
    ratatui::run(|terminal| {
        loop {
            terminal.draw(|frame| {
                let areas = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(3),
                        Constraint::Min(1),
                        Constraint::Length(3),
                    ])
                    .split(frame.area());

                frame.render_widget(
                    Paragraph::new("TCDD - Toxin to Government Surveillance ")
                        .block(Block::default().borders(Borders::ALL).title(" TCDD ")),
                    areas[0],
                );

                frame.render_widget(
                    Paragraph::new(
                        "Nenhuma conversa aberta.\n\n\
                         O transporte Tor sera integrado aqui.",
                    )
                    .block(Block::default().borders(Borders::ALL).title(" Conversas ")),
                    areas[1],
                );

                frame.render_widget(
                    Paragraph::new("Pressione Q para sair")
                        .block(Block::default().borders(Borders::ALL)),
                    areas[2],
                );
            })?;

            if event::poll(Duration::from_millis(200))? {
                if let Event::Key(key) = event::read()? {
                    if key.code == KeyCode::Char('q') {
                        break Ok(());
                    }
                }
            }
        }
    })
}
// Toxin to Government Surveillance essa é a logo :)
