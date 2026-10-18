use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};

use crate::app::{App, Screen};

pub fn render(frame: &mut Frame<'_>, app: &App) {
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Min(8),
            Constraint::Length(3),
        ])
        .split(frame.area());

    let header = Paragraph::new("CRYPTAND\nToxin to Government Surveillance")
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL).title(" cryptand "));

    frame.render_widget(header, areas[0]);

    match app.screen() {
        Screen::Home => {
            let items = ["Hospedar sessao temporaria", "Conectar a um contato"];

            let lines: Vec<String> = items
                .iter()
                .enumerate()
                .map(|(index, item)| {
                    let marker = if index == app.selected() {
                        " > "
                    } else {
                        "   "
                    };

                    format!("{marker}{item}")
                })
                .collect();

            let menu = Paragraph::new(lines.join("\n\n"))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Nova conexao "),
                )
                .wrap(Wrap { trim: false });

            frame.render_widget(menu, areas[1]);
        }

        Screen::EnterOnion => {
            let layout = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Length(3),
                    Constraint::Min(1),
                ])
                .margin(1)
                .split(areas[1]);

            frame.render_widget(
                Paragraph::new("Endereco onion do contato:")
                    .block(Block::default().borders(Borders::ALL)),
                layout[0],
            );

            frame.render_widget(
                Paragraph::new(format!("{}_", app.onion_address()))
                    .style(Style::default().fg(Color::Cyan))
                    .block(Block::default().borders(Borders::ALL).title(" Endereco ")),
                layout[1],
            );

            frame.render_widget(
                Paragraph::new("Enter: continuar | Esc: voltar").alignment(Alignment::Center),
                layout[2],
            );
        }

        Screen::Hosting => {
            let onion = app.onion_address();

            let mensagem = if onion.is_empty() {
                format!(
                    "{}\n\nAguardando endereco onion...\n\nEsc: voltar",
                    app.status()
                )
            } else {
                format!(
                    "{}\n\nEndereco onion:\n{}\n\nEsc: voltar",
                    app.status(),
                    onion
                )
            };

            render_message(frame, areas[1], "Sessao temporaria", &mensagem);
        }

        Screen::Connecting => {
            render_message(
                frame,
                areas[1],
                "Conectar",
                &format!(
                    "Destino: {}\n\nO transporte Tor ainda nao foi iniciado.",
                    app.onion_address()
                ),
            );
        }

        Screen::Chat => {
            render_message(
                frame,
                areas[1],
                "Conversa",
                "A sessao duplex ainda nao foi integrada.",
            );
        }
    }

    frame.render_widget(
        Paragraph::new(format!(
            "{} | Setas: navegar | Enter: selecionar | Esc: voltar/sair",
            app.status()
        ))
        .block(Block::default().borders(Borders::ALL)),
        areas[2],
    );
}

fn render_message(frame: &mut Frame<'_>, area: ratatui::layout::Rect, title: &str, message: &str) {
    frame.render_widget(Clear, area);

    frame.render_widget(
        Paragraph::new(message)
            .block(Block::default().borders(Borders::ALL).title(title))
            .wrap(Wrap { trim: false })
            .style(Style::default().add_modifier(Modifier::BOLD)),
        area,
    );
}
