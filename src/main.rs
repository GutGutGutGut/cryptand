use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

use crossterm::event::{self, Event, KeyCode};
use cryptand::{
    app::{App, NetworkAction, Screen},
    transport::listener::{CryptandListener, handle_connection},
    ui,
};

fn start_server(tx: mpsc::Sender<String>, stop: Arc<AtomicBool>) {
    thread::spawn(move || {
        let addr: SocketAddr = "127.0.0.1:4242".parse().unwrap();

        let listener = match CryptandListener::bind(addr) {
            Ok(listener) => listener,
            Err(error) => {
                let _ = tx.send(format!("Erro ao iniciar servidor: {error}"));
                return;
            }
        };

        if let Err(error) = listener.set_nonblocking(true) {
            let _ = tx.send(format!("Erro ao configurar listener: {error}"));
            return;
        }

        let _ = tx.send(format!(
            "Aguardando conexao em {}",
            listener.local_addr().unwrap_or(addr)
        ));

        while !stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok(stream) => {
                    let _ = tx.send(String::from("Conectado; recebendo quadros"));

                    let result = handle_connection(stream);

                    let status = match result {
                        Ok(()) => String::from("Conexao encerrada"),
                        Err(error) => format!("Erro na conexao: {error}"),
                    };

                    let _ = tx.send(status);
                    return;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(100));
                }
                Err(error) => {
                    let _ = tx.send(format!("Erro no listener: {error}"));
                    return;
                }
            }
        }

        let _ = tx.send(String::from("Servidor temporario encerrado"));
    });
}

fn main() -> io::Result<()> {
    let mut app = App::new();
    let (tx, rx) = mpsc::channel::<String>();
    let mut server_stop: Option<Arc<AtomicBool>> = None;

    ratatui::run(|terminal| {
        while app.is_running() {
            while let Ok(status) = rx.try_recv() {
                app.handle_network_event(status);
            }

            terminal.draw(|frame| ui::render(frame, &app))?;

            if event::poll(Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    let previous_screen = app.screen();

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

                    if previous_screen == Screen::Hosting && app.screen() != Screen::Hosting {
                        if let Some(stop) = server_stop.take() {
                            stop.store(true, Ordering::Relaxed);
                        }
                    }
                }
            }

            if let Some(NetworkAction::StartServer) = app.take_network_action() {
                let stop = Arc::new(AtomicBool::new(false));
                server_stop = Some(Arc::clone(&stop));
                start_server(tx.clone(), stop);
            }
        }

        if let Some(stop) = server_stop {
            stop.store(true, Ordering::Relaxed);
        }

        Ok(())
    })
}
