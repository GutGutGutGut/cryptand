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
    transport::{
        listener::{CryptandListener, handle_connection},
        tor_control::TorControl,
        tor_process::TorProcess,
    },
    ui,
};

const SERVER_ADDR: &str = "127.0.0.1:4242";
const ONION_PORT: u16 = 4242;

fn start_server(tx: mpsc::Sender<String>, stop: Arc<AtomicBool>) {
    thread::spawn(move || {
        let addr: SocketAddr = match SERVER_ADDR.parse() {
            Ok(addr) => addr,
            Err(error) => {
                let _ = tx.send(format!("Endereco local invalido: {error}"));
                return;
            }
        };

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
            "Servidor local escutando em {}",
            listener.local_addr().unwrap_or(addr)
        ));

        while !stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok(stream) => {
                    let _ = tx.send(String::from("Conexao recebida"));

                    let result = handle_connection(stream);
                    let status = match result {
                        Ok(()) => String::from("Conexao encerrada"),
                        Err(error) => format!("Erro na conexao: {error}"),
                    };

                    let _ = tx.send(status);
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

        let _ = tx.send(String::from("Servidor local encerrado"));
    });
}

fn start_tor_host(tx: mpsc::Sender<String>, stop: Arc<AtomicBool>) {
    thread::spawn(move || {
        let result = (|| -> io::Result<()> {
            let _ = tx.send(String::from("Iniciando Tor independente..."));

            let mut tor = TorProcess::start()?;
            tor.wait_for_bootstrap(Duration::from_secs(200))?;

            let _ = tx.send(String::from(
                "Tor iniciado; aguardando conexao com a rede...",
            ));

            tor.wait_for_bootstrap(Duration::from_secs(180))?;

            if stop.load(Ordering::Relaxed) {
                tor.shutdown()?;
                return Ok(());
            }

            let control = TorControl::new(tor.control_addr(), tor.cookie_path().to_path_buf());

            let _ = tx.send(String::from("Autenticando no ControlPort..."));

            // O listener local precisa existir antes da criacao do onion.
            let local_addr: SocketAddr = SERVER_ADDR
                .parse()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;

            let onion = control.add_onion(ONION_PORT, local_addr)?;
            let _ = tx.send(format!("ONION:{onion}"));

            // Mantem o processo Tor vivo enquanto a hospedagem estiver ativa.
            while !stop.load(Ordering::Relaxed) {
                if !tor.is_running()? {
                    return Err(io::Error::other("O processo Tor encerrou inesperadamente"));
                }

                thread::sleep(Duration::from_millis(200));
            }

            let service_id = onion.strip_suffix(".onion").unwrap_or(&onion);

            // Tenta remover o servico antes de encerrar o Tor.
            let _ = control.del_onion(service_id);
            tor.shutdown()?;

            Ok(())
        })();

        if let Err(error) = result {
            let _ = tx.send(format!("Erro na hospedagem Tor: {error}"));
        }

        let _ = tx.send(String::from("Processo de hospedagem finalizado"));
    });
}

fn main() -> io::Result<()> {
    let mut app = App::new();
    let (tx, rx) = mpsc::channel::<String>();
    let mut server_stop: Option<Arc<AtomicBool>> = None;
    let mut hosting_stop: Option<Arc<AtomicBool>> = None;

    ratatui::run(|terminal| {
        while app.is_running() {
            while let Ok(status) = rx.try_recv() {
                if let Some(address) = status.strip_prefix("ONION:") {
                    app.set_onion_address(address.to_owned());
                    app.handle_network_event(String::from(
                        "Servico onion temporario criado com sucesso",
                    ));
                } else {
                    app.handle_network_event(status);
                }
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
                        if let Some(stop) = hosting_stop.take() {
                            stop.store(true, Ordering::Relaxed);
                        }
                    }
                }
            }

            if let Some(NetworkAction::StartServer) = app.take_network_action() {
                let stop = Arc::new(AtomicBool::new(false));

                server_stop = Some(Arc::clone(&stop));
                hosting_stop = Some(Arc::clone(&stop));

                start_server(tx.clone(), Arc::clone(&stop));
                start_tor_host(tx.clone(), stop);
            }
        }

        if let Some(stop) = server_stop {
            stop.store(true, Ordering::Relaxed);
        }

        if let Some(stop) = hosting_stop {
            stop.store(true, Ordering::Relaxed);
        }

        Ok(())
    })
}
