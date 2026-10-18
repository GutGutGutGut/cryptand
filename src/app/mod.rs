#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Home,
    EnterOnion,
    Hosting,
    Connecting,
    Chat,
}

pub struct App {
    running: bool,
    screen: Screen,
    selected: usize,
    onion_address: String,
    status: String,
}

impl App {
    pub fn new() -> Self {
        Self {
            running: true,
            screen: Screen::Home,
            selected: 0,
            onion_address: String::new(),
            status: String::from("Pronto"),
        }
    }

    pub fn is_running(&self) -> bool {
        self.running
    }

    pub fn screen(&self) -> Screen {
        self.screen
    }

    pub fn selected(&self) -> usize {
        self.selected
    }

    pub fn onion_address(&self) -> &str {
        &self.onion_address
    }

    pub fn status(&self) -> &str {
        &self.status
    }

    pub fn quit(&mut self) {
        self.running = false;
    }

    pub fn handle_up(&mut self) {
        if self.screen == Screen::Home {
            self.selected = self.selected.saturating_sub(1);
        }
    }

    pub fn handle_down(&mut self) {
        if self.screen == Screen::Home {
            self.selected = (self.selected + 1).min(1);
        }
    }

    pub fn back(&mut self) {
        match self.screen {
            Screen::Home => self.quit(),
            Screen::EnterOnion | Screen::Hosting | Screen::Connecting | Screen::Chat => {
                self.screen = Screen::Home;
                self.status = String::from("Pronto");
            }
        }
    }

    pub fn select(&mut self) {
        match self.screen {
            Screen::Home => {
                if self.selected == 0 {
                    self.screen = Screen::Hosting;
                    self.status = String::from("Servidor temporario ainda nao iniciado");
                } else {
                    self.screen = Screen::EnterOnion;
                    self.status = String::from("Informe o endereco onion");
                }
            }
            Screen::EnterOnion => {
                if self.onion_address.ends_with(".onion")
                    && !self.onion_address.contains('/')
                    && !self.onion_address.contains(':')
                    && !self.onion_address.contains(' ')
                {
                    self.screen = Screen::Connecting;
                    self.status = String::from("Transporte Tor ainda nao conectado");
                } else {
                    self.status = String::from("Endereco onion invalido");
                }
            }
            Screen::Hosting | Screen::Connecting | Screen::Chat => {}
        }
    }

    pub fn push_char(&mut self, c: char) {
        if self.screen == Screen::EnterOnion && !c.is_control() && self.onion_address.len() < 255 {
            self.onion_address.push(c);
        }
    }

    pub fn backspace(&mut self) {
        if self.screen == Screen::EnterOnion {
            self.onion_address.pop();
        }
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}
