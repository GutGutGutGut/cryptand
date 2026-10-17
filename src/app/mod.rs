pub struct App {
    pub running: bool,
}

impl App {
    pub fn new() -> Self {
        Self { running: true }
    }

    pub fn quit(&mut self) {
        self.running = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_starts_running() {
        let app = App::new();

        assert!(app.running);
    }

    #[test]
    fn app_stops_after_quit() {
        let mut app = App::new();

        app.quit();

        assert!(!app.running);
    }
}
