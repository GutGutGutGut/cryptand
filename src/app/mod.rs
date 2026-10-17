use crate::session::{Session, SessionError};

pub struct App {
    running: bool,
    session: Option<Session>,
}

impl App {
    pub fn new() -> Self {
        Self {
            running: true,
            session: Some(Session::new()),
        }
    }

    pub fn is_running(&self) -> bool {
        self.running
    }

    pub fn session(&self) -> Option<&Session> {
        self.session.as_ref()
    }

    pub fn quit(&mut self) -> Result<(), SessionError> {
        if let Some(session) = self.session.as_mut() {
            session.close()?;
        }

        self.session = None;
        self.running = false;

        Ok(())
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SessionState;

    #[test]
    fn app_starts_with_active_session() {
        let app = App::new();

        assert!(app.is_running());
        assert_eq!(app.session().unwrap().state(), &SessionState::Active);
    }

    #[test]
    fn quitting_app_closes_session() {
        let mut app = App::new();

        assert!(app.quit().is_ok());
        assert!(!app.is_running());
        assert!(app.session().is_none());
    }
}
