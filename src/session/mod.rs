#[derive(Debug, PartialEq, Eq)]
pub enum SessionState {
    Active,
    Closed,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SessionError {
    AlreadyClosed,
}

pub struct Session {
    state: SessionState,
}

impl Session {
    pub fn new() -> Self {
        Self {
            state: SessionState::Active,
        }
    }

    pub fn state(&self) -> &SessionState {
        &self.state
    }

    pub fn close(&mut self) -> Result<(), SessionError> {
        match self.state {
            SessionState::Active => {
                self.state = SessionState::Closed;
                Ok(())
            }
            SessionState::Closed => Err(SessionError::AlreadyClosed),
        }
    }

    pub fn ensure_active(&self) -> Result<(), SessionError> {
        match self.state {
            SessionState::Active => Ok(()),
            SessionState::Closed => Err(SessionError::AlreadyClosed),
        }
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_starts_active() {
        let session = Session::new();

        assert_eq!(session.state(), &SessionState::Active);
        assert!(session.ensure_active().is_ok());
    }

    #[test]
    fn session_can_be_closed() {
        let mut session = Session::new();

        assert!(session.close().is_ok());
        assert_eq!(session.state(), &SessionState::Closed);
    }

    #[test]
    fn closing_twice_returns_error() {
        let mut session = Session::new();

        assert!(session.close().is_ok());
        assert_eq!(session.close(), Err(SessionError::AlreadyClosed));
    }

    #[test]
    fn closed_session_cannot_be_used() {
        let mut session = Session::new();

        session.close().unwrap();

        assert_eq!(session.ensure_active(), Err(SessionError::AlreadyClosed));
    }
}
