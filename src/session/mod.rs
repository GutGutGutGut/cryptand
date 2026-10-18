use crate::crypto::{AeadCipher, CryptoError, EncryptedMessage};

#[derive(Debug, PartialEq, Eq)]
pub enum SessionState {
    Active,
    Closed,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SessionError {
    AlreadyClosed,
    Crypto(CryptoError),
}

pub struct Session {
    state: SessionState,
    cipher: AeadCipher,
}

impl Session {
    pub fn new(key: &[u8]) -> Result<Self, SessionError> {
        let cipher = AeadCipher::new(key).map_err(SessionError::Crypto)?;

        Ok(Self {
            state: SessionState::Active,
            cipher,
        })
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

    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<EncryptedMessage, SessionError> {
        self.ensure_active()?;

        self.cipher
            .encrypt(plaintext, aad)
            .map_err(SessionError::Crypto)
    }

    pub fn decrypt(
        &self,
        encrypted: &EncryptedMessage,
        aad: &[u8],
    ) -> Result<Vec<u8>, SessionError> {
        self.ensure_active()?;

        self.cipher
            .decrypt(encrypted, aad)
            .map_err(SessionError::Crypto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KEY_LEN;

    fn test_session() -> Session {
        Session::new(&[7u8; KEY_LEN]).unwrap()
    }

    #[test]
    fn session_starts_active() {
        let session = test_session();

        assert_eq!(session.state(), &SessionState::Active);
        assert!(session.ensure_active().is_ok());
    }

    #[test]
    fn session_can_be_closed() {
        let mut session = test_session();

        assert!(session.close().is_ok());
        assert_eq!(session.state(), &SessionState::Closed);
    }

    #[test]
    fn closing_twice_returns_error() {
        let mut session = test_session();

        assert!(session.close().is_ok());
        assert_eq!(session.close(), Err(SessionError::AlreadyClosed));
    }

    #[test]
    fn closed_session_cannot_be_used() {
        let mut session = test_session();

        session.close().unwrap();

        assert_eq!(session.ensure_active(), Err(SessionError::AlreadyClosed));
    }

    #[test]
    fn session_encrypts_and_decrypts() {
        let session = test_session();

        let encrypted = session.encrypt(b"hello", b"header").unwrap();
        let decrypted = session.decrypt(&encrypted, b"header").unwrap();

        assert_eq!(decrypted, b"hello");
    }

    #[test]
    fn closed_session_cannot_encrypt_or_decrypt() {
        let mut session = test_session();
        let encrypted = session.encrypt(b"hello", b"header").unwrap();

        session.close().unwrap();

        assert_eq!(
            session.encrypt(b"again", b"header"),
            Err(SessionError::AlreadyClosed)
        );
        assert_eq!(
            session.decrypt(&encrypted, b"header"),
            Err(SessionError::AlreadyClosed)
        );
    }

    #[test]
    fn session_rejects_modified_ciphertext() {
        let session = test_session();
        let mut encrypted = session.encrypt(b"hello", b"header").unwrap();

        encrypted.ciphertext[0] ^= 1;

        assert_eq!(
            session.decrypt(&encrypted, b"header"),
            Err(SessionError::Crypto(CryptoError::AuthenticationFailed))
        );
    }
}
