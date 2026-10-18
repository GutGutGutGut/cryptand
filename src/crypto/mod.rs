use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::{RngCore, rngs::OsRng};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;

#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    InvalidKey,
    RandomGenerationFailed,
    AuthenticationFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedMessage {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

pub struct AeadCipher {
    cipher: Aes256Gcm,
}

impl AeadCipher {
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != KEY_LEN {
            return Err(CryptoError::InvalidKey);
        }

        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;

        Ok(Self { cipher })
    }

    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<EncryptedMessage, CryptoError> {
        let mut nonce_bytes = [0u8; NONCE_LEN];

        OsRng
            .try_fill_bytes(&mut nonce_bytes)
            .map_err(|_| CryptoError::RandomGenerationFailed)?;

        let nonce = Nonce::from(nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?;

        Ok(EncryptedMessage {
            nonce: nonce_bytes,
            ciphertext,
        })
    }

    pub fn decrypt(
        &self,
        encrypted: &EncryptedMessage,
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let nonce = Nonce::from(encrypted.nonce);

        self.cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &encrypted.ciphertext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_then_decrypt() {
        let key = [7u8; KEY_LEN];
        let cipher = AeadCipher::new(&key).unwrap();

        let encrypted = cipher.encrypt(b"hello", b"header").unwrap();
        let decrypted = cipher.decrypt(&encrypted, b"header").unwrap();

        assert_eq!(decrypted, b"hello");
        assert_eq!(encrypted.nonce.len(), NONCE_LEN);
    }

    #[test]
    fn modified_ciphertext_is_rejected() {
        let key = [7u8; KEY_LEN];
        let cipher = AeadCipher::new(&key).unwrap();

        let mut encrypted = cipher.encrypt(b"hello", b"header").unwrap();
        encrypted.ciphertext[0] ^= 1;

        assert_eq!(
            cipher.decrypt(&encrypted, b"header"),
            Err(CryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn modified_aad_is_rejected() {
        let key = [7u8; KEY_LEN];
        let cipher = AeadCipher::new(&key).unwrap();

        let encrypted = cipher.encrypt(b"hello", b"header").unwrap();

        assert_eq!(
            cipher.decrypt(&encrypted, b"other"),
            Err(CryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn invalid_key_length_is_rejected() {
        assert!(matches!(
            AeadCipher::new(&[0u8; 16]),
            Err(CryptoError::InvalidKey)
        ));
    }

    #[test]
    fn empty_plaintext_roundtrips() {
        let key = [7u8; KEY_LEN];
        let cipher = AeadCipher::new(&key).unwrap();

        let encrypted = cipher.encrypt(b"", b"header").unwrap();
        let decrypted = cipher.decrypt(&encrypted, b"header").unwrap();

        assert!(decrypted.is_empty());
    }
}
