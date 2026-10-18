use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::{RngCore, rngs::OsRng};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

const SPK_DOMAIN: &[u8] = b"cryptand-SPK-v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicIdentity {
    pub identity_dh_key: [u8; 32],
    pub signing_key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicSignedPreKey {
    pub public_key: [u8; 32],
    pub signature: [u8; 64],
}

pub struct Identity {
    dh_secret: StaticSecret,
    signing_key: SigningKey,
}

pub struct SignedPreKey {
    secret: StaticSecret,
    public: PublicSignedPreKey,
}

fn random_bytes<const N: usize>() -> Result<[u8; N], rand::Error> {
    let mut bytes = [0u8; N];
    OsRng.try_fill_bytes(&mut bytes)?;
    Ok(bytes)
}

fn signature_message(identity_dh_key: &[u8; 32], signed_prekey: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(SPK_DOMAIN.len() + 64);
    message.extend_from_slice(SPK_DOMAIN);
    message.extend_from_slice(identity_dh_key);
    message.extend_from_slice(signed_prekey);
    message
}

impl Identity {
    pub fn generate() -> Result<Self, rand::Error> {
        let dh_secret = StaticSecret::from(random_bytes::<32>()?);
        let signing_seed = random_bytes::<32>()?;

        Ok(Self {
            dh_secret,
            signing_key: SigningKey::from_bytes(&signing_seed),
        })
    }

    pub fn public_identity(&self) -> PublicIdentity {
        let dh_public = X25519PublicKey::from(&self.dh_secret);

        PublicIdentity {
            identity_dh_key: dh_public.to_bytes(),
            signing_key: self.signing_key.verifying_key().to_bytes(),
        }
    }

    pub fn generate_signed_prekey(&self) -> Result<SignedPreKey, rand::Error> {
        let secret = StaticSecret::from(random_bytes::<32>()?);
        let public = X25519PublicKey::from(&secret).to_bytes();

        let identity = self.public_identity();
        let message = signature_message(&identity.identity_dh_key, &public);

        let signature = self.signing_key.sign(&message).to_bytes();

        Ok(SignedPreKey {
            secret,
            public: PublicSignedPreKey {
                public_key: public,
                signature,
            },
        })
    }
}

impl SignedPreKey {
    pub fn public(&self) -> &PublicSignedPreKey {
        &self.public
    }

    pub fn verify(
        identity: &PublicIdentity,
        prekey: &PublicSignedPreKey,
    ) -> Result<(), &'static str> {
        let verifying_key = VerifyingKey::from_bytes(&identity.signing_key)
            .map_err(|_| "Chave de assinatura inválida")?;

        let message = signature_message(&identity.identity_dh_key, &prekey.public_key);

        let signature = Signature::from_bytes(&prekey.signature);

        verifying_key
            .verify_strict(&message, &signature)
            .map_err(|_| "Assinatura da signed prekey inválida")
    }

    pub fn public_key(&self) -> [u8; 32] {
        X25519PublicKey::from(&self.secret).to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_identity_has_public_keys() {
        let identity = Identity::generate().unwrap();
        let public = identity.public_identity();

        assert_eq!(public.identity_dh_key.len(), 32);
        assert_eq!(public.signing_key.len(), 32);
    }

    #[test]
    fn signed_prekey_verifies() {
        let identity = Identity::generate().unwrap();
        let public_identity = identity.public_identity();
        let prekey = identity.generate_signed_prekey().unwrap();

        assert!(SignedPreKey::verify(&public_identity, prekey.public()).is_ok());
    }

    #[test]
    fn modified_prekey_is_rejected() {
        let identity = Identity::generate().unwrap();
        let public_identity = identity.public_identity();
        let prekey = identity.generate_signed_prekey().unwrap();

        let mut forged = prekey.public().clone();
        forged.public_key[0] ^= 1;

        assert!(SignedPreKey::verify(&public_identity, &forged).is_err());
    }
}

use hkdf::Hkdf;
use sha2::Sha256;

// Contexto criptográfico específico do protocolo cryptand.
const X3DH_INFO: &[u8] = b"cryptand_X3DH_v1";

pub struct X3dhInitiator {
    ephemeral_public: [u8; 32],
}

pub struct OneTimePreKey {
    secret: StaticSecret,
    public_key: [u8; 32],
}

impl OneTimePreKey {
    pub fn generate() -> Result<Self, rand::Error> {
        let secret = StaticSecret::from(random_bytes::<32>()?);
        let public_key = X25519PublicKey::from(&secret).to_bytes();

        Ok(Self { secret, public_key })
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }
}

fn derive_x3dh_key(dh_values: &[[u8; 32]]) -> Result<[u8; 32], &'static str> {
    // O perfil X3DH para X25519 usa 32 bytes 0xFF como prefixo.
    let mut input = Vec::with_capacity(32 + dh_values.len() * 32);
    input.extend_from_slice(&[0xFF; 32]);

    for value in dh_values {
        input.extend_from_slice(value);
    }

    let salt = [0u8; 32];
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &input);

    let mut output = [0u8; 32];
    hkdf.expand(X3DH_INFO, &mut output)
        .map_err(|_| "Falha ao derivar a chave X3DH")?;

    // Evitar manter o material intermediário na memória por mais tempo
    // do que o necessário não substitui uma estratégia de zeroização.
    input.fill(0);

    Ok(output)
}

fn checked_dh(secret: &StaticSecret, public_bytes: &[u8; 32]) -> Result<[u8; 32], &'static str> {
    let public = X25519PublicKey::from(*public_bytes);
    let shared = secret.diffie_hellman(&public);

    if !shared.was_contributory() {
        return Err("Chave pública X25519 não contributiva");
    }

    Ok(*shared.as_bytes())
}

impl X3dhInitiator {
    pub fn start(
        identity: &Identity,
        responder_identity: &PublicIdentity,
        responder_spk: &PublicSignedPreKey,
        responder_opk: Option<[u8; 32]>,
    ) -> Result<(Self, [u8; 32]), &'static str> {
        SignedPreKey::verify(responder_identity, responder_spk)?;

        let ephemeral_secret =
            StaticSecret::from(random_bytes::<32>().map_err(|_| "Falha ao gerar chave efêmera")?);

        let ephemeral_public = X25519PublicKey::from(&ephemeral_secret).to_bytes();

        // DH1 = DH(IK_A, SPK_B)
        let dh1 = checked_dh(&identity.dh_secret, &responder_spk.public_key)?;

        // DH2 = DH(EK_A, IK_B)
        let dh2 = checked_dh(&ephemeral_secret, &responder_identity.identity_dh_key)?;

        // DH3 = DH(EK_A, SPK_B)
        let dh3 = checked_dh(&ephemeral_secret, &responder_spk.public_key)?;

        let mut values = vec![dh1, dh2, dh3];

        // DH4 = DH(EK_A, OPK_B), se houver one-time prekey.
        if let Some(opk) = responder_opk {
            values.push(checked_dh(&ephemeral_secret, &opk)?);
        }

        let key = derive_x3dh_key(&values)?;

        Ok((Self { ephemeral_public }, key))
    }

    pub fn ephemeral_public_key(&self) -> [u8; 32] {
        self.ephemeral_public
    }
}

impl Identity {
    pub fn complete_x3dh(
        &self,
        initiator_identity: &PublicIdentity,
        initiator_ephemeral: &[u8; 32],
        responder_spk: &SignedPreKey,
        responder_opk: Option<&OneTimePreKey>,
    ) -> Result<[u8; 32], &'static str> {
        // DH1 = DH(SPK_B, IK_A)
        let dh1 = checked_dh(&responder_spk.secret, &initiator_identity.identity_dh_key)?;

        // DH2 = DH(IK_B, EK_A)
        let dh2 = checked_dh(&self.dh_secret, initiator_ephemeral)?;

        // DH3 = DH(SPK_B, EK_A)
        let dh3 = checked_dh(&responder_spk.secret, initiator_ephemeral)?;

        let mut values = vec![dh1, dh2, dh3];

        // DH4 = DH(OPK_B, EK_A), se houver one-time prekey.
        if let Some(opk) = responder_opk {
            values.push(checked_dh(&opk.secret, initiator_ephemeral)?);
        }

        derive_x3dh_key(&values)
    }
}

#[cfg(test)]
mod x3dh_tests {
    use super::*;

    #[test]
    fn x3dh_produces_same_key_without_opk() {
        // bob cria sua identidade e sua signed prekey.
        let bob = Identity::generate().unwrap();
        let bob_public = bob.public_identity();
        let bob_spk = bob.generate_signed_prekey().unwrap();

        // Alice cria sua própria identidade.
        let alice = Identity::generate().unwrap();
        let alice_public = alice.public_identity();

        // Alice inicia o X3DH usando as chaves públicas de bob.
        let (initiator, alice_key) =
            X3dhInitiator::start(&alice, &bob_public, bob_spk.public(), None).unwrap();

        // bob calcula o segredo correspondente.
        let bob_key = bob
            .complete_x3dh(
                &alice_public,
                &initiator.ephemeral_public_key(),
                &bob_spk,
                None,
            )
            .unwrap();

        assert_eq!(alice_key, bob_key);
    }

    #[test]
    fn modified_ephemeral_key_produces_different_shared_key() {
        let bob = Identity::generate().unwrap();
        let bob_spk = bob.generate_signed_prekey().unwrap();

        let alice = Identity::generate().unwrap();

        let (initiator, alice_key) =
            X3dhInitiator::start(&alice, &bob.public_identity(), bob_spk.public(), None).unwrap();

        // Copia a chave pública efêmera original da Alice.
        let mut modified_ephemeral = initiator.ephemeral_public_key();

        // Altera um byte para simular uma chave pública modificada.
        modified_ephemeral[0] ^= 0x01;

        // bob deriva a chave usando a versão modificada.
        let bob_key = bob
            .complete_x3dh(
                &alice.public_identity(),
                &modified_ephemeral,
                &bob_spk,
                None,
            )
            .unwrap();

        // As chaves derivadas devem ser diferentes.
        assert_ne!(alice_key, bob_key);
    }

    #[test]
    fn x3dh_rejects_modified_signed_prekey() {
        let bob = Identity::generate().unwrap();
        let bob_public = bob.public_identity();
        let bob_spk = bob.generate_signed_prekey().unwrap();

        let alice = Identity::generate().unwrap();

        // Copia a prekey pública e altera um byte.
        let mut modified_spk = bob_spk.public().clone();
        modified_spk.public_key[0] ^= 1;

        // Alice deve rejeitar a assinatura inválida.
        let result = X3dhInitiator::start(&alice, &bob_public, &modified_spk, None);

        assert!(result.is_err());
    }

    #[test]
    fn x3dh_produces_same_key_with_opk() {
        // bob cria identidade, signed prekey e one-time prekey.
        let bob = Identity::generate().unwrap();
        let bob_public = bob.public_identity();
        let bob_spk = bob.generate_signed_prekey().unwrap();
        let bob_opk = OneTimePreKey::generate().unwrap();

        let alice = Identity::generate().unwrap();
        let alice_public = alice.public_identity();

        // Alice inclui a chave pública da OPK de bob.
        let (initiator, alice_key) = X3dhInitiator::start(
            &alice,
            &bob_public,
            bob_spk.public(),
            Some(bob_opk.public_key()),
        )
        .unwrap();

        // bob usa a mesma OPK privada para calcular o segredo.
        let bob_key = bob
            .complete_x3dh(
                &alice_public,
                &initiator.ephemeral_public_key(),
                &bob_spk,
                Some(&bob_opk),
            )
            .unwrap();

        assert_eq!(alice_key, bob_key);
    }
}
