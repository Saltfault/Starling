use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use rand::random;
use sha2::{Digest, Sha256};
use sha2_10::Sha256 as Sha256V10;
use zeroize::{Zeroize, ZeroizeOnDrop};

const EPOCH_KEY_INFO: &[u8] = b"starling/v1/epoch-key";

/// A V1 content-encryption key. Its bytes are erased when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EpochKey([u8; 32]);

impl EpochKey {
    /// Derives an epoch key from secret input key material and public context.
    pub fn derive(secret: &[u8], context: &[u8], epoch: u64) -> anyhow::Result<Self> {
        anyhow::ensure!(!secret.is_empty(), "epoch key secret must not be empty");
        let hkdf = Hkdf::<Sha256V10>::new(Some(context), secret);
        let mut key = [0_u8; 32];
        let mut info = Vec::with_capacity(EPOCH_KEY_INFO.len() + 8);
        info.extend_from_slice(EPOCH_KEY_INFO);
        info.extend_from_slice(&epoch.to_be_bytes());
        hkdf.expand(&info, &mut key)
            .map_err(|_| anyhow::anyhow!("failed to derive epoch key"))?;
        Ok(Self(key))
    }

    pub fn seal(&self, plaintext: &[u8], aad: &[u8]) -> anyhow::Result<([u8; 12], Vec<u8>)> {
        let nonce_bytes: [u8; 12] = random();
        let cipher = ChaCha20Poly1305::new((&self.0).into());
        let ciphertext = cipher
            .encrypt(
                &Nonce::from(nonce_bytes),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("failed to encrypt event payload"))?;
        Ok((nonce_bytes, ciphertext))
    }

    pub fn open(&self, nonce: &[u8; 12], ciphertext: &[u8], aad: &[u8]) -> anyhow::Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new((&self.0).into());
        cipher
            .decrypt(
                &Nonce::from(*nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("event payload failed authentication"))
    }
}

/// Legacy V0 room-code crypto. Its wire format and behavior are preserved.
pub struct FlockCrypto {
    cipher: ChaCha20Poly1305,
}

impl FlockCrypto {
    pub fn from_room_code(code: &str) -> Self {
        let key = Sha256::digest(format!("starling/flock/{code}").as_bytes());
        let cipher = ChaCha20Poly1305::new(&key);
        Self { cipher }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        self.try_encrypt(plaintext).unwrap_or_default()
    }

    pub fn try_encrypt(&self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let uuid = uuid::Uuid::new_v4();
        let nonce_bytes: [u8; 12] = uuid.as_bytes()[..12]
            .try_into()
            .map_err(|_| anyhow::anyhow!("failed to construct encryption nonce"))?;
        let nonce = Nonce::from(nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| anyhow::anyhow!("failed to encrypt payload"))?;

        let mut output = nonce_bytes.to_vec();
        output.extend(ciphertext);
        Ok(output)
    }

    pub fn decrypt(&self, data: &[u8]) -> Option<Vec<u8>> {
        self.try_decrypt(data).ok()
    }

    pub fn try_decrypt(&self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let nonce_bytes: [u8; 12] = data
            .get(..12)
            .ok_or_else(|| anyhow::anyhow!("encrypted payload is shorter than its nonce"))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("failed to parse encryption nonce"))?;
        let nonce = Nonce::from(nonce_bytes);
        self.cipher
            .decrypt(&nonce, &data[12..])
            .map_err(|_| anyhow::anyhow!("encrypted payload failed authentication"))
    }
}

#[cfg(test)]
mod tests {
    use super::{EpochKey, FlockCrypto};

    #[test]
    fn epoch_key_is_deterministic_and_context_bound() {
        let first = EpochKey::derive(b"secret", b"space", 7).unwrap();
        let same = EpochKey::derive(b"secret", b"space", 7).unwrap();
        let other = EpochKey::derive(b"secret", b"space", 8).unwrap();
        let (nonce, ciphertext) = first.seal(b"hello", b"aad").unwrap();

        assert_eq!(same.open(&nonce, &ciphertext, b"aad").unwrap(), b"hello");
        assert!(other.open(&nonce, &ciphertext, b"aad").is_err());
        assert!(first.open(&nonce, &ciphertext, b"other aad").is_err());
    }

    #[test]
    fn epoch_encryption_uses_random_nonces() {
        let key = EpochKey::derive(b"secret", b"space", 1).unwrap();
        let first = key.seal(b"same", b"").unwrap();
        let second = key.seal(b"same", b"").unwrap();
        assert_ne!(first.0, second.0);
        assert_ne!(first.1, second.1);
    }

    #[test]
    fn v0_round_trip_and_authentication_failure() {
        let crypto = FlockCrypto::from_room_code("room");
        let ciphertext = crypto.try_encrypt(b"hello").expect("encrypt");
        assert_eq!(crypto.try_decrypt(&ciphertext).expect("decrypt"), b"hello");

        let mut tampered = ciphertext;
        *tampered.last_mut().expect("ciphertext byte") ^= 1;
        assert!(crypto.try_decrypt(&tampered).is_err());
        assert!(crypto.try_decrypt(&[0; 11]).is_err());
    }
}
