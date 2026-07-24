use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, aead::Aead};
use sha2::{Digest, Sha256};

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
    use super::FlockCrypto;

    #[test]
    fn round_trip_and_authentication_failure() {
        let crypto = FlockCrypto::from_room_code("room");
        let ciphertext = crypto.try_encrypt(b"hello").expect("encrypt");
        assert_eq!(crypto.try_decrypt(&ciphertext).expect("decrypt"), b"hello");

        let mut tampered = ciphertext;
        *tampered.last_mut().expect("ciphertext byte") ^= 1;
        assert!(crypto.try_decrypt(&tampered).is_err());
        assert!(crypto.try_decrypt(&[0; 11]).is_err());
    }
}
