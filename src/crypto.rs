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
        let uuid = uuid::Uuid::new_v4();
        let nonce_bytes: [u8; 12] = uuid.as_bytes()[..12].try_into().unwrap();
        let nonce = Nonce::from(nonce_bytes);

        let ciphertext = self.cipher.encrypt(&nonce, plaintext).unwrap_or_default();

        let mut output = nonce_bytes.to_vec();
        output.extend(ciphertext);
        output
    }

    pub fn decrypt(&self, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < 12 {
            return None;
        }
        let nonce_bytes: [u8; 12] = data[..12].try_into().ok()?;
        let nonce = Nonce::from(nonce_bytes);
        self.cipher.decrypt(&nonce, &data[12..]).ok()
    }
}
