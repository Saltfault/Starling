use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use crypto_box::{
    ChaChaBox, PublicKey as DmPublicKey, SecretKey as DmSecretKey,
    aead::{Aead as _, AeadCore, OsRng},
};
use hkdf::Hkdf;
use rand::random;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use argon2::Argon2;

const EPOCH_KEY_INFO: &[u8] = b"starling/v1/epoch-key";

/// A content-encryption key. Its bytes are erased when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EpochKey([u8; 32]);

impl EpochKey {
    /// Derives an epoch key from secret input key material and public context.
    pub fn derive(secret: &[u8], context: &[u8], epoch: u64) -> anyhow::Result<Self> {
        anyhow::ensure!(!secret.is_empty(), "epoch key secret must not be empty");
        let hkdf = Hkdf::<Sha256>::new(Some(context), secret);
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

/// Legacy room-code crypto. Its wire format and behavior are preserved.
pub struct FlockCrypto {
    cipher: ChaCha20Poly1305,
}

impl FlockCrypto {
    /// Legacy room-code derivation. **Deprecated** — this uses a single
    /// SHA-256 hash with no salt, no KDF iterations, and no memory hardness.
    /// Anyone who learns the room code (which is displayed in the UI and
    /// shared as an invite) can derive the cipher key and decrypt all past
    /// and future gossip. New flocks MUST use [`from_secret`] instead.
    ///
    /// This path is preserved only to read legacy traffic during the
    /// deprecation window. It will be removed in a future release.
    #[deprecated(
        since = "0.3.18",
        note = "use from_secret for new flocks; use from_room_code_v2 if a code-derived key is unavoidable"
    )]
    pub fn from_room_code(code: &str) -> Self {
        let key = Sha256::digest(format!("starling/flock/{code}").as_bytes());
        let cipher = ChaCha20Poly1305::new(&key);
        Self { cipher }
    }

    /// Derive a flock cipher from a room code and a per-flock random salt
    /// using Argon2id (memory-hard KDF). The salt MUST be a fresh random
    /// 16-byte value stored alongside the flock descriptor so that all
    /// members can reproduce the key. The room code is treated purely as an
    /// identifier, not as key material — the salt prevents precomputation
    /// and the memory hardness raises the cost of brute-force attacks.
    ///
    /// Prefer [`from_secret`] for new flocks; use this only when a
    /// code-derived key is unavoidable (e.g. bridging a legacy flock).
    pub fn from_room_code_v2(code: &str, salt: &[u8; 16]) -> anyhow::Result<Self> {
        let mut key = [0u8; 32];
        Argon2::default()
            .hash_password_into(code.as_bytes(), salt, &mut key)
            .map_err(|_| anyhow::anyhow!("flock KDF failed"))?;
        Ok(Self {
            cipher: ChaCha20Poly1305::new((&key).into()),
        })
    }

    /// Construct a flock cipher directly from a granted 32-byte secret. Unlike
    /// [`from_room_code`], the key is not derivable from any public code, so a
    /// roost can mint per-channel secrets and hand them only to admitted birds.
    pub fn from_secret(secret: &[u8; 32]) -> Self {
        let cipher = ChaCha20Poly1305::new(secret.into());
        Self { cipher }
    }

    #[deprecated(since = "0.3.19", note = "use try_encrypt and propagate the Result")]
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        self.try_encrypt(plaintext).unwrap_or_else(|e| {
            crate::logger::warn(&format!("flock encryption failed: {e}"));
            Vec::new()
        })
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

/// Header on a sealed chirp: a 24-byte X25519 NaCl-style nonce followed by the
/// `crypto_box` `ChaCha20Poly1305` ciphertext. The flock never needs to read
/// this — only the addressed recipient's `crypto_box` private key opens it.
const CHIRP_NONCE_LEN: usize = 24;

/// Seal a 1:1 chirp to `their` DM public key using `my` DM secret key for the
/// X25519 DH derivation. Output is `[24-byte nonce | ciphertext]` and can be
/// sent through a flock that only relays opaque bytes.
pub fn seal_chirp(my: &DmSecretKey, their: &DmPublicKey, plain: &[u8]) -> anyhow::Result<Vec<u8>> {
    let box_ = ChaChaBox::new(their, my);
    let nonce = ChaChaBox::generate_nonce(&mut OsRng);
    let ciphertext = box_
        .encrypt(&nonce, plain)
        .map_err(|_| anyhow::anyhow!("failed to seal chirp"))?;
    let mut out = nonce.to_vec();
    out.extend(ciphertext);
    Ok(out)
}

/// Open a chirp sealed with [`seal_chirp`]. Returns `None` if the blob is too
/// short to contain a nonce, if the sender's published DM key is unknown, or
/// if the AEAD tag fails authentication (the blob was tampered with or was
/// sealed to a different recipient's key).
pub fn open_chirp(my: &DmSecretKey, their: &DmPublicKey, blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() < CHIRP_NONCE_LEN {
        return None;
    }
    ChaChaBox::new(their, my)
        .decrypt(blob[..CHIRP_NONCE_LEN].into(), &blob[CHIRP_NONCE_LEN..])
        .ok()
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
        #[allow(deprecated)]
        let crypto = FlockCrypto::from_room_code("room");
        let ciphertext = crypto.try_encrypt(b"hello").expect("encrypt");
        assert_eq!(crypto.try_decrypt(&ciphertext).expect("decrypt"), b"hello");

        let mut tampered = ciphertext;
        *tampered.last_mut().expect("ciphertext byte") ^= 1;
        assert!(crypto.try_decrypt(&tampered).is_err());
        assert!(crypto.try_decrypt(&[0; 11]).is_err());
    }

    #[test]
    fn v2_round_trip_and_salt_isolation() {
        let salt_a: [u8; 16] = rand::random();
        let salt_b: [u8; 16] = rand::random();
        let crypto = FlockCrypto::from_room_code_v2("room", &salt_a).expect("KDF");
        let ciphertext = crypto.try_encrypt(b"hello").expect("encrypt");
        assert_eq!(crypto.try_decrypt(&ciphertext).expect("decrypt"), b"hello");

        // Different salt produces a different key — cannot decrypt.
        let other = FlockCrypto::from_room_code_v2("room", &salt_b).expect("KDF");
        assert!(other.try_decrypt(&ciphertext).is_err());

        // Tampered ciphertext fails authentication.
        let mut tampered = ciphertext;
        *tampered.last_mut().expect("ciphertext byte") ^= 1;
        assert!(crypto.try_decrypt(&tampered).is_err());
    }

    #[test]
    fn sealed_chirps_open_only_for_the_addressed_recipient() {
        use crypto_box::SecretKey as DmSecretKey;

        let mut rng = super::OsRng;
        let alice = DmSecretKey::generate(&mut rng);
        let bob = DmSecretKey::generate(&mut rng);
        let eve = DmSecretKey::generate(&mut rng);
        let bob_pk = bob.public_key();
        let alice_pk = alice.public_key();

        let sealed = super::seal_chirp(&alice, &bob_pk, b"chirp").expect("seal");
        assert_eq!(
            super::open_chirp(&bob, &alice_pk, &sealed).expect("bob opens"),
            b"chirp"
        );
        assert!(
            super::open_chirp(&eve, &alice_pk, &sealed).is_none(),
            "eve has no matching secret"
        );
        // Wrong sender public key rejects the AEAD tag (the DH was different).
        assert!(super::open_chirp(&bob, &bob_pk, &sealed).is_none());

        // Anything shorter than the nonce is rejected before AEAD.
        assert!(super::open_chirp(&bob, &alice_pk, &[0u8; 4]).is_none());

        let mut tampered = sealed;
        *tampered.last_mut().unwrap() ^= 1;
        assert!(super::open_chirp(&bob, &alice_pk, &tampered).is_none());
    }
}
