use iroh::EndpointId;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChatMessage {
    pub id: String,
    pub author: String,
    pub body: String,
    pub ts: i64,
}

/// Signed wrapper. What actually gets encrypted and broadcast on the V0
/// gossip layer is `postcard(Signed)`, not `postcard(GossipPayload)` —
/// receivers verify the signature before trusting the inner payload, so a
/// bird can no longer claim another bird's [`EndpointId`] or display name.
///
/// The signature covers `domain || payload`, where `domain` is
/// [`SIGNED_DOMAIN`], so a gossip signature cannot be replayed as a presence
/// lease, call signal, or any other ed25519 artifact in the system.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signed {
    pub author: EndpointId,
    pub payload: Vec<u8>,
    pub sig: Vec<u8>,
}

/// Domain separator bound into every [`Signed`] envelope so its signature
/// cannot be replayed into a different protocol that also uses iroh's
/// ed25519 keys.
pub const SIGNED_DOMAIN: &[u8] = b"starling/v1/gossip-signed";

impl Signed {
    /// Wrap `payload` (already-serialized `GossipPayload` bytes) in a signed
    /// envelope owned by `secret`. The signer's public key is published as
    /// `author` so receivers can authenticate the contents and bind the
    /// contained identity claim (`GossipPayload::Profile { id }`,
    /// `GossipPayload::Status { id }`, etc.) to a real cryptographic key.
    pub fn sign(secret: &iroh::SecretKey, payload: Vec<u8>) -> Self {
        let author = secret.public();
        let signing_bytes = Self::signing_bytes(&payload);
        let signature = secret.sign(&signing_bytes);
        Self {
            author,
            payload,
            sig: signature.to_bytes().to_vec(),
        }
    }

    fn signing_bytes(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(SIGNED_DOMAIN.len() + payload.len());
        out.extend_from_slice(SIGNED_DOMAIN);
        out.extend_from_slice(payload);
        out
    }

    /// Verify the signature against the public key in `author`. Supports any
    /// payload, not just `GossipPayload`, so future Mesh/MLS envelopes can
    /// reuse the same outer envelope without introducing a new domain that
    /// attackers could confuse for chat.
    pub fn verify(&self) -> anyhow::Result<()> {
        let signature = iroh::Signature::try_from(self.sig.as_slice())
            .map_err(|_| anyhow::anyhow!("malformed gossip signature"))?;
        self.author
            .verify(&Self::signing_bytes(&self.payload), &signature)
            .map_err(|_| anyhow::anyhow!("gossip signature verification failed"))
    }

    /// Number of bytes a serialized [`Signed`] envelope inserts ahead of the
    /// inner `postcard(GossipPayload)` body — used by tests to guard size
    /// regressions on the gossip payload.
    pub const OVERHEAD_BYTES: usize = 32 + 64 + 4;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GossipPayload {
    Chat(ChatMessage),
    /// `dm_pk` is the sender's `crypto_box` public key, published alongside
    /// the display name so peers can seal chirps to them. `id` MUST equal
    /// `Signed::author` (verified on receive); a mismatched `id` is a
    /// forgery attempt and is dropped before binding any name.
    Profile {
        id: EndpointId,
        name: String,
        dm_pk: Vec<u8>,
        pronouns: String,
    },
    /// `id` MUST equal `Signed::author`; mismatched status claims are dropped.
    Status {
        id: EndpointId,
        status: BirdStatus,
    },
    Presence(crate::presence::SignedPresenceLeaseV1),
    /// A private 1:1 chirp sealed to `to`'s published DM public key. The
    /// flock relays the opaque `sealed` blob; only the addressee can open
    /// it. `signed.author` is the seal maker's verified endpoint.
    Chirp {
        to: EndpointId,
        sealed: Vec<u8>,
    },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum BirdStatus {
    Online,
    Idle,
    InCall,
}

#[cfg(test)]
mod tests {
    use super::{GossipPayload, SIGNED_DOMAIN, Signed};

    #[test]
    fn signed_envelope_round_trips_and_rejects_tampering() {
        let secret = iroh::SecretKey::generate();
        let payload = postcard::to_stdvec(&GossipPayload::Status {
            id: secret.public(),
            status: super::BirdStatus::Online,
        })
        .expect("serialize payload");
        let signed = Signed::sign(&secret, payload.clone());
        assert_eq!(signed.author, secret.public());
        signed.verify().expect("valid signature verifies");

        let mut forged = signed.clone();
        forged.payload[0] ^= 0xff;
        assert!(forged.verify().is_err(), "tampered payload must fail");

        let mut stolen_sig = signed.clone();
        // Move the real signature onto a payload owned by a different author.
        let other = iroh::SecretKey::generate();
        let forged_payload = postcard::to_stdvec(&GossipPayload::Status {
            id: secret.public(),
            status: super::BirdStatus::Idle,
        })
        .expect("serialize forged payload");
        stolen_sig.author = other.public();
        stolen_sig.payload = forged_payload;
        assert!(
            stolen_sig.verify().is_err(),
            "cross-author signature rejected"
        );

        assert_eq!(SIGNED_DOMAIN, b"starling/v1/gossip-signed");
    }
}
