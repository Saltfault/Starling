use iroh::{EndpointId, Signature};
use serde::{Deserialize, Serialize};

use super::{MAX_BODY_BYTES, SpaceId};

const SIGNING_DOMAIN: &[u8] = b"starling/v1/signed-event";
pub const MAX_EVENT_PARENTS: usize = 64;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventUnsignedV1 {
    pub space: SpaceId,
    pub sender: EndpointId,
    pub session_id: [u8; 16],
    pub sequence: u64,
    pub key_epoch: u64,
    pub parents: Vec<[u8; 32]>,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedEventV1 {
    pub event: EventUnsignedV1,
    pub signature: Signature,
}

impl EventUnsignedV1 {
    pub fn validate_shape(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.parents.len() <= MAX_EVENT_PARENTS,
            "event has too many parents"
        );
        anyhow::ensure!(
            self.parents.windows(2).all(|pair| pair[0] < pair[1]),
            "event parents must be sorted and unique"
        );
        anyhow::ensure!(
            self.ciphertext.len() <= MAX_BODY_BYTES,
            "event ciphertext is too large"
        );
        Ok(())
    }

    pub fn signing_bytes(&self) -> anyhow::Result<Vec<u8>> {
        self.validate_shape()?;
        let encoded = postcard::to_stdvec(self)?;
        let mut bytes = Vec::with_capacity(SIGNING_DOMAIN.len() + encoded.len());
        bytes.extend_from_slice(SIGNING_DOMAIN);
        bytes.extend_from_slice(&encoded);
        Ok(bytes)
    }

    pub fn sign(self, secret_key: &iroh::SecretKey) -> anyhow::Result<SignedEventV1> {
        anyhow::ensure!(
            self.sender == secret_key.public(),
            "event sender does not match the signing key"
        );
        let signature = secret_key.sign(&self.signing_bytes()?);
        Ok(SignedEventV1 {
            event: self,
            signature,
        })
    }
}

impl SignedEventV1 {
    pub fn verify(&self) -> anyhow::Result<()> {
        self.event.validate_shape()?;
        self.event
            .sender
            .verify(&self.event.signing_bytes()?, &self.signature)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{EventUnsignedV1, MAX_EVENT_PARENTS};
    use crate::protocol::{FlockId, SpaceId};

    fn event(sender: iroh::EndpointId) -> EventUnsignedV1 {
        EventUnsignedV1 {
            space: SpaceId::Flock(FlockId([1; 32])),
            sender,
            session_id: [2; 16],
            sequence: 1,
            key_epoch: 0,
            parents: vec![[3; 32], [4; 32]],
            nonce: [5; 12],
            ciphertext: vec![6, 7, 8],
        }
    }

    #[test]
    fn signs_verifies_and_serializes_events() {
        let key = iroh::SecretKey::generate();
        let signed = event(key.public()).sign(&key).expect("sign event");
        signed.verify().expect("verify event");

        let encoded = postcard::to_stdvec(&signed).expect("serialize event");
        let decoded: super::SignedEventV1 =
            postcard::from_bytes(&encoded).expect("deserialize event");
        decoded.verify().expect("verify decoded event");
    }

    #[test]
    fn rejects_tampering_wrong_signers_and_invalid_parents() {
        let key = iroh::SecretKey::generate();
        let mut signed = event(key.public()).sign(&key).expect("sign event");
        signed.event.ciphertext[0] ^= 0xff;
        assert!(signed.verify().is_err());

        let wrong_key = iroh::SecretKey::generate();
        assert!(event(key.public()).sign(&wrong_key).is_err());

        let mut duplicate_parents = event(key.public());
        duplicate_parents.parents = vec![[3; 32], [3; 32]];
        assert!(duplicate_parents.validate_shape().is_err());

        let mut too_many_parents = event(key.public());
        too_many_parents.parents = vec![[0; 32]; MAX_EVENT_PARENTS + 1];
        assert!(too_many_parents.validate_shape().is_err());
    }
}
