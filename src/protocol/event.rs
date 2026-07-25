use iroh::{EndpointId, Signature};
use serde::{Deserialize, Serialize};
use sha2_10::{Digest, Sha256};

use crate::crypto::EpochKey;

use super::{MAX_BODY_BYTES, SpaceId};

const SIGNING_DOMAIN: &[u8] = b"starling/v1/signed-event\0";
const HASH_DOMAIN: &[u8] = b"starling/v1/event-hash\0";
const AAD_DOMAIN: &[u8] = b"starling/v1/event-aad\0";
const MAX_EVENT_OVERHEAD: usize = 2 * 1024;
pub const MAX_EVENT_PARENTS: usize = 32;
pub const MAX_EVENT_CIPHERTEXT: usize = MAX_BODY_BYTES - MAX_EVENT_OVERHEAD;
pub type EventHash = [u8; 32];

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EventMetadataV1 {
    pub kind: u16,
    pub space: SpaceId,
    pub sender: EndpointId,
    pub session_id: [u8; 16],
    pub sequence: u64,
    pub key_epoch: u64,
    pub membership_revision: u64,
    pub parents: Vec<EventHash>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventUnsignedV1 {
    pub kind: u16,
    pub space: SpaceId,
    pub sender: EndpointId,
    pub session_id: [u8; 16],
    pub sequence: u64,
    pub key_epoch: u64,
    pub membership_revision: u64,
    pub parents: Vec<EventHash>,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedEventV1 {
    pub event: EventUnsignedV1,
    pub signature: Signature,
}

impl EventMetadataV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: u16,
        space: SpaceId,
        sender: EndpointId,
        session_id: [u8; 16],
        sequence: u64,
        key_epoch: u64,
        membership_revision: u64,
        mut parents: Vec<EventHash>,
    ) -> anyhow::Result<Self> {
        parents.sort_unstable();
        parents.dedup();
        anyhow::ensure!(
            parents.len() <= MAX_EVENT_PARENTS,
            "event has too many parents"
        );
        Ok(Self {
            kind,
            space,
            sender,
            session_id,
            sequence,
            key_epoch,
            membership_revision,
            parents,
        })
    }

    pub fn canonical_bytes(&self) -> anyhow::Result<Vec<u8>> {
        self.validate()?;
        Ok(postcard::to_stdvec(self)?)
    }

    fn validate(&self) -> anyhow::Result<()> {
        validate_parents(&self.parents)
    }

    fn aad(&self) -> anyhow::Result<Vec<u8>> {
        let canonical = self.canonical_bytes()?;
        let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + canonical.len());
        aad.extend_from_slice(AAD_DOMAIN);
        aad.extend_from_slice(&canonical);
        Ok(aad)
    }

    pub fn seal_and_sign(
        self,
        plaintext: &[u8],
        epoch_key: &EpochKey,
        secret_key: &iroh::SecretKey,
    ) -> anyhow::Result<SignedEventV1> {
        anyhow::ensure!(
            self.sender == secret_key.public(),
            "event sender does not match the signing key"
        );
        anyhow::ensure!(
            plaintext.len() <= MAX_EVENT_CIPHERTEXT - 16,
            "event plaintext is too large"
        );
        let aad = self.aad()?;
        let (nonce, ciphertext) = epoch_key.seal(plaintext, &aad)?;
        EventUnsignedV1 {
            kind: self.kind,
            space: self.space,
            sender: self.sender,
            session_id: self.session_id,
            sequence: self.sequence,
            key_epoch: self.key_epoch,
            membership_revision: self.membership_revision,
            parents: self.parents,
            nonce,
            ciphertext,
        }
        .sign(secret_key)
    }
}

impl EventUnsignedV1 {
    pub fn metadata(&self) -> EventMetadataV1 {
        EventMetadataV1 {
            kind: self.kind,
            space: self.space,
            sender: self.sender,
            session_id: self.session_id,
            sequence: self.sequence,
            key_epoch: self.key_epoch,
            membership_revision: self.membership_revision,
            parents: self.parents.clone(),
        }
    }

    pub fn validate_shape(&self) -> anyhow::Result<()> {
        self.metadata().validate()?;
        anyhow::ensure!(
            self.ciphertext.len() <= MAX_EVENT_CIPHERTEXT,
            "event ciphertext is too large"
        );
        Ok(())
    }

    pub fn canonical_bytes(&self) -> anyhow::Result<Vec<u8>> {
        self.validate_shape()?;
        Ok(postcard::to_stdvec(self)?)
    }

    pub fn hash(&self) -> anyhow::Result<EventHash> {
        let canonical = self.canonical_bytes()?;
        let mut hasher = Sha256::new();
        hasher.update(HASH_DOMAIN);
        hasher.update(canonical);
        Ok(hasher.finalize().into())
    }

    fn signing_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let canonical = self.canonical_bytes()?;
        let mut bytes = Vec::with_capacity(SIGNING_DOMAIN.len() + canonical.len());
        bytes.extend_from_slice(SIGNING_DOMAIN);
        bytes.extend_from_slice(&canonical);
        Ok(bytes)
    }

    pub fn sign(self, secret_key: &iroh::SecretKey) -> anyhow::Result<SignedEventV1> {
        anyhow::ensure!(
            self.sender == secret_key.public(),
            "event sender does not match the signing key"
        );
        let signature = secret_key.sign(&self.signing_bytes()?);
        let signed = SignedEventV1 {
            event: self,
            signature,
        };
        signed.validate_frame_size()?;
        Ok(signed)
    }
}

impl SignedEventV1 {
    fn validate_frame_size(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            postcard::to_stdvec(self)?.len() <= MAX_BODY_BYTES,
            "serialized event does not fit in a frame"
        );
        Ok(())
    }

    /// Verifies shape, frame size, and signature, returning the canonical event hash.
    pub fn verify(&self) -> anyhow::Result<EventHash> {
        self.event.validate_shape()?;
        self.validate_frame_size()?;
        self.event
            .sender
            .verify(&self.event.signing_bytes()?, &self.signature)?;
        self.event.hash()
    }

    /// Verifies the signature before attempting authenticated decryption.
    pub fn open(&self, epoch_key: &EpochKey) -> anyhow::Result<(EventHash, Vec<u8>)> {
        let hash = self.verify()?;
        let plaintext = epoch_key.open(
            &self.event.nonce,
            &self.event.ciphertext,
            &self.event.metadata().aad()?,
        )?;
        Ok((hash, plaintext))
    }
}

fn validate_parents(parents: &[EventHash]) -> anyhow::Result<()> {
    anyhow::ensure!(
        parents.len() <= MAX_EVENT_PARENTS,
        "event has too many parents"
    );
    anyhow::ensure!(
        parents.windows(2).all(|pair| pair[0] < pair[1]),
        "event parents must be sorted and unique"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{EventMetadataV1, MAX_EVENT_PARENTS};
    use crate::{
        crypto::EpochKey,
        protocol::{FlockId, SpaceId},
    };

    fn fixture() -> (iroh::SecretKey, EpochKey, EventMetadataV1) {
        let signing_key = iroh::SecretKey::from_bytes(&[7; 32]);
        let epoch_key = EpochKey::derive(b"epoch secret", b"fixture space", 3).unwrap();
        let metadata = EventMetadataV1::new(
            9,
            SpaceId::Flock(FlockId([1; 32])),
            signing_key.public(),
            [2; 16],
            11,
            3,
            5,
            vec![[4; 32], [3; 32], [4; 32]],
        )
        .unwrap();
        (signing_key, epoch_key, metadata)
    }

    #[test]
    fn canonical_metadata_sorts_and_deduplicates_parents() {
        let (_, _, metadata) = fixture();
        assert_eq!(metadata.parents, vec![[3; 32], [4; 32]]);
        assert_eq!(metadata.canonical_bytes().unwrap().len(), 150);
    }

    #[test]
    fn seals_signs_verifies_and_opens() {
        let (signing_key, epoch_key, metadata) = fixture();
        let signed = metadata
            .seal_and_sign(b"hello", &epoch_key, &signing_key)
            .unwrap();
        let expected_hash = signed.event.hash().unwrap();
        assert_eq!(signed.verify().unwrap(), expected_hash);
        let (hash, plaintext) = signed.open(&epoch_key).unwrap();
        assert_eq!(hash, expected_hash);
        assert_eq!(plaintext, b"hello");

        let encoded = postcard::to_stdvec(&signed).unwrap();
        let decoded: super::SignedEventV1 = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded.open(&epoch_key).unwrap().1, b"hello");
    }

    #[test]
    fn canonical_event_and_hash_golden() {
        let (signing_key, _, metadata) = fixture();
        let event = super::EventUnsignedV1 {
            kind: metadata.kind,
            space: metadata.space,
            sender: signing_key.public(),
            session_id: metadata.session_id,
            sequence: metadata.sequence,
            key_epoch: metadata.key_epoch,
            membership_revision: metadata.membership_revision,
            parents: metadata.parents,
            nonce: [6; 12],
            ciphertext: vec![7, 8, 9],
        };
        assert_eq!(event.canonical_bytes().unwrap().len(), 166);
        assert_eq!(
            event.hash().unwrap(),
            [
                0x6c, 0xdd, 0x9f, 0x5d, 0x93, 0x6a, 0x3b, 0x57, 0x16, 0x01, 0xe6, 0xe9, 0x80, 0x85,
                0xbb, 0xde, 0xb9, 0xf2, 0x9d, 0x9d, 0x19, 0x0b, 0xfd, 0xcd, 0xb1, 0xa0, 0x3b, 0x45,
                0x8d, 0x79, 0x65, 0x1a,
            ]
        );
    }

    #[test]
    fn rejects_signature_ciphertext_and_aad_tampering() {
        let (signing_key, epoch_key, metadata) = fixture();
        let signed = metadata
            .seal_and_sign(b"hello", &epoch_key, &signing_key)
            .unwrap();

        let mut ciphertext = signed.clone();
        ciphertext.event.ciphertext[0] ^= 1;
        assert!(ciphertext.open(&epoch_key).is_err());

        let mut aad = signed.clone();
        aad.event.sequence += 1;
        assert!(aad.open(&epoch_key).is_err());

        let mut nonce = signed;
        nonce.event.nonce[0] ^= 1;
        assert!(nonce.open(&epoch_key).is_err());
    }

    #[test]
    fn rejects_wrong_signers_and_excessive_parents() {
        let (signing_key, epoch_key, metadata) = fixture();
        let wrong_key = iroh::SecretKey::generate();
        assert!(
            metadata
                .clone()
                .seal_and_sign(b"hello", &epoch_key, &wrong_key)
                .is_err()
        );
        assert!(
            EventMetadataV1::new(
                1,
                metadata.space,
                signing_key.public(),
                [0; 16],
                0,
                0,
                0,
                (0..=MAX_EVENT_PARENTS)
                    .map(|value| [value as u8; 32])
                    .collect(),
            )
            .is_err()
        );
    }
}
