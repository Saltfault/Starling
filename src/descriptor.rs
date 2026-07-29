//! Canonical, signed flock descriptor chains.

use anyhow::{Context, ensure};
use iroh::{EndpointId, Signature};
use iroh_gossip::proto::TopicId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    membership::{MembershipScopeId, MembershipState},
    protocol::FlockId,
};

pub const MAX_BOOTSTRAP_PEERS: usize = 32;

const SIGNING_DOMAIN: &[u8] = b"starling/flock-descriptor/v1/sign\0";
const HASH_DOMAIN: &[u8] = b"starling/flock-descriptor/v1/hash\0";
const TOPIC_DOMAIN: &[u8] = b"starling/flock-topic/v1\0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlockDescriptorBodyV1 {
    pub flock: FlockId,
    pub descriptor_revision: u64,
    pub previous_hash: Option<[u8; 32]>,
    pub topic_id: TopicId,
    pub membership_revision: u64,
    pub key_epoch: u64,
    pub bootstrap: Vec<EndpointId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedFlockDescriptorV1 {
    pub body: FlockDescriptorBodyV1,
    pub signer: EndpointId,
    pub signature: Signature,
}

impl FlockDescriptorBodyV1 {
    pub fn validate_shape(&self) -> anyhow::Result<()> {
        ensure!(
            self.bootstrap.len() <= MAX_BOOTSTRAP_PEERS,
            "too many bootstrap peers"
        );
        ensure!(
            self.bootstrap.windows(2).all(|pair| pair[0] < pair[1]),
            "bootstrap peers must be sorted and unique"
        );
        Ok(())
    }

    pub fn canonical_bytes(&self) -> anyhow::Result<Vec<u8>> {
        self.validate_shape()?;
        domain_encode(SIGNING_DOMAIN, self)
    }

    pub fn hash(&self) -> anyhow::Result<[u8; 32]> {
        self.validate_shape()?;
        hash_encoded(HASH_DOMAIN, self)
    }

    pub fn sign(self, key: &iroh::SecretKey) -> anyhow::Result<SignedFlockDescriptorV1> {
        let signer = key.public();
        let signature = key.sign(&self.canonical_bytes()?);
        Ok(SignedFlockDescriptorV1 {
            body: self,
            signer,
            signature,
        })
    }
}

impl SignedFlockDescriptorV1 {
    pub fn canonical_bytes(&self) -> anyhow::Result<Vec<u8>> {
        self.body.canonical_bytes()
    }

    pub fn hash(&self) -> anyhow::Result<[u8; 32]> {
        self.body.hash()
    }

    pub fn verify(&self) -> anyhow::Result<()> {
        self.body.validate_shape()?;
        self.signer
            .verify(&self.canonical_bytes()?, &self.signature)?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct DescriptorState {
    flock: FlockId,
    descriptor_revision: u64,
    head_hash: [u8; 32],
    topic_id: TopicId,
    membership_revision: u64,
    key_epoch: u64,
    current: SignedFlockDescriptorV1,
}

impl DescriptorState {
    pub fn genesis(
        descriptor: SignedFlockDescriptorV1,
        membership: &MembershipState,
    ) -> anyhow::Result<Self> {
        descriptor
            .verify()
            .context("invalid descriptor signature")?;
        let body = &descriptor.body;
        ensure!(
            body.descriptor_revision == 0,
            "initial descriptor revision must be zero"
        );
        ensure!(
            body.previous_hash.is_none(),
            "initial descriptor cannot have a previous hash"
        );
        validate_membership_authority(body, descriptor.signer, membership)?;
        let head_hash = descriptor.hash()?;
        Ok(Self {
            flock: body.flock,
            descriptor_revision: 0,
            head_hash,
            topic_id: body.topic_id,
            membership_revision: body.membership_revision,
            key_epoch: body.key_epoch,
            current: descriptor,
        })
    }

    pub fn apply(
        &mut self,
        descriptor: SignedFlockDescriptorV1,
        membership: &MembershipState,
    ) -> anyhow::Result<()> {
        descriptor
            .verify()
            .context("invalid descriptor signature")?;
        let body = &descriptor.body;
        ensure!(
            body.flock == self.flock,
            "descriptor changed stable flock identity"
        );
        let next_revision = self
            .descriptor_revision
            .checked_add(1)
            .context("descriptor revision overflow")?;
        ensure!(
            body.descriptor_revision == next_revision,
            "descriptor revision must increment exactly once"
        );
        ensure!(
            body.previous_hash == Some(self.head_hash),
            "descriptor fork or missing descriptor"
        );
        ensure!(
            body.membership_revision >= self.membership_revision,
            "descriptor membership revision regressed"
        );
        ensure!(
            body.key_epoch >= self.key_epoch,
            "descriptor key epoch regressed"
        );
        validate_membership_authority(body, descriptor.signer, membership)?;

        self.descriptor_revision = body.descriptor_revision;
        self.head_hash = descriptor.hash()?;
        self.topic_id = body.topic_id;
        self.membership_revision = body.membership_revision;
        self.key_epoch = body.key_epoch;
        self.current = descriptor;
        Ok(())
    }

    pub fn fold(
        descriptors: impl IntoIterator<Item = SignedFlockDescriptorV1>,
        membership: &MembershipState,
    ) -> anyhow::Result<Self> {
        let mut descriptors = descriptors.into_iter();
        let first = descriptors.next().context("descriptor chain is empty")?;
        let mut state = Self::genesis(first, membership)?;
        for descriptor in descriptors {
            state.apply(descriptor, membership)?;
        }
        Ok(state)
    }

    pub fn flock(&self) -> FlockId {
        self.flock
    }
    pub fn descriptor_revision(&self) -> u64 {
        self.descriptor_revision
    }
    pub fn head_hash(&self) -> [u8; 32] {
        self.head_hash
    }
    pub fn topic_id(&self) -> TopicId {
        self.topic_id
    }
    pub fn membership_revision(&self) -> u64 {
        self.membership_revision
    }
    pub fn key_epoch(&self) -> u64 {
        self.key_epoch
    }
    pub fn current(&self) -> &SignedFlockDescriptorV1 {
        &self.current
    }
}

/// Derives the initial V1 topic. Later descriptors may explicitly rotate it.
pub fn derive_topic_id_v1(flock: &FlockId) -> TopicId {
    let mut hasher = Sha256::new();
    hasher.update(TOPIC_DOMAIN);
    hasher.update(flock.0);
    TopicId::from_bytes(hasher.finalize().into())
}

fn validate_membership_authority(
    body: &FlockDescriptorBodyV1,
    signer: EndpointId,
    membership: &MembershipState,
) -> anyhow::Result<()> {
    ensure!(
        membership.scope() == MembershipScopeId::Flock(body.flock),
        "descriptor flock and membership scope differ"
    );
    let snapshot = membership
        .snapshot(body.membership_revision)
        .context("descriptor references unknown membership revision")?;
    ensure!(
        body.key_epoch >= snapshot.key_epoch,
        "descriptor key epoch predates the membership snapshot"
    );
    ensure!(
        membership.admin_at(&signer, body.membership_revision, body.key_epoch),
        "descriptor signer lacks historical admin authority"
    );
    Ok(())
}

fn domain_encode<T: Serialize>(domain: &[u8], value: &T) -> anyhow::Result<Vec<u8>> {
    let encoded = postcard::to_stdvec(value)?;
    let mut bytes = Vec::with_capacity(domain.len() + encoded.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&encoded);
    Ok(bytes)
}

fn hash_encoded<T: Serialize>(domain: &[u8], value: &T) -> anyhow::Result<[u8; 32]> {
    Ok(Sha256::digest(domain_encode(domain, value)?).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::membership::{
        MemberRole, MembershipMutationBodyV1, MembershipOperationV1, SignedMembershipMutationV1,
    };

    fn membership(flock: FlockId, admin: EndpointId) -> MembershipState {
        MembershipState::genesis(MembershipScopeId::Flock(flock), admin)
    }

    fn mutation(
        state: &MembershipState,
        key: &iroh::SecretKey,
        operation: MembershipOperationV1,
    ) -> SignedMembershipMutationV1 {
        MembershipMutationBodyV1 {
            scope: state.scope(),
            revision: state.revision() + 1,
            previous_hash: state.head_hash(),
            actor: key.public(),
            operation,
            effective_key_epoch: state.key_epoch(),
        }
        .sign(key)
        .unwrap()
    }

    fn descriptor(
        key: &iroh::SecretKey,
        state: &MembershipState,
        revision: u64,
        previous_hash: Option<[u8; 32]>,
        topic_id: TopicId,
        key_epoch: u64,
    ) -> SignedFlockDescriptorV1 {
        let MembershipScopeId::Flock(flock) = state.scope() else {
            panic!("flock scope")
        };
        FlockDescriptorBodyV1 {
            flock,
            descriptor_revision: revision,
            previous_hash,
            topic_id,
            membership_revision: state.revision(),
            key_epoch,
            bootstrap: vec![key.public()],
        }
        .sign(key)
        .unwrap()
    }

    #[test]
    fn topic_rotation_preserves_stable_flock() {
        let admin = iroh::SecretKey::generate();
        let flock = FlockId([1; 32]);
        let membership = membership(flock, admin.public());
        let first_topic = derive_topic_id_v1(&flock);
        let first = descriptor(&admin, &membership, 0, None, first_topic, 0);
        let mut state = DescriptorState::genesis(first, &membership).unwrap();
        let rotated_topic = TopicId::from_bytes([9; 32]);
        let next = descriptor(
            &admin,
            &membership,
            1,
            Some(state.head_hash()),
            rotated_topic,
            0,
        );
        state.apply(next, &membership).unwrap();
        assert_eq!(state.flock(), flock);
        assert_eq!(state.topic_id(), rotated_topic);
        assert_ne!(first_topic, rotated_topic);
    }

    #[test]
    fn rejects_bad_authority_tampering_and_rollbacks() {
        let admin = iroh::SecretKey::generate();
        let outsider = iroh::SecretKey::generate();
        let flock = FlockId([2; 32]);
        let membership = membership(flock, admin.public());
        let first = descriptor(&admin, &membership, 0, None, derive_topic_id_v1(&flock), 0);
        let mut state = DescriptorState::genesis(first, &membership).unwrap();
        let unauthorized = descriptor(
            &outsider,
            &membership,
            1,
            Some(state.head_hash()),
            TopicId::from_bytes([3; 32]),
            0,
        );
        assert!(state.apply(unauthorized, &membership).is_err());
        let mut tampered = descriptor(
            &admin,
            &membership,
            1,
            Some(state.head_hash()),
            TopicId::from_bytes([4; 32]),
            0,
        );
        tampered.body.topic_id = TopicId::from_bytes([5; 32]);
        assert!(state.apply(tampered, &membership).is_err());

        let next_admin = iroh::SecretKey::generate();
        let mut advanced = membership.clone();
        advanced
            .apply(&mutation(
                &advanced,
                &admin,
                MembershipOperationV1::Add {
                    member: next_admin.public(),
                    role: MemberRole::Admin,
                },
            ))
            .unwrap();
        let mut rollback = descriptor(
            &admin,
            &advanced,
            1,
            Some(state.head_hash()),
            TopicId::from_bytes([6; 32]),
            0,
        );
        rollback.body.membership_revision = 0;
        assert!(state.apply(rollback, &advanced).is_err());
    }

    #[test]
    fn enforces_canonical_bounded_bootstrap() {
        let key = iroh::SecretKey::generate();
        let flock = FlockId([7; 32]);
        let state = membership(flock, key.public());
        let mut body = descriptor(&key, &state, 0, None, derive_topic_id_v1(&flock), 0).body;
        body.bootstrap = vec![key.public(), key.public()];
        assert!(body.canonical_bytes().is_err());
        body.bootstrap = (0..=MAX_BOOTSTRAP_PEERS)
            .map(|_| iroh::SecretKey::generate().public())
            .collect();
        assert!(body.canonical_bytes().is_err());
    }
}
