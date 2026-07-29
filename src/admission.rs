use std::collections::{HashMap, VecDeque};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use iroh::{EndpointId, Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::protocol::RoostId;

pub const ADMISSION_ALPN: &[u8] = b"starling/admission/1";
pub const FRAME_ADMISSION_CHALLENGE: u16 = 0x2101;
pub const FRAME_ADMISSION_REQUEST: u16 = 0x2102;
pub const FRAME_ADMISSION_CERTIFICATE: u16 = 0x2103;
pub const PROTOCOL_MAJOR: u16 = 1;
pub const CHALLENGE_BYTES: usize = 32;
pub const MAX_CONNECTION_BINDING_BYTES: usize = 256;
pub const MAX_CAPABILITY_BYTES: usize = 256;
const AUTH_PROOF_DOMAIN: &[u8] = b"starling/admission-auth-proof/v1\0";
const CERTIFICATE_DOMAIN: &[u8] = b"starling/membership-certificate/v1\0";
const CAPABILITY_DOMAIN: &[u8] = b"starling/admission-capability/v1\0";

pub type Challenge = [u8; CHALLENGE_BYTES];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionChallenge {
    pub major: u16,
    pub roost_id: RoostId,
    pub server: EndpointId,
    pub challenge: Challenge,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AdmissionRequestKind {
    Join = 1,
    Renew = 2,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionAuthProof {
    pub major: u16,
    pub roost_id: RoostId,
    pub server: EndpointId,
    pub client: EndpointId,
    pub connection_binding: Vec<u8>,
    pub challenge: Challenge,
    pub kind: AdmissionRequestKind,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedAdmissionAuthProof {
    pub proof: AdmissionAuthProof,
    pub signature: Signature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionRequest {
    pub auth: SignedAdmissionAuthProof,
    pub capability: AdmissionCapability,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionCapability {
    pub epoch: u64,
    pub digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipCertificate {
    pub major: u16,
    pub roost_id: RoostId,
    pub member: EndpointId,
    pub issuer: EndpointId,
    pub membership_epoch: u64,
    pub auth_generation: u64,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedMembershipCertificate {
    pub certificate: MembershipCertificate,
    pub signature: Signature,
}

pub trait MembershipValidationHooks {
    fn issuer_was_authorized(
        &self,
        roost_id: &RoostId,
        epoch: u64,
        issuer: &EndpointId,
    ) -> anyhow::Result<()>;
    fn member_generation_is_current(
        &self,
        roost_id: &RoostId,
        member: &EndpointId,
        generation: u64,
    ) -> anyhow::Result<()>;
}

pub struct ChallengeStore {
    capacity: usize,
    lifetime: Duration,
    entries: HashMap<Challenge, u64>,
    order: VecDeque<Challenge>,
}

impl ChallengeStore {
    pub fn new(capacity: usize, lifetime: Duration) -> anyhow::Result<Self> {
        anyhow::ensure!(capacity > 0, "challenge capacity must be positive");
        anyhow::ensure!(!lifetime.is_zero(), "challenge lifetime must be positive");
        Ok(Self {
            capacity,
            lifetime,
            entries: HashMap::new(),
            order: VecDeque::new(),
        })
    }

    pub fn issue(&mut self, challenge: Challenge, now: SystemTime) -> anyhow::Result<u64> {
        let now_ms = unix_ms(now)?;
        self.purge_expired_ms(now_ms);
        anyhow::ensure!(
            !self.entries.contains_key(&challenge),
            "challenge already exists"
        );
        while self.entries.len() >= self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
        let lifetime_ms: u64 = self
            .lifetime
            .as_millis()
            .try_into()
            .map_err(|_| anyhow::anyhow!("challenge lifetime is too large"))?;
        let expiry = now_ms
            .checked_add(lifetime_ms)
            .ok_or_else(|| anyhow::anyhow!("challenge expiry overflow"))?;
        self.entries.insert(challenge, expiry);
        self.order.push_back(challenge);
        Ok(expiry)
    }

    /// Atomically consumes a challenge. Failed/expired challenges cannot be replayed.
    pub fn consume(&mut self, challenge: &Challenge, now: SystemTime) -> bool {
        let Ok(now_ms) = unix_ms(now) else {
            return false;
        };
        self.purge_expired_ms(now_ms);
        self.entries.remove(challenge).is_some()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn purge_expired_ms(&mut self, now_ms: u64) {
        self.entries.retain(|_, expiry| *expiry > now_ms);
        self.order
            .retain(|challenge| self.entries.contains_key(challenge));
    }
}

impl AdmissionAuthProof {
    pub fn validate_shape(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.major == PROTOCOL_MAJOR,
            "unsupported admission protocol major"
        );
        anyhow::ensure!(
            self.roost_id != RoostId([0; 32]),
            "roost id must not be zero"
        );
        anyhow::ensure!(
            !self.connection_binding.is_empty(),
            "connection binding is required"
        );
        anyhow::ensure!(
            self.connection_binding.len() <= MAX_CONNECTION_BINDING_BYTES,
            "connection binding is too large"
        );
        Ok(())
    }
    pub fn signing_bytes(&self) -> anyhow::Result<Vec<u8>> {
        self.validate_shape()?;
        domain_encode(AUTH_PROOF_DOMAIN, self)
    }
    pub fn sign(self, key: &iroh::SecretKey) -> anyhow::Result<SignedAdmissionAuthProof> {
        anyhow::ensure!(
            self.client == key.public(),
            "client does not match signing key"
        );
        let signature = key.sign(&self.signing_bytes()?);
        Ok(SignedAdmissionAuthProof {
            proof: self,
            signature,
        })
    }
}

impl SignedAdmissionAuthProof {
    pub fn verify(&self) -> anyhow::Result<()> {
        self.proof
            .client
            .verify(&self.proof.signing_bytes()?, &self.signature)?;
        Ok(())
    }
}

impl PartialEq for SignedAdmissionAuthProof {
    fn eq(&self, other: &Self) -> bool {
        postcard::to_stdvec(self).ok() == postcard::to_stdvec(other).ok()
    }
}
impl Eq for SignedAdmissionAuthProof {}

impl AdmissionCapability {
    pub fn derive(epoch: u64, secret: &[u8]) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !secret.is_empty() && secret.len() <= MAX_CAPABILITY_BYTES,
            "invalid capability secret length"
        );
        let digest = capability_digest(epoch, secret);
        Ok(Self { epoch, digest })
    }
    pub fn verify(&self, secret: &[u8]) -> bool {
        if secret.is_empty() || secret.len() > MAX_CAPABILITY_BYTES {
            return false;
        }
        constant_time_eq(&self.digest, &capability_digest(self.epoch, secret))
    }
}

impl MembershipCertificate {
    pub fn validate_shape(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.major == PROTOCOL_MAJOR,
            "unsupported certificate protocol major"
        );
        anyhow::ensure!(
            self.roost_id != RoostId([0; 32]),
            "roost id must not be zero"
        );
        anyhow::ensure!(
            self.issued_at_unix_ms < self.expires_at_unix_ms,
            "invalid certificate lifetime"
        );
        Ok(())
    }
    pub fn signing_bytes(&self) -> anyhow::Result<Vec<u8>> {
        self.validate_shape()?;
        domain_encode(CERTIFICATE_DOMAIN, self)
    }
    pub fn sign(self, key: &iroh::SecretKey) -> anyhow::Result<SignedMembershipCertificate> {
        anyhow::ensure!(
            self.issuer == key.public(),
            "issuer does not match signing key"
        );
        let signature = key.sign(&self.signing_bytes()?);
        Ok(SignedMembershipCertificate {
            certificate: self,
            signature,
        })
    }
}

impl SignedMembershipCertificate {
    pub fn verify(&self) -> anyhow::Result<()> {
        self.certificate
            .issuer
            .verify(&self.certificate.signing_bytes()?, &self.signature)?;
        Ok(())
    }
    pub fn validate_with(
        &self,
        now_unix_ms: u64,
        hooks: &impl MembershipValidationHooks,
    ) -> anyhow::Result<()> {
        self.verify()?;
        anyhow::ensure!(
            now_unix_ms >= self.certificate.issued_at_unix_ms
                && now_unix_ms < self.certificate.expires_at_unix_ms,
            "certificate is not currently valid"
        );
        hooks.issuer_was_authorized(
            &self.certificate.roost_id,
            self.certificate.membership_epoch,
            &self.certificate.issuer,
        )?;
        hooks.member_generation_is_current(
            &self.certificate.roost_id,
            &self.certificate.member,
            self.certificate.auth_generation,
        )
    }
}

fn capability_digest(epoch: u64, secret: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(CAPABILITY_DOMAIN);
    hash.update(epoch.to_be_bytes());
    hash.update((secret.len() as u64).to_be_bytes());
    hash.update(secret);
    hash.finalize().into()
}
fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |diff, (a, b)| diff | (a ^ b))
        == 0
}
fn unix_ms(time: SystemTime) -> anyhow::Result<u64> {
    time.duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()
        .map_err(Into::into)
}
fn domain_encode<T: Serialize>(domain: &[u8], value: &T) -> anyhow::Result<Vec<u8>> {
    let encoded = postcard::to_stdvec(value)?;
    let mut out = Vec::with_capacity(domain.len() + encoded.len());
    out.extend_from_slice(domain);
    out.extend_from_slice(&encoded);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn challenges_are_bounded_expiring_and_one_use() {
        let now = UNIX_EPOCH + Duration::from_secs(10);
        let mut store = ChallengeStore::new(2, Duration::from_secs(2)).unwrap();
        store.issue([1; 32], now).unwrap();
        store.issue([2; 32], now).unwrap();
        store.issue([3; 32], now).unwrap();
        assert!(!store.consume(&[1; 32], now));
        assert!(store.consume(&[2; 32], now));
        assert!(!store.consume(&[2; 32], now));
        assert!(!store.consume(&[3; 32], now + Duration::from_secs(2)));
    }
    #[test]
    fn proof_binds_every_field_and_capability_checks() {
        let client = iroh::SecretKey::generate();
        let server = iroh::SecretKey::generate();
        let proof = AdmissionAuthProof {
            major: 1,
            roost_id: RoostId([1; 32]),
            server: server.public(),
            client: client.public(),
            connection_binding: b"tls-exporter".to_vec(),
            challenge: [2; 32],
            kind: AdmissionRequestKind::Join,
        }
        .sign(&client)
        .unwrap();
        proof.verify().unwrap();
        let mut changed = proof.clone();
        changed.proof.kind = AdmissionRequestKind::Renew;
        assert!(changed.verify().is_err());
        let cap = AdmissionCapability::derive(4, b"invite").unwrap();
        assert!(cap.verify(b"invite"));
        assert!(!cap.verify(b"wrong"));
        assert!(!AdmissionCapability { epoch: 5, ..cap }.verify(b"invite"));
    }
    struct Hooks {
        issuer: EndpointId,
        member: EndpointId,
    }
    impl MembershipValidationHooks for Hooks {
        fn issuer_was_authorized(
            &self,
            _: &RoostId,
            _: u64,
            issuer: &EndpointId,
        ) -> anyhow::Result<()> {
            anyhow::ensure!(*issuer == self.issuer, "issuer");
            Ok(())
        }
        fn member_generation_is_current(
            &self,
            _: &RoostId,
            member: &EndpointId,
            g: u64,
        ) -> anyhow::Result<()> {
            anyhow::ensure!(*member == self.member && g == 7, "generation");
            Ok(())
        }
    }
    #[test]
    fn certificate_signature_time_and_hooks_are_enforced() {
        let issuer = iroh::SecretKey::generate();
        let member = iroh::SecretKey::generate().public();
        let signed = MembershipCertificate {
            major: 1,
            roost_id: RoostId([8; 32]),
            member,
            issuer: issuer.public(),
            membership_epoch: 9,
            auth_generation: 7,
            issued_at_unix_ms: 10,
            expires_at_unix_ms: 20,
        }
        .sign(&issuer)
        .unwrap();
        signed
            .validate_with(
                15,
                &Hooks {
                    issuer: issuer.public(),
                    member,
                },
            )
            .unwrap();
        assert!(
            signed
                .validate_with(
                    20,
                    &Hooks {
                        issuer: issuer.public(),
                        member
                    }
                )
                .is_err()
        );
        let mut tampered = signed;
        tampered.certificate.auth_generation = 8;
        assert!(tampered.verify().is_err());
    }
}
