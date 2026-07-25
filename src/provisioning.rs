use iroh::{EndpointId, Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::protocol::{ChannelId, RoostId};

pub const PROVISIONING_ALPN: &[u8] = b"starling/provisioning/1";
pub const FRAME_PROVISIONING_REQUEST: u16 = 0x2201;
pub const FRAME_PROVISIONING_PACKAGE: u16 = 0x2202;
pub const PROTOCOL_MAJOR: u16 = 1;
pub const MAX_CONNECTION_BINDING_BYTES: usize = 256;
pub const MAX_WRAPPED_KEY_BYTES: usize = 16 * 1024;
pub const MAX_ENCRYPTED_PACKAGE_BYTES: usize = 8 * 1024 * 1024;
pub const CHANNEL_EPOCH_KEY_BYTES: usize = 32;
const REQUEST_DOMAIN: &[u8] = b"starling/provisioning-request/v1\0";
const PACKAGE_DOMAIN: &[u8] = b"starling/provisioning-package/v1\0";
const CONFIRMATION_DOMAIN: &[u8] = b"starling/channel-key-confirmation/v1\0";

pub type Challenge = [u8; 32];
pub type KeyConfirmation = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisioningRequest {
    pub major: u16,
    pub roost_id: RoostId,
    pub channel_id: ChannelId,
    pub epoch: u64,
    pub revision: u64,
    pub recipient: EndpointId,
    pub provider: EndpointId,
    pub auth_generation: u64,
    pub challenge: Challenge,
    pub connection_binding: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedProvisioningRequest {
    pub request: ProvisioningRequest,
    pub signature: Signature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisioningPackageMetadata {
    pub major: u16,
    pub roost_id: RoostId,
    pub channel_id: ChannelId,
    pub epoch: u64,
    pub revision: u64,
    pub recipient: EndpointId,
    pub provider: EndpointId,
    pub auth_generation: u64,
    pub challenge: Challenge,
    pub key_confirmation: KeyConfirmation,
    pub wrapped_key: Vec<u8>,
    pub encrypted_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedProvisioningPackage {
    pub package: ProvisioningPackageMetadata,
    pub signature: Signature,
}

/// Wraps a channel key using transport/application key material supplied by the caller.
/// No endpoint-key ECDH is implied by this protocol API.
pub trait KeyWrapper {
    fn wrap_key(
        &self,
        context: &ProvisioningRequest,
        key: &ChannelEpochKey,
    ) -> anyhow::Result<Vec<u8>>;
}

pub trait KeyUnwrapper {
    fn unwrap_key(
        &self,
        context: &ProvisioningPackageMetadata,
        wrapped: &[u8],
    ) -> anyhow::Result<ChannelEpochKey>;
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ChannelEpochKey([u8; CHANNEL_EPOCH_KEY_BYTES]);

impl ChannelEpochKey {
    pub fn new(bytes: [u8; CHANNEL_EPOCH_KEY_BYTES]) -> Self {
        Self(bytes)
    }
    pub fn expose(&self) -> &[u8; CHANNEL_EPOCH_KEY_BYTES] {
        &self.0
    }
    pub fn confirmation(&self, request: &ProvisioningRequest) -> anyhow::Result<KeyConfirmation> {
        request.validate_shape()?;
        let context = postcard::to_stdvec(request)?;
        let mut hash = Sha256::new();
        hash.update(CONFIRMATION_DOMAIN);
        hash.update(self.0);
        hash.update((context.len() as u64).to_be_bytes());
        hash.update(context);
        Ok(hash.finalize().into())
    }
    pub fn verify_confirmation(
        &self,
        request: &ProvisioningRequest,
        expected: &KeyConfirmation,
    ) -> anyhow::Result<bool> {
        Ok(constant_time_eq(&self.confirmation(request)?, expected))
    }
}

impl ProvisioningRequest {
    pub fn validate_shape(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.major == PROTOCOL_MAJOR,
            "unsupported provisioning protocol major"
        );
        anyhow::ensure!(
            self.roost_id != RoostId([0; 32]),
            "roost id must not be zero"
        );
        anyhow::ensure!(
            self.channel_id != ChannelId([0; 16]),
            "channel id must not be zero"
        );
        anyhow::ensure!(
            !self.connection_binding.is_empty(),
            "connection binding is required"
        );
        anyhow::ensure!(
            self.connection_binding.len() <= MAX_CONNECTION_BINDING_BYTES,
            "connection binding is too large"
        );
        anyhow::ensure!(
            self.recipient != self.provider,
            "recipient and provider must differ"
        );
        Ok(())
    }
    pub fn signing_bytes(&self) -> anyhow::Result<Vec<u8>> {
        self.validate_shape()?;
        domain_encode(REQUEST_DOMAIN, self)
    }
    pub fn sign(self, key: &iroh::SecretKey) -> anyhow::Result<SignedProvisioningRequest> {
        anyhow::ensure!(
            self.recipient == key.public(),
            "recipient does not match signing key"
        );
        let signature = key.sign(&self.signing_bytes()?);
        Ok(SignedProvisioningRequest {
            request: self,
            signature,
        })
    }
}
impl SignedProvisioningRequest {
    pub fn verify(&self) -> anyhow::Result<()> {
        self.request
            .recipient
            .verify(&self.request.signing_bytes()?, &self.signature)?;
        Ok(())
    }
}

impl ProvisioningPackageMetadata {
    pub fn validate_shape(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.major == PROTOCOL_MAJOR,
            "unsupported provisioning protocol major"
        );
        anyhow::ensure!(
            self.roost_id != RoostId([0; 32]) && self.channel_id != ChannelId([0; 16]),
            "invalid package scope"
        );
        anyhow::ensure!(
            self.recipient != self.provider,
            "recipient and provider must differ"
        );
        anyhow::ensure!(
            !self.wrapped_key.is_empty() && self.wrapped_key.len() <= MAX_WRAPPED_KEY_BYTES,
            "invalid wrapped key length"
        );
        anyhow::ensure!(
            !self.encrypted_bytes.is_empty()
                && self.encrypted_bytes.len() <= MAX_ENCRYPTED_PACKAGE_BYTES,
            "invalid encrypted package length"
        );
        Ok(())
    }
    pub fn signing_bytes(&self) -> anyhow::Result<Vec<u8>> {
        self.validate_shape()?;
        domain_encode(PACKAGE_DOMAIN, self)
    }
    pub fn sign(self, key: &iroh::SecretKey) -> anyhow::Result<SignedProvisioningPackage> {
        anyhow::ensure!(
            self.provider == key.public(),
            "provider does not match signing key"
        );
        let signature = key.sign(&self.signing_bytes()?);
        Ok(SignedProvisioningPackage {
            package: self,
            signature,
        })
    }
    pub fn matches_request(&self, request: &ProvisioningRequest) -> anyhow::Result<()> {
        self.validate_shape()?;
        request.validate_shape()?;
        anyhow::ensure!(
            self.major == request.major
                && self.roost_id == request.roost_id
                && self.channel_id == request.channel_id
                && self.epoch == request.epoch
                && self.revision == request.revision
                && self.recipient == request.recipient
                && self.provider == request.provider
                && self.auth_generation == request.auth_generation
                && self.challenge == request.challenge,
            "package does not match request"
        );
        Ok(())
    }
}
impl SignedProvisioningPackage {
    pub fn verify(&self) -> anyhow::Result<()> {
        self.package
            .provider
            .verify(&self.package.signing_bytes()?, &self.signature)?;
        Ok(())
    }
}

fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter().zip(right).fold(0u8, |d, (a, b)| d | (a ^ b)) == 0
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
    fn request(recipient: EndpointId, provider: EndpointId) -> ProvisioningRequest {
        ProvisioningRequest {
            major: 1,
            roost_id: RoostId([1; 32]),
            channel_id: ChannelId([2; 16]),
            epoch: 3,
            revision: 4,
            recipient,
            provider,
            auth_generation: 5,
            challenge: [6; 32],
            connection_binding: b"exporter".to_vec(),
        }
    }
    #[test]
    fn request_and_package_bind_all_metadata() {
        let recipient = iroh::SecretKey::generate();
        let provider = iroh::SecretKey::generate();
        let req = request(recipient.public(), provider.public());
        req.clone().sign(&recipient).unwrap().verify().unwrap();
        let key = ChannelEpochKey::new([9; 32]);
        let package = ProvisioningPackageMetadata {
            major: 1,
            roost_id: req.roost_id,
            channel_id: req.channel_id,
            epoch: req.epoch,
            revision: req.revision,
            recipient: req.recipient,
            provider: req.provider,
            auth_generation: req.auth_generation,
            challenge: req.challenge,
            key_confirmation: key.confirmation(&req).unwrap(),
            wrapped_key: vec![1, 2],
            encrypted_bytes: vec![3, 4],
        };
        package.matches_request(&req).unwrap();
        let mut signed = package.sign(&provider).unwrap();
        signed.verify().unwrap();
        signed.package.encrypted_bytes[0] ^= 1;
        assert!(signed.verify().is_err());
    }
    #[test]
    fn confirmation_and_strict_limits_work() {
        let recipient = iroh::SecretKey::generate();
        let provider = iroh::SecretKey::generate();
        let req = request(recipient.public(), provider.public());
        let key = ChannelEpochKey::new([7; 32]);
        let confirmation = key.confirmation(&req).unwrap();
        assert!(key.verify_confirmation(&req, &confirmation).unwrap());
        let mut changed = req.clone();
        changed.epoch += 1;
        assert!(!key.verify_confirmation(&changed, &confirmation).unwrap());
        let mut oversized = req;
        oversized.connection_binding = vec![0; MAX_CONNECTION_BINDING_BYTES + 1];
        assert!(oversized.validate_shape().is_err());
    }
    struct Wrapper;
    impl KeyWrapper for Wrapper {
        fn wrap_key(
            &self,
            _: &ProvisioningRequest,
            key: &ChannelEpochKey,
        ) -> anyhow::Result<Vec<u8>> {
            Ok(key.expose().iter().map(|byte| byte ^ 0xaa).collect())
        }
    }
    impl KeyUnwrapper for Wrapper {
        fn unwrap_key(
            &self,
            _: &ProvisioningPackageMetadata,
            wrapped: &[u8],
        ) -> anyhow::Result<ChannelEpochKey> {
            let bytes: Vec<_> = wrapped.iter().map(|byte| byte ^ 0xaa).collect();
            Ok(ChannelEpochKey::new(
                bytes.try_into().map_err(|_| anyhow::anyhow!("length"))?,
            ))
        }
    }
    #[test]
    fn wrapper_is_caller_supplied() {
        let recipient = iroh::SecretKey::generate();
        let provider = iroh::SecretKey::generate();
        let req = request(recipient.public(), provider.public());
        let key = ChannelEpochKey::new([4; 32]);
        let wrapped = Wrapper.wrap_key(&req, &key).unwrap();
        assert_eq!(wrapped, vec![0xae; 32]);
    }
}
